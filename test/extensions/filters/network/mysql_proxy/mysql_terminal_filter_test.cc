#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/conn_pool.h"
#include "envoy/common/exception.h"
#include "envoy/extensions/filters/network/mysql_proxy/v3/mysql_proxy.pb.h"
#include "envoy/tcp/conn_pool.h"

#include "common/buffer/buffer_impl.h"

#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_command.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_greeting.h"
#include "extensions/filters/network/mysql_proxy/mysql_config.h"
#include "extensions/filters/network/mysql_proxy/mysql_decoder.h"
#include "extensions/filters/network/mysql_proxy/mysql_filter.h"
#include "extensions/filters/network/mysql_proxy/mysql_session.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "extensions/filters/network/mysql_proxy/route.h"

#include "test/mocks/api/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/tcp/mocks.h"
#include "test/mocks/upstream/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "mock.h"
#include "mysql_test_utils.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

const std::string cluster_name = "cluster";

envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy
parseProtoFromYaml(const std::string& yaml_string) {
  envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy config;
  TestUtility::loadFromYaml(yaml_string, config);
  return config;
}

class MySQLTerminalFitlerTest
    : public DecoderFactory,
      public testing::TestWithParam<Tcp::ConnectionPool::PoolFailureReason> {
public:
  const std::string yaml_string = R"EOF(
  database_routes:
    catch_all_route:
      database: db
      cluster: cluster
  stat_prefix: foo
  )EOF";
  using MySQLFilterPtr = std::unique_ptr<MySQLFilter>;
  DecoderPtr create(DecoderCallbacks&) override {
    if (filter_ == nullptr) {
      downstream_decoder_ = new MockDecoder();
      return DecoderPtr{downstream_decoder_};
      ;
    }
    if (!filter_->downstream_decoder_) {
      return nullptr;
    }
    if (!filter_->upstream_decoder_) {
      upstream_decoder_ = new MockDecoder();
      return DecoderPtr{upstream_decoder_};
      ;
    }
    return nullptr;
  }
  void setup() {
    auto proto_config = parseProtoFromYaml(yaml_string);
    MySQLFilterConfigSharedPtr config = std::make_shared<MySQLFilterConfig>(store_, proto_config);
    route_ = std::make_shared<MockRoute>(&cm_.thread_local_cluster_, cluster_name);
    router_ = std::make_shared<MockRouter>(route_);
    filter_ = std::make_unique<MySQLFilter>(config, router_, *this);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, addConnectionCallbacks(_));
    filter_->initializeReadFilterCallbacks(read_callbacks_);
  }

  void teardown() {
    filter_.reset(nullptr);
    router_.reset();
    route_.reset();
    upstream_decoder_ = nullptr;
    downstream_decoder_ = nullptr;
  }

  void connectionComeNoDefaultClusterInConfig() {
    auto router = std::make_shared<MockRouter>(nullptr);
    filter_->router_ = router;
    EXPECT_CALL(*router, defaultPool());
    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));
    EXPECT_CALL(store_.counter_, inc);

    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  }

  void connectionComeClusterNotExisit() {
    auto route = std::make_shared<MockRoute>(nullptr, cluster_name);
    auto router = std::make_shared<MockRouter>(route);

    filter_->router_ = router;
    EXPECT_CALL(*router, defaultPool());
    EXPECT_CALL(*route, upstream());

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));
    EXPECT_CALL(store_.counter_, inc);

    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  }

  void connectionComeNoHost() {
    auto route = std::make_shared<MockRoute>(&cm_.thread_local_cluster_, cluster_name);
    auto router = std::make_shared<MockRouter>(route);
    filter_->router_ = router;
    EXPECT_CALL(*router, defaultPool());
    EXPECT_CALL(*route, upstream());

    EXPECT_CALL(cm_.thread_local_cluster_,
                tcpConnPool(Upstream::ResourcePriority::Default, nullptr))
        .WillOnce(Invoke([&](Upstream::ResourcePriority, Upstream::LoadBalancerContext*)
                             -> Tcp::ConnectionPool::Instance* { return nullptr; }));

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

    EXPECT_CALL(store_.counter_, inc);

    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  }

  void connectionOk() {
    auto route = std::make_shared<MockRoute>(&cm_.thread_local_cluster_, cluster_name);
    auto router = std::make_shared<MockRouter>(route);
    filter_->router_ = router;
    EXPECT_CALL(*router, defaultPool());
    EXPECT_CALL(*route, upstream());

    EXPECT_CALL(cm_.thread_local_cluster_,
                tcpConnPool(Upstream::ResourcePriority::Default, nullptr));

    EXPECT_CALL(cm_.thread_local_cluster_.tcp_conn_pool_, newConnection(_));
    EXPECT_CALL(store_.counter_, inc);
    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  }

  void connectClosedAndPoolNotReady() {
    connectionOk();
    EXPECT_CALL(*(dynamic_cast<Envoy::ConnectionPool::MockCancellable*>(filter_->canceler_)),
                cancel(_));
    EXPECT_EQ(filter_->upstream_conn_data_, nullptr);
    read_callbacks_.connection_.close(Network::ConnectionCloseType::NoFlush);
    EXPECT_EQ(filter_->canceler_, nullptr);
  }

  void connectOkAndPoolReady() {
    connectionOk();
    EXPECT_CALL(*(cm_.thread_local_cluster_.tcp_conn_pool_.connection_data_.get()),
                addUpstreamCallbacks(_));
    EXPECT_CALL(read_callbacks_, continueReading());
    cm_.thread_local_cluster_.tcp_conn_pool_.poolReady(connection_);
    EXPECT_NE(filter_->upstream_decoder_, nullptr);
    EXPECT_NE(upstreamConnData(), nullptr);
    EXPECT_NE(downstream_decoder_, nullptr);
    EXPECT_NE(upstream_decoder_, nullptr);
  }
  // seq 0
  void serverSendGreet();
  // seq 1
  void clientSendSsl();

  void clientSendHandShakeReponse();
  // seq 2
  void serverSendOk();

  void serverSendError();

  void serverSendAuthSwitch();

  void serverSendAuthMore();
  // seq 3
  void clientSendAuthSwitchResponse();
  // seq 4
  void serverSendClientSwitchOk();

  void serverSendClientSwitchError();

  void serverSendClientSwitchMore();

  void serverSendClientSwitchSwitch();

  void clientSendAuthMoreResponse();

  // command phase seq 0
  void clientSendQuery();
  void clientSendQuit();
  void clientSendInvalidQuery();

  // command phase seq 1 - N
  void serverSendCommandResponse();

  MySQLFilter::UpstreamDecoder& upstreamDecoder() { return *filter_->upstream_decoder_; }
  MySQLFilter::DownstreamDecoder& downstreamDecoder() { return *filter_->downstream_decoder_; }
  Tcp::ConnectionPool::MockConnectionData* upstreamConnData() {
    return dynamic_cast<Tcp::ConnectionPool::MockConnectionData*>(
        filter_->upstream_conn_data_.get());
  }

  Upstream::MockClusterManager cm_;
  Network::MockClientConnection connection_;
  Network::MockReadFilterCallbacks read_callbacks_;
  RouteSharedPtr route_;
  RouterSharedPtr router_;
  MySQLFilterPtr filter_;
  MockDecoder* downstream_decoder_{};
  MockDecoder* upstream_decoder_{};
  NiceMock<Stats::MockStore> store_;
};

INSTANTIATE_TEST_CASE_P(ConnectOkButPoolFailed, MySQLTerminalFitlerTest,
                        ::testing::ValuesIn({
                            Tcp::ConnectionPool::PoolFailureReason::LocalConnectionFailure,
                            Tcp::ConnectionPool::PoolFailureReason::RemoteConnectionFailure,
                            Tcp::ConnectionPool::PoolFailureReason::Timeout,
                            Tcp::ConnectionPool::PoolFailureReason::Overflow,
                            static_cast<Tcp::ConnectionPool::PoolFailureReason>(-1),
                        }));

void MySQLTerminalFitlerTest::serverSendGreet() {
  auto greet = MessageHelper::encodeGreeting(MySQLTestUtils::getAuthPluginData8());
  greet.setSeq(0);
  auto data = greet.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), greet.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(2);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(3);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));
    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 0);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::Init);
    upstreamDecoder().onServerGreeting(greet);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::clientSendSsl() {
  auto ssl = MessageHelper::encodeSslUpgrade();
  ssl.setSeq(1);
  auto data = ssl.encodePacket();
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(*downstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), ssl.encodePacket().toString());

    data.drain(data.length());
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(2);

    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);

    EXPECT_CALL(store_.counter_, inc()).Times(2);
    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));
    EXPECT_CALL(connection_, close(Network::ConnectionCloseType::NoFlush));

    downstreamDecoder().onClientLogin(ssl);
  }));
  downstreamDecoder().onData(data, false);
}

void MySQLTerminalFitlerTest::clientSendHandShakeReponse() {
  auto login = MessageHelper::encodeClientLogin(
      MySQLTestUtils::getUsername(), MySQLTestUtils::getDb(), MySQLTestUtils::getAuthResp20());
  login.setSeq(1);
  auto data = login.encodePacket();
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(*downstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), login.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(2);
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(3);

    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);

    EXPECT_CALL(store_.counter_, inc());

    EXPECT_CALL(*upstreamConnData(), connection());
    EXPECT_CALL(connection_, write(_, false));

    downstreamDecoder().onClientLogin(login);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
  }));
  downstreamDecoder().onData(data, false);
}

void MySQLTerminalFitlerTest::serverSendOk() {
  auto ok = MessageHelper::encodeOk();
  ok.setSeq(2);
  auto data = ok.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), ok.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(5);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);
    upstreamDecoder().onClientLoginResponse(ok);
    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::serverSendError() {
  auto err = MessageHelper::passwordLengthError(NATIVE_PSSWORD_HASH_LENGTH);
  err.setSeq(2);
  auto data = err.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), err.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(4);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_CALL(store_.counter_, inc());

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);
    upstreamDecoder().onClientLoginResponse(err);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Error);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::serverSendAuthSwitch() {
  testing::Sequence seq;
  auto auth_switch = MessageHelper::encodeAuthSwitch(MySQLTestUtils::getAuthPluginData8());
  auth_switch.setSeq(2);
  auto data = auth_switch.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    testing::Sequence seq;
    EXPECT_EQ(data.toString(), auth_switch.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(4);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_CALL(store_.counter_, inc());

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);
    upstreamDecoder().onClientLoginResponse(auth_switch);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchResp);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::serverSendAuthMore() {
  SCOPED_TRACE("");

  testing::Sequence seq;

  auto more = MessageHelper::encodeAuthMore(MySQLTestUtils::getAuthPluginData8());
  more.setSeq(2);
  auto data = more.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), more.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(4);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);
    upstreamDecoder().onClientLoginResponse(more);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 2);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeResp41);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::NotHandled);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::clientSendAuthSwitchResponse() {
  testing::Sequence seq;

  auto switch_resp = MessageHelper::encodeSwithResponse(MySQLTestUtils::getAuthResp20());
  switch_resp.setSeq(3);
  auto data = switch_resp.encodePacket();
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(*downstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), switch_resp.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(2);
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(3);

    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchResp);

    EXPECT_CALL(*upstreamConnData(), connection());
    EXPECT_CALL(connection_, write(_, false));

    downstreamDecoder().onClientSwitchResponse(switch_resp);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
  }));
  downstreamDecoder().onData(data, false);
}

// seq 4
void MySQLTerminalFitlerTest::serverSendClientSwitchOk() {
  testing::Sequence seq;

  auto ok = MessageHelper::encodeOk();
  ok.setSeq(4);
  auto data = ok.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), ok.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(5);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchResp);

    upstreamDecoder().onMoreClientLoginResponse(ok);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::serverSendClientSwitchError() {
  testing::Sequence seq;
  auto err = MessageHelper::passwordLengthError(NATIVE_PSSWORD_HASH_LENGTH);
  err.setSeq(4);
  auto data = err.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), err.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(4);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_CALL(store_.counter_, inc());

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchResp);
    upstreamDecoder().onMoreClientLoginResponse(err);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 5);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Error);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::serverSendClientSwitchMore() {
  testing::Sequence seq;
  auto more = MessageHelper::encodeAuthMore(MySQLTestUtils::getAuthPluginData8());
  more.setSeq(4);
  auto data = more.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), more.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(4);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchResp);
    upstreamDecoder().onMoreClientLoginResponse(more);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 5);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchResp);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

void MySQLTerminalFitlerTest::serverSendClientSwitchSwitch() {
  testing::Sequence seq;
  auto auth_switch = MessageHelper::encodeAuthSwitch(MySQLTestUtils::getAuthPluginData8());
  auth_switch.setSeq(4);
  auto data = auth_switch.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    testing::Sequence seq;
    EXPECT_EQ(data.toString(), auth_switch.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(4);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 3);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchResp);
    upstreamDecoder().onMoreClientLoginResponse(auth_switch);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), 4);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::AuthSwitchMore);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 5);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::NotHandled);
  }));
  upstreamDecoder().onUpstreamData(data, false);
}

// command phase seq 0
void MySQLTerminalFitlerTest::clientSendQuery() {
  auto command = MessageHelper::encodeCommand(Command::Cmd::Query, "select * from t;", "", true);
  command.setSeq(0);
  auto data = command.encodePacket();
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(*downstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), command.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(5);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);

    EXPECT_CALL(store_.counter_, inc());

    EXPECT_CALL(read_callbacks_, connection()).Times(2);
    EXPECT_CALL(read_callbacks_.connection_, streamInfo()).Times(2);

    EXPECT_CALL(*upstreamConnData(), connection());
    EXPECT_CALL(connection_, write(_, false));

    downstreamDecoder().onCommand(command);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);
  }));
  downstreamDecoder().onData(data, false);
}

void MySQLTerminalFitlerTest::clientSendInvalidQuery() {
  auto command = MessageHelper::encodeCommand(Command::Cmd::Query, "slecet * from t;", "", true);
  command.setSeq(0);
  auto data = command.encodePacket();
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(*downstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), command.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(5);
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(5);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);

    EXPECT_CALL(store_.counter_, inc());

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, streamInfo());

    EXPECT_CALL(*upstreamConnData(), connection());
    EXPECT_CALL(connection_, write(_, false));

    downstreamDecoder().onCommand(command);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);
  }));
  downstreamDecoder().onData(data, false);
}

void MySQLTerminalFitlerTest::clientSendQuit() {

  auto quit = MessageHelper::encodeCommand(Command::Cmd::Quit, "", "", false);
  quit.setSeq(0);
  auto data = quit.encodePacket();
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(*downstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), quit.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(4);
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(4);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

    EXPECT_CALL(*upstreamConnData(), connection()).Times(2);
    EXPECT_CALL(connection_, write(_, false));
    EXPECT_CALL(connection_, close(Network::ConnectionCloseType::NoFlush));

    downstreamDecoder().onCommand(quit);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);
  }));
  downstreamDecoder().onData(data, false);
}

void MySQLTerminalFitlerTest::serverSendCommandResponse() {
  auto response = MessageHelper::encodeCommandResponse("command response");
  response.setSeq(1);
  auto data = response.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), response.encodePacket().toString());
    data.drain(data.length());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(5);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(4);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, write(_, false));
    upstreamDecoder().onCommandResponse(response);

    EXPECT_EQ(upstream_decoder_->getSession().getExpectedSeq(), MYSQL_RESPONSE_PKT_NUM + 1);
    EXPECT_EQ(upstream_decoder_->getSession().getState(), MySQLSession::State::ReqResp);
    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), MYSQL_REQUEST_PKT_NUM);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::Req);
  }));

  upstreamDecoder().onUpstreamData(data, false);
}

TEST_F(MySQLTerminalFitlerTest, ConnectButNoClusterInRoute) {
  setup();
  connectionComeNoDefaultClusterInConfig();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, ConnectButNoCluster) {
  setup();
  connectionComeClusterNotExisit();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, ConnectButNoHost) {
  setup();
  connectionComeNoHost();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, ConnectOk) {
  setup();
  connectionOk();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, ConnectClosedAndPoolNotReady) {
  setup();
  connectClosedAndPoolNotReady();
  teardown();
}

TEST_P(MySQLTerminalFitlerTest, ConnectOkButPoolFailed) {
  setup();
  connectionOk();
  EXPECT_CALL(store_.counter_, inc);
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

  cm_.thread_local_cluster_.tcp_conn_pool_.poolFailure(GetParam());
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, ConnectOkAndPoolReady) {
  setup();
  connectOkAndPoolReady();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreetThenSslUpgrade) {
  setup();
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendSsl();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreetThenResponse) {
  setup();
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreetThenLoginThenOk) {
  setup();
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendOk();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreeThenLoginThenError) {
  setup();
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendError();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreeThenLoginThenAuthSwitchThenError) {
  setup();
  testing::Sequence seq;
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendAuthSwitch();
  clientSendAuthSwitchResponse();
  serverSendClientSwitchError();
  teardown();
}

// pending
TEST_F(MySQLTerminalFitlerTest, GreeThenLoginThenAuthSwitchThenMore) {
  setup();
  testing::Sequence seq;
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendAuthSwitch();
  clientSendAuthSwitchResponse();
  serverSendClientSwitchMore();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreeThenLoginThenAuthSwitchThenSwitch) {
  setup();
  testing::Sequence seq;
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendAuthSwitch();
  clientSendAuthSwitchResponse();
  serverSendClientSwitchSwitch();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreeThenLoginThenAuthSwitchThenOkThenQueryThenResult) {
  setup();
  testing::Sequence seq;
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendAuthSwitch();
  clientSendAuthSwitchResponse();
  serverSendClientSwitchOk();
  clientSendQuery();
  serverSendCommandResponse();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreeThenLoginThenAuthSwitchThenOkThenQuit) {
  setup();
  testing::Sequence seq;
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendAuthSwitch();
  clientSendAuthSwitchResponse();
  serverSendClientSwitchOk();
  clientSendQuit();
  teardown();
}

TEST_F(MySQLTerminalFitlerTest, GreeThenLoginThenAuthSwitchThenOkThenInvalidQuery) {
  setup();
  testing::Sequence seq;
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendHandShakeReponse();
  serverSendAuthSwitch();
  clientSendAuthSwitchResponse();
  serverSendClientSwitchOk();
  clientSendInvalidQuery();
  teardown();
}
} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
