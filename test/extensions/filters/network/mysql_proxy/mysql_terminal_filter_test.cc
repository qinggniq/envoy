#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/conn_pool.h"
#include "envoy/common/exception.h"
#include "envoy/extensions/filters/network/mysql_proxy/v3/mysql_proxy.pb.h"

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
  routes:
  - database: db
    cluster: cluster
  stat_prefix: foo
  )EOF";
  using MySQLFilterPtr = std::unique_ptr<MySQLFilter>;
  DecoderPtr create(DecoderCallbacks&) override {
    if (filter_ == nullptr) {
      return DecoderPtr{downstream_decoder_};
      ;
    }
    if (!filter_->downstream_decoder_) {
      return nullptr;
    }
    if (!filter_->upstream_decoder_) {
      return DecoderPtr{upstream_decoder_};
    }
    return nullptr;
  }
  MySQLTerminalFitlerTest() {
    auto proto_config = parseProtoFromYaml(yaml_string);
    MySQLFilterConfigSharedPtr config = std::make_shared<MySQLFilterConfig>(store_, proto_config);
    route_ = std::make_shared<MockRoute>(&cm_.thread_local_cluster_, cluster_name);
    router_ = std::make_shared<MockRouter>(route_);
    filter_ = std::make_unique<MySQLFilter>(config, router_, *this);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, addConnectionCallbacks(_));
    filter_->initializeReadFilterCallbacks(read_callbacks_);
  }

  void connectionComeNoClusterInRoute() {
    auto router = std::make_shared<MockRouter>(nullptr);
    filter_->router_ = router;
    EXPECT_CALL(*router, primaryPool());
    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));
    EXPECT_CALL(store_.counter_, inc);

    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  }

  void connectionComeNoCluster() {
    auto route = std::make_shared<MockRoute>(nullptr, cluster_name);
    auto router = std::make_shared<MockRouter>(route);

    filter_->router_ = router;
    EXPECT_CALL(*router, primaryPool());
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
    EXPECT_CALL(*router, primaryPool());
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
    EXPECT_CALL(*router, primaryPool());
    EXPECT_CALL(*route, upstream());

    EXPECT_CALL(cm_.thread_local_cluster_,
                tcpConnPool(Upstream::ResourcePriority::Default, nullptr));

    EXPECT_CALL(cm_.thread_local_cluster_.tcp_conn_pool_, newConnection(_));
    EXPECT_CALL(store_.counter_, inc);
    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
  }

  void connectOkAndPoolReady() {
    connectionOk();
    EXPECT_CALL(*(cm_.thread_local_cluster_.tcp_conn_pool_.connection_data_.get()),
                addUpstreamCallbacks(_));
    EXPECT_CALL(read_callbacks_, continueReading());
    cm_.thread_local_cluster_.tcp_conn_pool_.poolReady(connection_);
    EXPECT_NE(filter_->upstream_decoder_, nullptr);
  }

  void serverSendGreet();

  void clientSendSsl();

  MySQLFilter::UpstreamDecoder& upstreamDecoder() { return *filter_->upstream_decoder_; }
  MySQLFilter::DownstreamDecoder& downstreamDecoder() { return *filter_->downstream_decoder_; }

  MySQLSession downstream_session_;
  MySQLSession upstream_session_;
  MockDecoder* downstream_decoder_{new MockDecoder(downstream_session_)};
  MockDecoder* upstream_decoder_{new MockDecoder(upstream_session_)};
  Upstream::MockClusterManager cm_;
  Network::MockClientConnection connection_;
  Network::MockReadFilterCallbacks read_callbacks_;

  RouteSharedPtr route_;
  RouterSharedPtr router_;
  MySQLFilterPtr filter_;
  NiceMock<Stats::MockStore> store_;
};

TEST_F(MySQLTerminalFitlerTest, ConnectButNoClusterInRoute) { connectionComeNoClusterInRoute(); }

TEST_F(MySQLTerminalFitlerTest, ConnectButNoCluster) { connectionComeNoCluster(); }

TEST_F(MySQLTerminalFitlerTest, ConnectButNoHost) { connectionComeNoHost(); }

TEST_F(MySQLTerminalFitlerTest, ConnectOk) { connectionOk(); }

INSTANTIATE_TEST_CASE_P(ConnectOkButPoolFailed, MySQLTerminalFitlerTest,
                        ::testing::ValuesIn({
                            Tcp::ConnectionPool::PoolFailureReason::LocalConnectionFailure,
                            Tcp::ConnectionPool::PoolFailureReason::RemoteConnectionFailure,
                            Tcp::ConnectionPool::PoolFailureReason::Timeout,
                            Tcp::ConnectionPool::PoolFailureReason::Overflow,
                            static_cast<Tcp::ConnectionPool::PoolFailureReason>(-1),
                        }));

TEST_P(MySQLTerminalFitlerTest, ConnectOkButPoolFailed) {
  connectionOk();
  EXPECT_CALL(store_.counter_, inc);
  EXPECT_CALL(read_callbacks_, connection());
  EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

  cm_.thread_local_cluster_.tcp_conn_pool_.poolFailure(GetParam());
}

TEST_F(MySQLTerminalFitlerTest, ConnectOkAndPoolReady) { connectOkAndPoolReady(); }

void MySQLTerminalFitlerTest::serverSendGreet() {
  auto greet = MessageHelper::encodeGreeting(MySQLTestUtils::getAuthPluginData8());
  greet.setSeq(0);
  auto data = greet.encodePacket();

  EXPECT_CALL(*upstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), greet.encodePacket().toString());
    EXPECT_CALL(*upstream_decoder_, getSession()).Times(2);
    EXPECT_CALL(*downstream_decoder_, getSession()).Times(4);

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
  EXPECT_CALL(*downstream_decoder_, onData(_)).WillOnce(Invoke([&](Buffer::Instance& data) {
    EXPECT_EQ(data.toString(), ssl.encodePacket().toString());

    EXPECT_CALL(*downstream_decoder_, getSession()).Times(2);

    EXPECT_EQ(downstream_decoder_->getSession().getExpectedSeq(), 1);
    EXPECT_EQ(downstream_decoder_->getSession().getState(), MySQLSession::State::ChallengeReq);

    EXPECT_CALL(store_.counter_, inc()).Times(2);
    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

    downstreamDecoder().onClientLogin(ssl);
  }));
  downstreamDecoder().onData(data, false);
}

TEST_F(MySQLTerminalFitlerTest, GreetThenSslUpgrade) {
  connectOkAndPoolReady();
  serverSendGreet();
  clientSendSsl();
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
