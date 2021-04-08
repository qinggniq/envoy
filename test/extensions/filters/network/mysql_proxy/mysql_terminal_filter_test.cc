#include <memory>

#include "envoy/buffer/buffer.h"
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

#include "test/mocks/api/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/tcp/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "mock.h"
#include "mysql_test_utils.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy
parseProtoFromYaml(const std::string& yaml_string) {
  envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy config;
  TestUtility::loadFromYaml(yaml_string, config);
  return config;
}

class MySQLFilterTest : public DecoderFactory {
public:
  const std::string yaml_string = R"EOF(
  routes:
  - database: db
    cluster: cluster
  stat_prefix: foo
  )EOF";

  MySQLFilterTest() {
    auto proto_config = parseProtoFromYaml(yaml_string);
    MySQLFilterConfigSharedPtr config =
        std::make_shared<MySQLFilterConfig>(store_, proto_config, api_);
    route_ = std::make_shared<MockRoute>(pool_.get());
    router_ = std::make_shared<MockRouter>(route_);
    filter_ = std::make_unique<MySQLFilter>(config, router_, *this, *this);
    EXPECT_CALL(filter_callbacks_.connection_, addConnectionCallbacks);
    filter_->initializeReadFilterCallbacks(filter_callbacks_);
    EXPECT_CALL(*decoder_, getSession).Times(2);
    EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
        .WillOnce(Invoke([&](Buffer::Instance& buffer, bool) {
          ServerGreeting greet{};
          BufferHelper::consumeHdr(buffer);
          greet.decode(buffer, 0, buffer.length());
          seed_ = greet.getAuthPluginData();
        }));
    EXPECT_EQ(filter_->onNewConnection(), Network::FilterStatus::Continue);
  }

  std::vector<uint8_t> seed_;
  MySQLSession session_;
  MockDecoder* decoder_{new MockDecoder(session_)};
  DecoderCallbacks* decoder_callbacks_{};
  std::shared_ptr<MockRoute> route_;
  std::shared_ptr<MockRouter> router_;
  Stats::TestUtil::TestStore store_;
  MySQLFilterConfigSharedPtr config_;
  std::unique_ptr<MySQLFilter> filter_;
  NiceMock<Network::MockReadFilterCallbacks> filter_callbacks_;
  NiceMock<Api::MockApi> api_;
};

void etractBufferData(MySQLCodec& message, Buffer::Instance& data, uint8_t expect_seq,
                      uint32_t expect_len) {
  uint8_t seq;
  uint32_t len;
  BufferHelper::peekHdr(data, len, seq);
  EXPECT_EQ(seq, expect_seq);
  EXPECT_EQ(len, expect_len);
  BufferHelper::consumeHdr(data);
  message.decode(data, seq, len);
}

TEST_F(MySQLFilterTest, WrongUsername) {
  std::string username = "wrong_username";
  std::string db = "db";
  std::string password = "password";
  auto client_login = MessageHelper::encodeClientLogin(auth_method_, username, password, db, seed_);
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(filter_callbacks_.connection_, addressProvider);
  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        ErrMessage err{};
        etractBufferData(err, data, 2, data.length() - 4);
        EXPECT_EQ(err.getErrorCode(), ER_ACCESS_DENIED_ERROR);
      }));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, WrongDb) {
  std::string username = "username";
  std::string db = "wrong_db";
  std::string password = "password";
  auto client_login = MessageHelper::encodeClientLogin(auth_method_, username, password, db, seed_);
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(*router_, upstreamPool(db)).WillOnce(Invoke([&](const std::string&) {
    return nullptr;
  }));
  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        ErrMessage err{};
        etractBufferData(err, data, 2, data.length() - 4);
        EXPECT_EQ(err.getErrorCode(), ER_ER_BAD_DB_ERROR);
      }));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, SslUpgrade) {
  std::string username = "username";
  std::string db = "wrong_db";
  std::string password = "password";
  auto client_login = MessageHelper::encodeSslUpgrade();
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(filter_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, WrongOldPasswordLength) {
  std::string username = "username";
  std::string db = "db";
  std::string password = "password";
  auto client_login =
      MessageHelper::encodeClientLogin(AuthMethod::OldPassword, username, password, db, seed_);
  EXPECT_EQ(client_login.getAuthResp().size(), 8);
  client_login.setAuthResp(MySQLTestUtils::getAuthPluginData20());
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(*router_, upstreamPool(db));
  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        ErrMessage err{};
        etractBufferData(err, data, 2, data.length() - 4);
        EXPECT_EQ(err.getErrorCode(), ER_PASSWD_LENGTH);
      }));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, WrongNativePasswordLength) {
  std::string username = "username";
  std::string db = "db";
  std::string password = "password";
  auto client_login =
      MessageHelper::encodeClientLogin(AuthMethod::NativePassword, username, password, db, seed_);
  EXPECT_EQ(client_login.getAuthResp().size(), 20);
  client_login.setAuthResp(MySQLTestUtils::getAuthPluginData8());
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(*router_, upstreamPool(db));

  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        ErrMessage err{};
        etractBufferData(err, data, 2, data.length() - 4);
        EXPECT_EQ(err.getErrorCode(), ER_PASSWD_LENGTH);
      }));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, WrongOldPassword) {
  std::string username = "username";
  std::string db = "db";
  std::string password = "wrong_password";
  auto client_login =
      MessageHelper::encodeClientLogin(AuthMethod::OldPassword, username, password, db, seed_);
  EXPECT_EQ(client_login.getAuthResp().size(), 8);
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(*router_, upstreamPool(db));
  ;
  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        ErrMessage err{};
        etractBufferData(err, data, 2, data.length() - 4);
        EXPECT_EQ(err.getErrorCode(), ER_ACCESS_DENIED_ERROR);
      }));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, WrongNativePassword) {
  std::string username = "username";
  std::string db = "db";
  std::string password = "wrong_password";
  auto client_login =
      MessageHelper::encodeClientLogin(AuthMethod::NativePassword, username, password, db, seed_);
  EXPECT_EQ(client_login.getAuthResp().size(), 20);
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(*router_, upstreamPool(db));

  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        ErrMessage err{};
        etractBufferData(err, data, 2, data.length() - 4);
        EXPECT_EQ(err.getErrorCode(), ER_ACCESS_DENIED_ERROR);
      }));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, OtherAuthPlugin) {
  std::string username = "username";
  std::string db = "db";
  std::string password = "password";
  auto client_login =
      MessageHelper::encodeClientLogin(AuthMethod::Sha256Password, username, password, db, seed_);
  EXPECT_EQ(client_login.getAuthResp().size(), 20);
  client_login.setAuthPluginName("sha256_password");
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(*router_, upstreamPool(db));

  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        AuthSwitchMessage auth_switch{};
        etractBufferData(auth_switch, data, 2, data.length() - 4);
        EXPECT_EQ(auth_switch.getAuthPluginName(), "mysql_native_password");
      }));
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
}

TEST_F(MySQLFilterTest, PassAuthWriteQueryButUpstreamClientNotReady) {
  std::string username = "username";
  std::string db = "db";
  std::string password = "password";
  auto client_login =
      MessageHelper::encodeClientLogin(AuthMethod::NativePassword, username, password, db, seed_);
  EXPECT_EQ(client_login.getAuthResp().size(), 20);
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData).WillOnce(Invoke([&](Buffer::Instance& data) {
    ClientLogin login{};
    etractBufferData(login, data, 1, data.length() - 4);
    decoder_callbacks_->onClientLogin(login);
  }));
  EXPECT_CALL(*decoder_, getSession()).Times(2);
  EXPECT_CALL(*router_, upstreamPool(db));
  EXPECT_CALL(*route_, upstream());

  EXPECT_CALL(*pool_, newConnection(_));
  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        OkMessage ok{};
        etractBufferData(ok, data, 2, data.length() - 4);
      }));

  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);

  std::string query = "select * from test";
  auto cmd = MessageHelper::encodeCommand(Command::Cmd::Query, query, "", true);
  buffer = MessageHelper::encodePacket(cmd, 0);
  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::StopIteration);
}

TEST_F(MySQLFilterTest, PassAuthWriteQueryAndUpstreamClientIsReady) {
  std::string username = "username";
  std::string db = "db";
  std::string password = "password";
  auto client_login =
      MessageHelper::encodeClientLogin(AuthMethod::NativePassword, username, password, db, seed_);
  EXPECT_EQ(client_login.getAuthResp().size(), 20);
  auto buffer = MessageHelper::encodePacket(client_login, 1);

  EXPECT_CALL(*decoder_, onData)
      .WillOnce(Invoke([&](Buffer::Instance& data) {
        ClientLogin login{};
        etractBufferData(login, data, 1, data.length() - 4);
        decoder_callbacks_->onClientLogin(login);
      }))
      .WillOnce(Invoke([&](Buffer::Instance& data) {
        Command command{};
        etractBufferData(command, data, 0, data.length() - 4);
        decoder_callbacks_->onCommand(command);
      }));

  EXPECT_CALL(*router_, upstreamPool(db));
  EXPECT_CALL(*route_, upstream());

  EXPECT_CALL(filter_callbacks_, continueReading());
  EXPECT_CALL(*decoder_, getSession()).Times(4);
  auto* client_data = new Tcp::ConnectionPool::MockConnectionData();

  EXPECT_CALL(*client_, makeRequest(_));
  EXPECT_CALL(*pool_, newConnection(_))
      .WillOnce(
          Invoke([&](ConnPool::ClientPoolCallBack& callbacks) -> Tcp::ConnectionPool::Cancellable* {
            callbacks.onPoolReady(
                std::unique_ptr<Tcp::ConnectionPool::MockConnectionData>(client_data), nullptr);
            return nullptr;
          }));
  EXPECT_CALL(filter_callbacks_.connection_, write(_, false))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        OkMessage ok{};
        etractBufferData(ok, data, 2, data.length() - 4);
      }))
      .WillOnce(Invoke([&](Buffer::Instance& data, bool) {
        CommandResponse cmd_resp{};
        etractBufferData(cmd_resp, data, 1, data.length() - 4);
      }));

  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);

  std::string query = "select * from test";
  auto cmd = MessageHelper::encodeCommand(Command::Cmd::Query, query, "", true);
  buffer = MessageHelper::encodePacket(cmd, 0);

  EXPECT_EQ(filter_->onData(buffer, false), Network::FilterStatus::Continue);
  std::string response = "command response";
  auto cmd_resp = MessageHelper::encodeCommandResponse(response);
  filter_->onResponse(cmd_resp, 1);
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
