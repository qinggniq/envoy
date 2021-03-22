#include "extensions/filters/network/mysql_proxy/mysql_filter.h"

#include "envoy/api/api.h"
#include "envoy/config/core/v3/base.pb.h"
#include "envoy/extensions/filters/network/mysql_proxy/v3/mysql_proxy.pb.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/tcp/conn_pool.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/assert.h"
#include "common/common/logger.h"
#include "common/config/datasource.h"

#include "extensions/filters/network/mysql_proxy/conn_pool.h"
#include "extensions/filters/network/mysql_proxy/fault.h"
#include "extensions/filters/network/mysql_proxy/message_helper.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_greeting.h"
#include "extensions/filters/network/mysql_proxy/mysql_decoder_impl.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "extensions/filters/network/well_known_names.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

MySQLFilterConfig::MySQLFilterConfig(
    Stats::Scope& scope,
    const envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy& config, Api::Api& api)
    : stats_(generateStats(fmt::format("mysql.{}.", config.stat_prefix()), scope)),
      username_(Config::DataSource::read(config.downstream_auth_username(), true, api)),
      password_(Config::DataSource::read(config.downstream_auth_password(), true, api)) {}

MySQLFilter::MySQLFilter(MySQLFilterConfigSharedPtr config, RouterSharedPtr router,
                         ClientFactory& client_factory, DecoderFactory& decoder_factory,
                         FaultManagerSharedPtr fault_manager)
    : config_(std::move(config)), decoder_(decoder_factory.create(*this)), router_(router),
      client_factory_(client_factory), decoder_factory_(decoder_factory), client_(nullptr),
      fault_manager_(fault_manager) {}

void MySQLFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
  read_callbacks_->connection().addConnectionCallbacks(*this);
}

void MySQLFilter::onEvent(Network::ConnectionEvent event) {
  if (event == Network::ConnectionEvent::RemoteClose ||
      event == Network::ConnectionEvent::LocalClose) {
    if (delay_timer_) {
      delay_timer_->disableTimer();
      delay_timer_.reset();
    }
    if (canceler_) {
      canceler_->cancel();
      canceler_ = nullptr;
    }
    if (client_) {
      client_->close();
    }
  }
}

Network::FilterStatus MySQLFilter::onData(Buffer::Instance& data, bool) {
  ENVOY_LOG(trace, "downstream data sent, len {}", data.length());
  read_buffer_.move(data);
  if ((client_ == nullptr && authed_) || delay_timer_) {
    return Network::FilterStatus::StopIteration;
  }
  doDecode(read_buffer_);
  return Network::FilterStatus::Continue;
}

void MySQLFilter::doDecode(Buffer::Instance& buffer) {
  // Clear dynamic metadata.
  envoy::config::core::v3::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  auto& metadata =
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy];
  metadata.mutable_fields()->clear();

  try {
    decoder_->onData(buffer);
  } catch (EnvoyException& e) {
    ENVOY_LOG(info, "mysql_proxy: decoding error: {}", e.what());
    config_->stats_.decoder_errors_.inc();
    read_buffer_.drain(read_buffer_.length());
    write_buffer_.drain(write_buffer_.length());
  }
}

void MySQLFilter::onClientReady(ConnectionPool::ClientDataPtr&& client_data) {
  client_ = client_factory_.create(std::move(client_data), decoder_factory_, *this);
  canceler_ = nullptr;
  read_callbacks_->continueReading();
  ENVOY_LOG(trace, "upstream client is ready, continue reading");
}

void MySQLFilter::onClientFailure(ConnectionPool::MySQLPoolFailureReason reason) {
  config_->stats_.login_failures_.inc();
  // triggers the release of the current stream at the end of the filter's callback.
  switch (reason) {
  case ConnectionPool::MySQLPoolFailureReason::Overflow:
    ENVOY_LOG(info, "mysql proxy upstream connection pool: too many connections");
    break;
  case ConnectionPool::MySQLPoolFailureReason::LocalConnectionFailure:
    ENVOY_LOG(info, "mysql proxy upstream connection pool: local connection failure");
    break;
  case ConnectionPool::MySQLPoolFailureReason::RemoteConnectionFailure:
    ENVOY_LOG(info, "mysql proxy upstream connection pool: remote connection failure");
    break;
  case ConnectionPool::MySQLPoolFailureReason::Timeout:
    ENVOY_LOG(info, "mysql proxy upstream connection pool: connection failure due to time out");
    break;
  case ConnectionPool::MySQLPoolFailureReason::AuthFailure:
    ENVOY_LOG(info, "mysql proxy upstream connection pool: connection failure due to auth");
    break;
  case ConnectionPool::MySQLPoolFailureReason::ParseFailure:
    ENVOY_LOG(info,
              "mysql proxy upstream connection pool: connection failure due to error of parsing");
    break;
  default:
    ENVOY_LOG(error, "mysql proxy upstream connection pool: unknown error");
  }
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
}

void MySQLFilter::onResponse(MySQLCodec& codec, uint8_t seq) {
  auto buffer = MessageHelper::encodePacket(codec, seq);
  if (delay_timer_) {
    write_buffer_.move(buffer);
    return;
  }
  read_callbacks_->connection().write(buffer, false);
}

void MySQLFilter::onFailure() {
  ENVOY_LOG(error, "upstream client: proxy to server occur failure");
  read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
}

void MySQLFilter::onProtocolError() { config_->stats_.protocol_errors_.inc(); }

void MySQLFilter::onNewMessage(MySQLSession::State state) {
  if (state == MySQLSession::State::ChallengeReq) {
    config_->stats_.login_attempts_.inc();
  }
}

void MySQLFilter::onClientLogin(ClientLogin& client_login) {
  if (client_login.isSSLRequest()) {
    config_->stats_.upgraded_to_ssl_.inc();
    ENVOY_LOG(error, "client try to upgrade to ssl, which can not be handled");
    read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
    return;
  }
  if (config_->username_ != client_login.getUsername()) {
    onFailure(MessageHelper::authError(
                  client_login.getUsername(),
                  read_callbacks_->connection().addressProvider().remoteAddress()->asString(),
                  true),
              2);
    return;
  }
  auto route = router_->upstreamPool(client_login.getDb());
  if (route == nullptr) {
    onFailure(MessageHelper::dbError(client_login.getDb()), 2);
    return;
  }
  if (client_login.isResponse41() &&
      (client_login.getAuthPluginName() == "mysql_native_password")) {
    if (client_login.getAuthResp().size() != NATIVE_PSSWORD_HASH_LENGTH) {
      onFailure(MessageHelper::passwordLengthError(client_login.getAuthResp().size()), 2);
      return;
    }
    if (AuthHelper::nativePasswordSignature(config_->password_, seed_) !=
        client_login.getAuthResp()) {
      onFailure(MessageHelper::authError(
                    client_login.getUsername(),
                    read_callbacks_->connection().addressProvider().remoteAddress()->asString(),
                    true),
                2);
      return;
    }
  } else if (client_login.isResponse320()) {
    if (client_login.getAuthResp().size() != OLD_PASSWORD_HASH_LENGTH) {
      onFailure(MessageHelper::passwordLengthError(client_login.getAuthResp().size()), 2);
      return;
    }
    if (AuthHelper::oldPasswordSignature(config_->password_, seed_) != client_login.getAuthResp()) {
      onFailure(MessageHelper::authError(
                    client_login.getUsername(),
                    read_callbacks_->connection().addressProvider().remoteAddress()->asString(),
                    true),
                2);
      return;
    }
  } else {
    auto auth_switch = MessageHelper::encodeAuthSwitch(seed_);
    auto buffer = MessageHelper::encodePacket(auth_switch, 2);
    read_callbacks_->connection().write(buffer, false);
    return;
  }
  auto& pool = route->upstream();
  canceler_ = pool.newMySQLClient(*this);
  onAuthOk();
}

void MySQLFilter::onAuthOk() {
  ENVOY_LOG(debug, "downstream auth ok, wait for upstream connection ready");
  authed_ = true;
  OkMessage ok = MessageHelper::encodeOk();
  auto buffer = MessageHelper::encodePacket(ok, MYSQL_LOGIN_RESP_PKT_NUM);
  decoder_->getSession().setExpectedSeq(MYSQL_REQUEST_PKT_NUM);
  decoder_->getSession().setState(MySQLSession::State::Req);
  read_callbacks_->connection().write(buffer, false);
}

void MySQLFilter::onFailure(const ClientLoginResponse& err, uint8_t seq) {
  auto buffer = MessageHelper::encodePacket(err, seq);
  read_callbacks_->connection().write(buffer, false);
}

void MySQLFilter::onClientLoginResponse(ClientLoginResponse&) {
  ENVOY_LOG(error, "mysql filter: onClientLoginResponse impossible callback is called");
}

void MySQLFilter::onMoreClientLoginResponse(ClientLoginResponse&) {
  ENVOY_LOG(error, "mysql filter: onMoreClientLoginResponse impossible callback is called");
}

void MySQLFilter::onCommand(Command& command) {
  ASSERT(client_ != nullptr);
  const Fault* fault;
  if (command.isQuery()) {
    envoy::config::core::v3::Metadata& dynamic_metadata =
        read_callbacks_->connection().streamInfo().dynamicMetadata();
    ProtobufWkt::Struct metadata(
        (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy]);

    auto result = Common::SQLUtils::SQLUtils::setMetadata(command.getData(),
                                                          decoder_->getAttributes(), metadata);

    ENVOY_CONN_LOG(trace, "mysql_proxy: query processed {}", read_callbacks_->connection(),
                   command.getData());
    if (!result) {
      config_->stats_.queries_parse_error_.inc();
    } else {
      config_->stats_.queries_parsed_.inc();
      read_callbacks_->connection().streamInfo().setDynamicMetadata(
          NetworkFilterNames::get().MySQLProxy, metadata);
    }
    for (const auto& kv : metadata.fields()) {
      fault = fault_manager_->getFaultForCommand(kv.second.string_value());
      break;
    }
  } else {
    fault = fault_manager_->getFaultForCommand("ALL_KEY");
  }
  tryInjectFault(fault);
  if (command.getCmd() == Command::Cmd::Quit) {
    read_callbacks_->connection().close(Network::ConnectionCloseType::NoFlush);
    return;
  }
  // Parse a given query
  decoder_->getSession().setExpectedSeq(MYSQL_REQUEST_PKT_NUM);
  decoder_->getSession().setState(MySQLSession::State::Req);
  auto buffer = MessageHelper::encodePacket(command, MYSQL_REQUEST_PKT_NUM);
  client_->makeRequest(buffer);
}

void MySQLFilter::delayInjectionTimerCallback() {
  delay_timer_.reset();
  // write the response
  if (write_buffer_.length() > 0) {
    read_callbacks_->connection().write(write_buffer_, false);
  }
  // Continue request processing.
  read_callbacks_->continueReading();
}

void MySQLFilter::tryInjectFault(const Fault* fault) {
  const bool has_delay_fault = fault != nullptr && fault->delayMs() > std::chrono::milliseconds(0);
  // Do not try to inject delays if there is an active delay.
  // Make sure to capture stats for the request otherwise.
  if (has_delay_fault && delay_timer_) {
    return;
  }
  if (has_delay_fault) {
    ENVOY_LOG(debug, "mysql filter: inject a delay to downstream");
    delay_timer_ = read_callbacks_->connection().dispatcher().createTimer(
        [this]() -> void { delayInjectionTimerCallback(); });
    delay_timer_->enableTimer(fault->delayMs());
  }
  const bool has_error_fault = fault != nullptr && fault->faultType() == FaultType::Error;
  if (has_error_fault) {
    ENVOY_LOG(debug, "mysql filter: inject a error to downstream");
    onFailure(MessageHelper::injectError(), MYSQL_RESPONSE_PKT_NUM);
  }
}

Network::FilterStatus MySQLFilter::onNewConnection() {
  config_->stats_.sessions_.inc();
  seed_ = AuthHelper::generateSeed();
  auto greet = MessageHelper::encodeGreeting(seed_);
  Buffer::OwnedImpl buffer = MessageHelper::encodePacket(greet, GREETING_SEQ_NUM);
  decoder_->getSession().setExpectedSeq(GREETING_SEQ_NUM + 1);
  decoder_->getSession().setState(MySQLSession::State::ChallengeReq);
  read_callbacks_->connection().write(buffer, false);
  return Network::FilterStatus::Continue;
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
