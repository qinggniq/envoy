#include "extensions/filters/network/mysql_proxy/mysql_filter.h"

#include "envoy/buffer/buffer.h"
#include "envoy/config/core/v3/base.pb.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/assert.h"
#include "common/common/logger.h"

#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "extensions/filters/network/well_known_names.h"
#include "source/extensions/filters/network/mysql_proxy/_virtual_includes/codec_lib/extensions/filters/network/mysql_proxy/mysql_codec.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

MySQLFilterConfig::MySQLFilterConfig(const std::string& stat_prefix, Stats::Scope& scope)
    : scope_(scope), stats_(generateStats(stat_prefix, scope)) {}

MySQLFilter::MySQLFilter(MySQLFilterConfigSharedPtr config) : config_(std::move(config)) {}

void MySQLFilter::initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) {
  read_callbacks_ = &callbacks;
}

Network::FilterStatus MySQLFilter::onData(Buffer::Instance& data, bool) {
  // Safety measure just to make sure that if we have a decoding error we keep going and lose stats.
  // This can be removed once we are more confident of this code.
  doDecode(data);
  return Network::FilterStatus::Continue;
}

Network::FilterStatus MySQLFilter::onWrite(Buffer::Instance& data, bool) {
  // Safety measure just to make sure that if we have a decoding error we keep going and lose stats.
  // This can be removed once we are more confident of this code.
  doDecode(data);
  return Network::FilterStatus::Continue;
}

void MySQLFilter::doDecode(Buffer::Instance& buffer) {
  // Clear dynamic metadata.
  envoy::config::core::v3::Metadata& dynamic_metadata =
      read_callbacks_->connection().streamInfo().dynamicMetadata();
  auto& metadata =
      (*dynamic_metadata.mutable_filter_metadata())[NetworkFilterNames::get().MySQLProxy];
  metadata.mutable_fields()->clear();

  if (!decoder_) {
    decoder_ = createDecoder(*this);
  }

  try {
    decoder_->onData(buffer);
  } catch (EnvoyException& e) {
    ENVOY_LOG(info, "mysql_proxy: decoding error: {}", e.what());
    config_->stats_.decoder_errors_.inc();
    sniffing_ = false;
    // read_buffer_.drain(read_buffer_.length());
    // write_buffer_.drain(write_buffer_.length());
  }
}

DecoderPtr MySQLFilter::createDecoder(DecoderCallbacks& callbacks) {
  return std::make_unique<DecoderImpl>(callbacks);
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
  }
  // send to server auth info
  auto username = config_->getDownstreamAuthUsername();
  auto password = config_->getDownstreamAuthPassword();
  if (username != client_login.getUsername()) {
    connect_allowed_ = false;
    onAuthFailure("username is not match");
    return;
  }

  client_login.setUsername(username);
  downsteram_auth_resp_ = client_login.getAuthResp();
  // TODO(qinggniq) write own auth resp to upstream
  std::string authResp = "";
  client_login.setAuthResp(authResp);

  client_->makeRequest(client_login);
}

void MySQLFilter::onAuthFailure(std::string&& reason) {
  client_->close();
  Buffer::OwnedImpl buffer;
  BufferHelper::addUint8(buffer, MYSQL_RESP_ERR);
  BufferHelper::addUint16(buffer, MYSQL_CR_AUTH_PLUGIN_ERR);
  BufferHelper::addString(buffer, std::move(reason));
  writeDownstream(buffer);
}

std::string MySQLFilter::scramAuth() {}

void MySQLFilter::onClientLoginResponse(ClientLoginResponse& client_login_resp) {
  // Auth Ok for upstream, now valid the downstream passowrd
  if (client_login_resp.getRespCode() == MYSQL_RESP_OK) {
    // use auth method to
    if (downsteram_auth_resp_ != scramAuth()) {
      config_->stats_.login_failures_.inc();
      onAuthFailure("auth failed");
    }
  }
  if (client_login_resp.getRespCode() == MYSQL_RESP_AUTH_SWITCH) {
    config_->stats_.auth_switch_request_.inc();
    Buffer::OwnedImpl buffer;
    client_login_resp.encode(buffer);
    writeDownstream(buffer);
    return;
  }
  if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
    ENVOY_LOG(error, "can not connect to upstream cluster");
    onAuthFailure("proxy failed to connect to upstream server");
  }
}

void MySQLFilter::onMoreClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
  }
}

void MySQLFilter::onCommand(Command& command) {
  if (!command.isQuery()) {
    return;
  }

  // Parse a given query
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
    return;
  }
  config_->stats_.queries_parsed_.inc();

  read_callbacks_->connection().streamInfo().setDynamicMetadata(
      NetworkFilterNames::get().MySQLProxy, metadata);
}

Network::FilterStatus MySQLFilter::onNewConnection() {
  config_->stats_.sessions_.inc();
  callbacks_->connection().noDelay(true);
  client_->connect();
  return Network::FilterStatus::Continue;
}

void MySQLFilter::writeDownstream(Buffer::Instance& data) {
  callbacks_->connection().write(data, false);
}

void MySQLFilter::onServerGreeting(ServerGreeting& sg) {
  Buffer::OwnedImpl buffer;
  seed_ = sg.getSalt();
  // 1. 如果 server 是5.5以上那么打印一条日志
  // 2. 根据 protocol 的 version 确定加密方式
  // 3. 存储 server 的 cap 位
  sg.encode(buffer);
  sg.getProtocol() writeDownstream(buffer);
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
