#include "extensions/filters/network/mysql_proxy/mysql_filter.h"

#include "envoy/buffer/buffer.h"
#include "envoy/config/core/v3/base.pb.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/assert.h"
#include "common/common/logger.h"

#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "extensions/filters/network/well_known_names.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"

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

  auto auth_method =
      AuthHelper::authMethod(client_login.getClientCap(), client_login.getExtendedClientCap());
  if (!authed_) {
    if (!authDownstream(auth_method, client_login.getUsername(), client_login.getAuthResp())) {
      onAuthFailure("username is not match");
      return;
    }
  }
  authed_ = true;
  auto upstream_username = config_->getUpstreamAuthUsername();
  // send upstream auth info
  client_login.setUsername(upstream_username);
  client_login.setAuthResp(authResp(auth_method));

  client_->makeRequest(client_login);
}

std::string MySQLFilter::authResp(AuthMethod method) {
  switch (method) {
  case OldPassword:
    return AuthHelper::oldPasswordSignature(config_->getUpstreamAuthPassword(), seed_);
  case NativePassword:
    return AuthHelper::nativePasswordSignature(config_->getUpstreamAuthPassword(), seed_);
  case PluginAuth:
    ENVOY_LOG(info, "");
    return "";
  }
}

bool MySQLFilter::authDownstream(AuthMethod method, const std::string& downstream_username,
                                 const std::string& downstream_auth_resp) {
  if (downstream_username != config_->getDownstreamAuthUsername()) {
    return false;
  }
  switch (method) {
  case OldPassword:
    return AuthHelper::oldPasswordVerify(config_->downstream_auth_password_, seed_,
                                         downstream_auth_resp);
    break;
  case NativePassword:
    return AuthHelper::nativePasswordVerify(config_->downstream_auth_password_, seed_,
                                            downstream_auth_resp);
    break;
  case PluginAuth:
    // TODO(qinggniq) log
    break;
  }
  return false;
}

void MySQLFilter::onAuthFailure(std::string&& reason) {
  client_->close();
  Buffer::OwnedImpl buffer;
  BufferHelper::addUint8(buffer, MYSQL_RESP_ERR);
  BufferHelper::addUint16(buffer, MYSQL_CR_AUTH_PLUGIN_ERR);
  BufferHelper::addString(buffer, std::move(reason));
  writeDownstream(buffer);
}

void MySQLFilter::onClientLoginResponse(ClientLoginResponse& client_login_resp) {
  switch (client_login_resp.getRespCode()) {
  case MYSQL_RESP_OK:
    // we auth downstream at @onClientLogin send auth response to downstream at
    // @onClientLoginResponse or auth at @onClientSwitchResponse send at @onMoreClientLoginResponse,
    // in this way we can guarantee the message seq
    writeDownstream(client_login_resp);
    break;
  case MYSQL_RESP_AUTH_SWITCH:
    config_->stats_.auth_switch_request_.inc();
    if (!client_login_resp.isOldAuthSwitchRequest()) {
      onAuthFailure("proxy cannot support auth plugin");
      return;
    }
    writeDownstream(client_login_resp);
    break;
  case MYSQL_RESP_ERR:
    config_->stats_.login_failures_.inc();
    ENVOY_LOG(error, "can not connect to upstream cluster");
    onAuthFailure("proxy failed to connect to upstream server");
    break;
  }
}
void MySQLFilter::onClientSwitchResponse(ClientSwitchResponse& client_switch_resp) {
  // we have authed downstream at @onClientLogin, so there is not need to auth by another auth
  // method
  ASSERT(authed_);
  // only support oldPasswordAuthSwitch
  client_switch_resp.setAuthPluginResp(authResp(OldPassword));
  client_->makeRequest(client_switch_resp);
}

void MySQLFilter::onMoreClientLoginResponse(ClientLoginResponse& client_login_resp) {
  if (client_login_resp.getRespCode() == MYSQL_RESP_ERR) {
    config_->stats_.login_failures_.inc();
    onAuthFailure("upstream server auth fail");
  }
  // authed_ must be true, or the state machine of decoder is broken
  ASSERT(authed_);
  writeDownstream(client_login_resp);
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

void MySQLFilter::writeDownstream(MySQLCodec& codec) {
  Buffer::OwnedImpl buffer;
  // TODO need to compact as packet
  codec.encode(buffer);
  writeDownstream(buffer);
}

void MySQLFilter::onServerGreeting(ServerGreeting& sg) {
  Buffer::OwnedImpl buffer;
  seed_ = sg.getAuthPluginData();
  upstream_auth_method_ = AuthHelper::authMethod(sg.getServerCap(), sg.getExtServerCap());
  // TODO(qinggniq) judge the server version, now mysql proxy only support version under 5.5 version
  sg.encode(buffer);
  writeDownstream(buffer);
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
