#pragma once

#include "envoy/access_log/access_log.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/stats/scope.h"
#include "envoy/stats/stats.h"
#include "envoy/stats/stats_macros.h"

#include "common/common/logger.h"

#include "extensions/filters/network/mysql_proxy/mysql_client.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_command.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_greeting.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_switch_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_decoder.h"
#include "extensions/filters/network/mysql_proxy/mysql_session.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

/**
 * All MySQL proxy stats. @see stats_macros.h
 */
#define ALL_MYSQL_PROXY_STATS(COUNTER)                                                             \
  COUNTER(sessions)                                                                                \
  COUNTER(login_attempts)                                                                          \
  COUNTER(login_failures)                                                                          \
  COUNTER(decoder_errors)                                                                          \
  COUNTER(protocol_errors)                                                                         \
  COUNTER(upgraded_to_ssl)                                                                         \
  COUNTER(auth_switch_request)                                                                     \
  COUNTER(queries_parsed)                                                                          \
  COUNTER(queries_parse_error)

/**
 * Struct definition for all MySQL proxy stats. @see stats_macros.h
 */
struct MySQLProxyStats {
  ALL_MYSQL_PROXY_STATS(GENERATE_COUNTER_STRUCT)
};

/**
 * Configuration for the MySQL proxy filter.
 */
class MySQLFilterConfig {
public:
  MySQLFilterConfig(const std::string& stat_prefix, Stats::Scope& scope);

  const MySQLProxyStats& stats() { return stats_; }

  std::string getDownstreamAuthPassword() { return downstream_auth_password_; }
  std::string getDownstreamAuthUsername() { return downstream_auth_username_; }
  std::string getUpstreamAuthPassword() { return upstream_auth_password_; }
  std::string getUpstreamAuthUsername() { return upstream_auth_username_; }
  Stats::Scope& scope_;
  MySQLProxyStats stats_;
  std::string downstream_auth_username_;
  std::string downstream_auth_password_;
  std::string upstream_auth_username_;
  std::string upstream_auth_password_;

private:
  MySQLProxyStats generateStats(const std::string& prefix, Stats::Scope& scope) {
    return MySQLProxyStats{ALL_MYSQL_PROXY_STATS(POOL_COUNTER_PREFIX(scope, prefix))};
  }
};

using MySQLFilterConfigSharedPtr = std::shared_ptr<MySQLFilterConfig>;

/**
 * Implementation of MySQL proxy filter.
 */
class MySQLFilter : public Network::Filter, DecoderCallbacks, Logger::Loggable<Logger::Id::filter> {
public:
  MySQLFilter(MySQLFilterConfigSharedPtr config);
  ~MySQLFilter() override = default;

  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;
  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;

  // Network::WriteFilter
  Network::FilterStatus onWrite(Buffer::Instance& data, bool end_stream) override;

  // MySQLProxy::DecoderCallback
  void onProtocolError() override;
  void onNewMessage(MySQLSession::State state) override;
  void onServerGreeting(ServerGreeting&) override;
  void onClientLogin(ClientLogin& message) override;
  void onClientLoginResponse(ClientLoginResponse& message) override;
  void onClientSwitchResponse(ClientSwitchResponse&) override;
  void onMoreClientLoginResponse(ClientLoginResponse& message) override;
  void onCommand(Command& message) override;
  void onCommandResponse(CommandResponse&) override {}

  void onAuthFailure(std::string&&);
  std::string scramAuth();
  void doDecode(Buffer::Instance& buffer);
  DecoderPtr createDecoder(DecoderCallbacks& callbacks);
  MySQLSession& getSession() { return decoder_->getSession(); }

  void writeDownstream(Buffer::Instance& data);
  void writeDownstream(MySQLCodec& codec);

private:
  std::string authResp(AuthMethod method);
  bool authDownstream(AuthMethod method, const std::string& downstream_username,
                      const std::string& downstream_auth_resp);
  void onAuthUpstream(AuthMethod method, ClientLogin& client_login);

private:
  ClientPtr client_;
  Network::ReadFilterCallbacks* read_callbacks_{};
  MySQLFilterConfigSharedPtr config_;
  Network::ReadFilterCallbacks* callbacks_{};
  // Buffer::OwnedImpl read_buffer_;
  // Buffer::OwnedImpl write_buffer_;
  std::unique_ptr<Decoder> decoder_;
  std::string seed_;
  AuthMethod upstream_auth_method_{OldPassword};
  AuthMethod downstream_auth_method_{OldPassword};
  bool sniffing_{true};
  bool authed_{false};
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
