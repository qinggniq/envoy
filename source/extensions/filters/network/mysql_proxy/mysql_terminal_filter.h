#pragma once

#include <bits/stdint-uintn.h>

#include "envoy/access_log/access_log.h"
#include "envoy/api/api.h"
#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"
#include "envoy/network/filter.h"
#include "envoy/tcp/conn_pool.h"

#include "mysql_codec.h"
#include "source/common/buffer/buffer_impl.h"
#include "source/common/common/logger.h"
#include "source/extensions/filters/network/mysql_proxy/mysql_decoder.h"
#include "source/extensions/filters/network/mysql_proxy/mysql_filter.h"

#include "mysql_codec_clogin_resp.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

/**
 * Implementation of MySQL proxy filter.
 */
class MySQLTerminalFilter : public Tcp::ConnectionPool::Callbacks,
                            public MySQLMonitorFilter,
                            public Network::ConnectionCallbacks {
public:
  MySQLTerminalFilter(MySQLFilterConfigSharedPtr config, RouterSharedPtr router,
                      DecoderFactory& factory, Api::Api& api);
  ~MySQLTerminalFilter() override = default;
  // Network::ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data, bool end_stream) override;
  Network::FilterStatus onNewConnection() override;

  void initializeReadFilterCallbacks(Network::ReadFilterCallbacks& callbacks) override;

  // Tcp::ConnectionPool::Callbacks
  void onPoolReady(Envoy::Tcp::ConnectionPool::ConnectionDataPtr&& conn,
                   Upstream::HostDescriptionConstSharedPtr host) override;
  void onPoolFailure(Tcp::ConnectionPool::PoolFailureReason,
                     Upstream::HostDescriptionConstSharedPtr host) override;

  // ConnectionCallback
  void onEvent(Network::ConnectionEvent event) override;
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  void closeLocal();
  void closeRemote();
  void sendLocal(const MySQLCodec& message);
  void sendRemote(const MySQLCodec& message);
  void gotoCommandPhase();
  void stepLocalSession(uint8_t expected_seq, MySQLSession::State expected_state);
  void stepRemoteSession(uint8_t expected_seq, MySQLSession::State expected_state);
  void onFailure(const ErrMessage& err);
  void onFailure(ErrMessage& err, uint8_t seq);
  void initUpstreamAuthInfo(Upstream::ThreadLocalCluster* cluster);
  void initDownstreamAuthInfo(const std::string& username, const std::string& password);
  struct DownstreamEventHandler : public DecoderCallbacks {
    DownstreamEventHandler(MySQLTerminalFilter& filter);

    Network::FilterStatus onData(Buffer::Instance& data, bool end_stream);
    // DecoderCallbacks
    void onProtocolError() override;
    void onNewMessage(MySQLSession::State) override;
    void onServerGreeting(ServerGreeting&) override;
    void onClientLogin(ClientLogin&) override;
    void onClientLoginResponse(ClientLoginResponse&) override;
    void onClientSwitchResponse(ClientSwitchResponse&) override;
    void onMoreClientLoginResponse(ClientLoginResponse&) override;
    void onCommand(Command&) override;
    void onCommandResponse(CommandResponse&) override;
    absl::optional<ErrMessage> checkAuth(const std::string& username,
                                         const std::vector<uint8_t>& login,
                                         const std::vector<uint8_t>& expect_sig);
    void tryConnectUpstream(uint8_t seq);

    void onAuthSucc();

    MySQLTerminalFilter& parent;
    DecoderPtr decoder;
    Buffer::OwnedImpl buffer;
    std::vector<uint8_t> seed;
    absl::optional<OkMessage> pending_response;
  };
  using DownstreamEventHandlerPtr = std::unique_ptr<DownstreamEventHandler>;

  struct UpstreamEventHandler : public Tcp::ConnectionPool::UpstreamCallbacks,
                                public DecoderCallbacks {
    UpstreamEventHandler(MySQLTerminalFilter& filter);
    // Network::UpstreamCallback
    void onUpstreamData(Buffer::Instance& buffer, bool end_stream) override;
    void onEvent(Network::ConnectionEvent event) override;
    void onAboveWriteBufferHighWatermark() override {}
    void onBelowWriteBufferLowWatermark() override {}

    // DecoderCallbacks
    void onProtocolError() override;
    void onNewMessage(MySQLSession::State) override;
    void onServerGreeting(ServerGreeting&) override;
    void onClientLogin(ClientLogin&) override;
    void onClientLoginResponse(ClientLoginResponse&) override;
    void onClientSwitchResponse(ClientSwitchResponse&) override;
    void onMoreClientLoginResponse(ClientLoginResponse&) override;
    void onCommand(Command&) override;
    void onCommandResponse(CommandResponse&) override;

    void onAuthSucc();

    MySQLTerminalFilter& parent;
    DecoderPtr decoder;
    Buffer::OwnedImpl buffer;
    std::vector<uint8_t> seed;
    bool ready{false};
  };
  using UpstreamEventHandlerPtr = std::unique_ptr<UpstreamEventHandler>;

  friend class MySQLTerminalFitlerTest;
  friend class MySQLFilterTest;

private:
  UpstreamEventHandlerPtr upstream_event_handler_;
  DownstreamEventHandlerPtr downstream_event_handler_;
  DecoderFactory& decoder_factory_;
  RouterSharedPtr router_;
  Envoy::ConnectionPool::Cancellable* canceler_{nullptr};
  Tcp::ConnectionPool::ConnectionDataPtr upstream_conn_data_;
  Api::Api& api_;
  std::string connect_db_;
  std::string downstream_username_;
  std::string downstream_password_;
  std::string upstream_username_;
  std::string upstream_password_;
};

using MySQLTerminalFilterPtr = std::unique_ptr<MySQLTerminalFilter>;
} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
