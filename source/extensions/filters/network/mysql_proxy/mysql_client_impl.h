#include "envoy/buffer/buffer.h"
#include "envoy/network/connection.h"

#include "common/network/filter_impl.h"

#include "extensions/filters/network/mysql_proxy/mysql_client.h"
#include "extensions/filters/network/mysql_proxy/mysql_decoder.h"
#include "extensions/filters/network/mysql_proxy/mysql_session.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

class ClientImpl : public Client, Envoy::Network::ConnectionCallbacks {

public:
  ClientImpl(Upstream::HostConstSharedPtr host, Event::Dispatcher& dispatcher, Decoder& decoder,
             const std::string& auth_username, const std::string& auth_password);
  ClientPtr create(Upstream::HostConstSharedPtr host, Event::Dispatcher& dispatcher,
                   Decoder& decoder, const std::string& auth_username,
                   const std::string& auth_password);

  // Client
  void makeRequest(MySQLCodec&) override;
  void connect() override;
  void close() override;

  // ConnectionCallbacks
  void onEvent(Envoy::Network::ConnectionEvent) override {}
  void onAboveWriteBufferHighWatermark() override {}
  void onBelowWriteBufferLowWatermark() override {}

  // ReadFilter
  Network::FilterStatus onData(Buffer::Instance& data);

private:
  struct UpstreamReadFilter : public Network::ReadFilterBaseImpl {
    UpstreamReadFilter(ClientImpl& parent) : parent_(parent) {}

    // Network::ReadFilter
    Network::FilterStatus onData(Buffer::Instance& data, bool) override {
      parent_.onData(data);
      return Network::FilterStatus::Continue;
    }

    ClientImpl& parent_;
  };
  std::string auth_username_;
  std::string auth_passowrd_;
  Decoder& decoder_;
  Buffer::OwnedImpl encode_buffer_;
  Envoy::Network::ClientConnectionPtr connection_;
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy