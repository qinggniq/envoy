#include "source/extensions/filters/network/mysql_proxy/mysql_client_impl.h"

#include "envoy/buffer/buffer.h"
#include "envoy/common/exception.h"

#include "envoy/network/filter.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"

#include "mysql_client.h"
#include <memory>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {
ClientImpl::ClientImpl(Upstream::HostConstSharedPtr host, Event::Dispatcher& dispatcher,
                       Decoder& decoder, const std::string& auth_username,
                       const std::string& auth_password)
    : auth_username_(auth_username), auth_passowrd_(auth_password), decoder_(decoder) {
  connection_ = host->createConnection(dispatcher, nullptr, nullptr).connection_;
  connection_.addConnectionCallbacks(*this);
}

ClientPtr ClientImpl::create(Upstream::HostConstSharedPtr host, Event::Dispatcher& dispatcher,
                             Decoder& decoder, const std::string& auth_username,
                             const std::string& auth_password) {
  return std::make_unique<ClientImpl>(host, dispatcher, decoder, auth_username, auth_password);
}

void ClientImpl::connect() {
  try {
    connection_->connect();
    connection_->noDelay(true);

  } catch (EnvoyException& e) {
  }
}

void ClientImpl::close() { connection_->close(); }

void ClientImpl::makeRequest(MySQLCodec& codec) {
  codec.encode(encode_buffer_);
  try {
    connection_->write(encode_buffer_, false);
  } catch (EnvoyException& e) {
    connection_->close();
  }
}

Network::FilterStatus ClientImpl::onData(Buffer::Instance& data) {
  try {
    decoder_.onData(data);
  } catch (EnvoyException& e) {
    connection_->close();
    return Network::FilterStatus::StopIteration;
  }
  return Network::FilterStatus::Continue;
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy