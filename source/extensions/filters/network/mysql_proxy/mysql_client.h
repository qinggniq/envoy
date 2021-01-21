#pragma once
#include "envoy/upstream/cluster_manager.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

/*
 * MySQL Client connecting upstream database.
 * Sometimes downstream could connect to server without spec db name, the proxy-server connection
 * info should be determined when downstream real connect. This Client will real connect database
 * when calling @connect function.
 */
class Client : public Event::DeferredDeletable {
public:
  ~Client() override = default;

  virtual void makeRequest(MySQLCodec&) PURE;

  virtual void connect() PURE;

  virtual void close() PURE;
};

using ClientPtr = std::unique_ptr<Client>;

class ClientFactory {
public:
  virtual ~ClientFactory() = default;
  virtual ClientPtr create(Upstream::ClusterManager&, std::string cluster_name);
};

} // namespace MySQLProxy

} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy