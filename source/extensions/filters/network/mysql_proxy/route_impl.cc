#include "extensions/filters/network/mysql_proxy/route_impl.h"

#include "envoy/api/api.h"
#include "envoy/event/dispatcher.h"
#include "envoy/runtime/runtime.h"
#include "envoy/upstream/cluster_manager.h"
#include "envoy/upstream/resource_manager.h"
#include "envoy/upstream/thread_local_cluster.h"
#include "envoy/upstream/upstream.h"

#include "extensions/filters/network/mysql_proxy/route.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

RouteImpl::RouteImpl(Upstream::ClusterManager* cm, const std::string& name)
    : cluster_name_(name), cm_(cm) {}

RouterImpl::RouterImpl(RouteSharedPtr primary_cluster_route,
                       absl::flat_hash_map<std::string, RouteSharedPtr>&& router)
    : primary_cluster_route_(primary_cluster_route), routes_(std::move(router)) {}

RouteSharedPtr RouterImpl::upstreamPool(const std::string& db) {
  if (routes_.find(db) != routes_.end()) {
    return routes_[db];
  }
  return nullptr;
}

RouteSharedPtr RouterImpl::primaryPool() { return primary_cluster_route_; }

RouteFactoryImpl RouteFactoryImpl::instance;

RouteSharedPtr RouteFactoryImpl::create(Upstream::ClusterManager* cm,
                                        const std::string& cluster_name) {
  return std::make_shared<RouteImpl>(cm, cluster_name);
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
