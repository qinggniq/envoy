#include "extensions/filters/network/mysql_proxy/mysql_config.h"

#include <string>

#include "envoy/config/core/v3/base.pb.h"
#include "envoy/extensions/filters/network/mysql_proxy/v3/mysql_proxy.pb.h"
#include "envoy/extensions/filters/network/mysql_proxy/v3/mysql_proxy.pb.validate.h"
#include "envoy/registry/registry.h"
#include "envoy/server/filter_config.h"

#include "common/common/logger.h"
#include "common/config/datasource.h"

#include "extensions/filters/network/mysql_proxy/mysql_decoder.h"
#include "extensions/filters/network/mysql_proxy/mysql_decoder_impl.h"
#include "extensions/filters/network/mysql_proxy/mysql_filter.h"
#include "extensions/filters/network/mysql_proxy/route.h"
#include "extensions/filters/network/mysql_proxy/route_impl.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {
/**
 * Config registration for the MySQL proxy filter. @see NamedNetworkFilterConfigFactory.
 */
Network::FilterFactoryCb
NetworkFilters::MySQLProxy::MySQLConfigFactory::createFilterFactoryFromProtoTyped(
    const envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy& proto_config,
    Server::Configuration::FactoryContext& context) {

  ASSERT(!proto_config.stat_prefix().empty());

  absl::flat_hash_map<std::string, RouteSharedPtr> routes;
  RouteSharedPtr primary_cluster_route = nullptr;
  for (const auto& route : proto_config.routes()) {
    if (primary_cluster_route == nullptr) {
      primary_cluster_route =
          RouteFactoryImpl::instance.create(&context.clusterManager(), route.cluster());
    }
    routes.emplace(route.database(),
                   RouteFactoryImpl::instance.create(&context.clusterManager(), route.cluster()));
  }
  auto router = std::make_shared<RouterImpl>(primary_cluster_route, std::move(routes));

  MySQLFilterConfigSharedPtr filter_config(
      std::make_shared<MySQLFilterConfig>(context.scope(), proto_config));
  return [filter_config, router](Network::FilterManager& filter_manager) -> void {
    filter_manager.addReadFilter(
        std::make_shared<MySQLFilter>(filter_config, router, DecoderFactoryImpl::instance_));
  };
}

/**
 * Static registration for the MySQL proxy filter. @see RegisterFactory.
 */
REGISTER_FACTORY(MySQLConfigFactory, Server::Configuration::NamedNetworkFilterConfigFactory);

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
