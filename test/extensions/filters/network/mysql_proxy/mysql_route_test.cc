#include "envoy/extensions/filters/network/mysql_proxy/v3/mysql_proxy.pb.h"

#include "extensions/filters/network/mysql_proxy/route_impl.h"

#include "test/mocks/upstream/mocks.h"

#include "gtest/gtest.h"
#include "mock.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {
envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy createConfig() {
  envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy config;
  auto* routes = config.mutable_routes();

  {
    auto* route = routes->Add();
    route->set_database("a");
    route->set_cluster("fake_clusterA");
  }
  {
    auto* route = routes->Add();
    route->set_database("b");
    route->set_cluster("fake_clusterB");
  }

  return config;
}

TEST(PrefixRoutesTest, BasicMatch) {
  auto config = createConfig();
  absl::flat_hash_map<std::string, RouteSharedPtr> routes;
  std::vector<std::string> clusters;
  Upstream::MockClusterManager cm;
  RouteSharedPtr primary_cluster_route;
  for (const auto& route : config.routes()) {
    if (primary_cluster_route == nullptr) {
      primary_cluster_route = std::make_shared<RouteImpl>(&cm, route.cluster());
    }

    clusters.emplace_back(route.cluster());
    auto route_ = std::make_shared<RouteImpl>(&cm, route.cluster());
    routes.emplace(route.database(), route_);
  }

  cm.initializeThreadLocalClusters(clusters);
  EXPECT_CALL(cm, getThreadLocalCluster).Times(3);
  RouterImpl router(primary_cluster_route, std::move(routes));
  EXPECT_EQ(nullptr, router.upstreamPool("c"));
  EXPECT_NE(nullptr, router.upstreamPool("b")->upstream());
  EXPECT_NE(nullptr, router.upstreamPool("a")->upstream());
  EXPECT_NE(nullptr, router.primaryPool()->upstream());

  EXPECT_EQ("fake_clusterB", router.upstreamPool("b")->name());
  EXPECT_EQ("fake_clusterA", router.upstreamPool("a")->name());
  EXPECT_EQ("fake_clusterA", router.primaryPool()->name());
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy