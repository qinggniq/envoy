#include <memory>

#include "envoy/buffer/buffer.h"
#include "envoy/common/exception.h"
#include "envoy/extensions/filters/network/mysql_proxy/v3/mysql_proxy.pb.h"

#include "common/buffer/buffer_impl.h"

#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_command.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_greeting.h"
#include "extensions/filters/network/mysql_proxy/mysql_config.h"
#include "extensions/filters/network/mysql_proxy/mysql_decoder.h"
#include "extensions/filters/network/mysql_proxy/mysql_filter.h"
#include "extensions/filters/network/mysql_proxy/mysql_session.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"

#include "extensions/filters/network/mysql_proxy/route.h"
#include "test/mocks/api/mocks.h"
#include "test/mocks/network/mocks.h"
#include "test/mocks/tcp/mocks.h"
#include "test/mocks/upstream/mocks.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "mock.h"
#include "mysql_test_utils.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

const std::string cluster_name = "cluster";

envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy
parseProtoFromYaml(const std::string& yaml_string) {
  envoy::extensions::filters::network::mysql_proxy::v3::MySQLProxy config;
  TestUtility::loadFromYaml(yaml_string, config);
  return config;
}

class MySQLFilterTest : public DecoderFactory, public testing::Test {
public:
  const std::string yaml_string = R"EOF(
  routes:
  - database: db
    cluster: cluster
  stat_prefix: foo
  )EOF";
  using MySQLFilterPtr = std::unique_ptr<MySQLFilter>;
  DecoderPtr create(DecoderCallbacks&) override {
    if (filter_ == nullptr) {
      return nullptr;
    }
    if (!filter_->downstream_decoder_) {
      return DecoderPtr{downstream_decoder_};
    }
    if (!filter_->upstream_decoder_) {
      return DecoderPtr{upstream_decoder_};
    }
    return nullptr;
  }
  MySQLFilterTest() {
    auto proto_config = parseProtoFromYaml(yaml_string);
    MySQLFilterConfigSharedPtr config =
        std::make_shared<MySQLFilterConfig>(store_, proto_config, api_);
    route_ = std::make_shared<MockRoute>(&cm_.thread_local_cluster_, cluster_name);
    router_ = std::make_shared<MockRouter>(route_);
    filter_ = std::make_unique<MySQLFilter>(config, router_, *this);

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, addConnectionCallbacks(*filter_->downstream_decoder_));
    filter_->initializeReadFilterCallbacks(read_callbacks_);
  }

  void connectionComeNoClusterInRoute() {
    auto router = std::make_shared<MockRouter>(nullptr);
    filter_->router_ = router;
    EXPECT_CALL(*router, primaryPool()).WillOnce(Return(nullptr));
    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
    EXPECT_EQ(filter_->config_->stats().sessions_.value(), 1);
  }
  void connectionComeNoCluster() {
    auto route = std::make_shared<MockRoute>(nullptr, cluster_name);
    auto router = std::make_shared<MockRouter>(route);

    EXPECT_CALL(cm_, getThreadLocalCluster(cluster_name))
        .WillOnce(
            Invoke([&](absl::string_view) -> Upstream::ThreadLocalCluster* { return nullptr; }));
    filter_->router_ = router;
    EXPECT_CALL(*router, primaryPool()).WillOnce(Return(route));
    EXPECT_CALL(*route, upstream()).WillOnce(Return(nullptr));

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
    EXPECT_EQ(filter_->config_->stats().sessions_.value(), 1);
  }

  void connectionComeNoHost() {
    auto route = std::make_shared<MockRoute>(&cm_.thread_local_cluster_, cluster_name);
    auto router = std::make_shared<MockRouter>(nullptr);
    filter_->router_ = router;
    EXPECT_CALL(*router, primaryPool()).WillOnce(Return(route));
    EXPECT_CALL(*route, upstream()).WillOnce(Return(nullptr));

    EXPECT_CALL(cm_, getThreadLocalCluster(cluster_name));

    EXPECT_CALL(cm_.thread_local_cluster_,
                tcpConnPool(Upstream::ResourcePriority::Default, nullptr))
        .WillOnce(Invoke([&](Upstream::ResourcePriority, Upstream::LoadBalancerContext*)
                             -> Tcp::ConnectionPool::Instance* { return nullptr; }));

    EXPECT_CALL(read_callbacks_, connection());
    EXPECT_CALL(read_callbacks_.connection_, close(Network::ConnectionCloseType::NoFlush));

    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
    EXPECT_EQ(filter_->config_->stats().sessions_.value(), 1);
  }

  void connectionOk() {
    auto route = std::make_shared<MockRoute>(&cm_.thread_local_cluster_, cluster_name);
    auto router = std::make_shared<MockRouter>(nullptr);
    filter_->router_ = router;
    EXPECT_CALL(*router, primaryPool()).WillOnce(Return(route));
    EXPECT_CALL(*route, upstream()).WillOnce(Return(nullptr));

    EXPECT_CALL(cm_, getThreadLocalCluster(cluster_name));

    EXPECT_CALL(cm_.thread_local_cluster_,
                tcpConnPool(Upstream::ResourcePriority::Default, nullptr));

    EXPECT_CALL(cm_.thread_local_cluster_.tcp_conn_pool_, newConnection(_));
    EXPECT_EQ(Network::FilterStatus::StopIteration, filter_->onNewConnection());
    EXPECT_EQ(filter_->config_->stats().sessions_.value(), 1);
  }
  MySQLSession downstream_session_;
  MySQLSession upstream_session_;
  MockDecoder* downstream_decoder_{new MockDecoder(downstream_session_)};
  MockDecoder* upstream_decoder_{new MockDecoder(upstream_session_)};
  Upstream::MockClusterManager cm_;
  Network::MockReadFilterCallbacks read_callbacks_;

  RouteSharedPtr route_;
  RouterSharedPtr router_;
  MySQLFilterPtr filter_;
  Stats::MockStore store_;
  Api::MockApi api_;
};

TEST_F(MySQLFilterTest, ConnectButNoClusterInRoute) { connectionComeNoClusterInRoute(); }

TEST_F(MySQLFilterTest, ConnectButNoCluster) { connectionComeNoCluster(); }

TEST_F(MySQLFilterTest, ConnectButNoHost) { connectionComeNoHost(); }

TEST_F(MySQLFilterTest, ConnectOk) { connectionOk(); }

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
