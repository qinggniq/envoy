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

class MySQLFilterTest : public DecoderFactory {
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
    route_ = std::make_shared<MockRoute>(&cm_.thread_local_cluster, cluster_name);
    // router_ = std::make_shared<MockRouter>(route_);

    filter_ = std::make_unique<MySQLFilter>(config, )
  }
  MySQLSession downstream_session_;
  MySQLSession upstream_session_;
  MockDecoder* downstream_decoder_{new MockDecoder(downstream_session_)};
  MockDecoder* upstream_decoder_{new MockDecoder(upstream_session_)};
  Upstream::MockClusterManager cm_;
  RouteSharedPtr route_;
  RouterSharedPtr router_;
  MySQLFilterPtr filter_;
  Stats::MockStore store_;
  Api::MockApi api_;
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
