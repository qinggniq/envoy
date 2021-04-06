#include "mock.h"

#include "extensions/filters/network/mysql_proxy/conn_pool.h"
#include "extensions/filters/network/mysql_proxy/route.h"

using testing::_;
using testing::Return;
using testing::ReturnRef;

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

MockRouter::MockRouter(RouteSharedPtr route) : route(route) {
  ON_CALL(*this, upstreamPool(_)).WillByDefault(Return(route));
}

MockRoute::MockRoute(ConnPool::ConnectionPoolManager* instance) : pool(instance) {
  ON_CALL(*this, upstream()).WillByDefault(ReturnRef(*pool));
}

MockDecoder::MockDecoder(const MySQLSession& session) : session_(session) {
  ON_CALL(*this, getSession()).WillByDefault([&]() -> MySQLSession& {
    std::cout << "call getSession()" << std::endl;
    return session_;
  });
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy