#include "envoy/upstream/thread_local_cluster.h"
#include "envoy/upstream/upstream.h"

#include "extensions/filters/network/mysql_proxy/mysql_decoder.h"
#include "extensions/filters/network/mysql_proxy/mysql_session.h"
#include "extensions/filters/network/mysql_proxy/route.h"

#include "gmock/gmock.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

class MockDecoder : public Decoder {
public:
  MockDecoder(const MySQLSession& session);
  ~MockDecoder() override = default;
  MOCK_METHOD(void, onData, (Buffer::Instance & data));
  MOCK_METHOD(MySQLSession&, getSession, ());
  MySQLSession session_;
};

class MockDecoderCallbacks : public DecoderCallbacks {
public:
  ~MockDecoderCallbacks() override = default;
  MOCK_METHOD(void, onProtocolError, ());
  MOCK_METHOD(void, onNewMessage, (MySQLSession::State));
  MOCK_METHOD(void, onServerGreeting, (ServerGreeting&));
  MOCK_METHOD(void, onClientLogin, (ClientLogin&));
  MOCK_METHOD(void, onClientLoginResponse, (ClientLoginResponse&));
  MOCK_METHOD(void, onClientSwitchResponse, (ClientSwitchResponse&));
  MOCK_METHOD(void, onMoreClientLoginResponse, (ClientLoginResponse&));
  MOCK_METHOD(void, onCommand, (Command&));
  MOCK_METHOD(void, onCommandResponse, (CommandResponse&));
};

class MockRouter : public Router {
public:
  MockRouter(RouteSharedPtr route);
  ~MockRouter() override = default;
  MOCK_METHOD(RouteSharedPtr, upstreamPool, (const std::string&));
  RouteSharedPtr route;
};

class MockRoute : public Route {
public:
  MockRoute(Upstream::ThreadLocalCluster* instance);
  ~MockRoute() override = default;
  MOCK_METHOD((Upstream::ThreadLocalCluster*), upstream, ());

  Upstream::ThreadLocalCluster* pool;
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy