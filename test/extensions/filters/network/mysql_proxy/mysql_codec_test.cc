#include "common/buffer/buffer_impl.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_command.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_greeting.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include <bits/stdint-uintn.h>
#include "mysql_test_utils.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

constexpr int MYSQL_UT_RESP_OK = 0;
constexpr int MYSQL_UT_LAST_ID = 0;
constexpr int MYSQL_UT_SERVER_OK = 0;
constexpr int MYSQL_UT_SERVER_WARNINGS = 0x0001;

class MySQLCodecTest : public testing::Test {};

TEST_F(MySQLCodecTest, MySQLServerChallengeV9EncDec) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_9);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  std::string auth_plugin_data(MySQLTestUtils::getAuthPluginData8());
  mysql_greet_encode.setAuthPluginData(auth_plugin_data);
  Buffer::OwnedImpl data;
  mysql_greet_encode.encode(data);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(data, GREETING_SEQ_NUM, data.length());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData1(), mysql_greet_encode.getAuthPluginData1());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData2(), mysql_greet_encode.getAuthPluginData2());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getServerCap(), mysql_greet_encode.getServerCap());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), mysql_greet_encode.getExtServerCap());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginName(), mysql_greet_encode.getAuthPluginName());
}

/*
 * Test the MYSQL Greeting message V10 parser:
 * - message is encoded using the ServerGreeting class
 * - message is decoded using the ServerGreeting class
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeV10EncDec) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  std::string salt(MySQLTestUtils::getAuthPluginData20());
  mysql_greet_encode.setAuthPluginData(salt);
  mysql_greet_encode.setBaseServerCap(MYSQL_SERVER_CAPAB);
  mysql_greet_encode.setServerCharset(MYSQL_SERVER_LANGUAGE);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);
  mysql_greet_encode.setExtServerCap(MYSQL_SERVER_EXT_CAPAB);
  Buffer::OwnedImpl decode_data;
  mysql_greet_encode.encode(decode_data);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData1(), mysql_greet_encode.getAuthPluginData1());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData2(), mysql_greet_encode.getAuthPluginData2());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getServerCap(), mysql_greet_encode.getServerCap());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), mysql_greet_encode.getExtServerCap());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginName(), mysql_greet_encode.getAuthPluginName());
}

/*
 * Negative Testing: Server Greetings Incomplete
 * - incomplete protocol
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeIncompleteProtocol) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = 0;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), 0);
}

/*
 * Negative Testing: Server Greetings Incomplete
 * - incomplete version
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeIncompleteVersion) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  mysql_greet_encode.setVersion(MySQLTestUtils::getVersion());
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_greet_encode.getProtocol());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getVersion(), "");
}

/*
 * Negative Testing: Server Greetings Incomplete
 * - incomplete thread_id
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeIncompleteThreadId) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_greet_encode.getProtocol()) + ver.size() + 1;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), 0);
}

/*
 * Negative Testing: Server Greetings Incomplete
 * - incomplete auth_plugin_data
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeIncompleteSalt) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  mysql_greet_encode.setAuthPluginData(MySQLTestUtils::getAuthPluginData8());
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_greet_encode.getProtocol()) + ver.size() + 1;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), "");
}

/*
 * Negative Testing: Server Greetings Incomplete
 * - incomplete Server Capabilities
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeIncompleteServerCap) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  mysql_greet_encode.setAuthPluginData1(MySQLTestUtils::getAuthPluginData8());
  mysql_greet_encode.setBaseServerCap(MYSQL_SERVER_CAPAB);
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_greet_encode.getProtocol()) + ver.size() + 1 +
                       sizeof(mysql_greet_encode.getThreadId()) +
                       mysql_greet_encode.getAuthPluginData1().size() + 1;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), 0);
}

/*
 * Negative Testing: Server Greetings Incomplete
 * - incomplete Server Status
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeIncompleteServerStatus) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  mysql_greet_encode.setAuthPluginData1(MySQLTestUtils::getAuthPluginData8());
  mysql_greet_encode.setBaseServerCap(MYSQL_SERVER_CAPAB);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_greet_encode.getProtocol()) + ver.size() + 1 +
                       sizeof(mysql_greet_encode.getThreadId()) +
                       mysql_greet_encode.getAuthPluginData1().size() + 1 +
                       sizeof(mysql_greet_encode.getBaseServerCap());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), 0);
}

/*
 * Negative Testing: Server Greetings Incomplete
 * - incomplete extended Server Capabilities
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeIncompleteExtServerCap) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  mysql_greet_encode.setAuthPluginData1(MySQLTestUtils::getAuthPluginData8());
  mysql_greet_encode.setBaseServerCap(MYSQL_SERVER_CAPAB);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);
  mysql_greet_encode.setExtServerCap(MYSQL_SERVER_EXT_CAPAB);
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_greet_encode.getProtocol()) + ver.size() + 1 +
                       sizeof(mysql_greet_encode.getThreadId()) +
                       mysql_greet_encode.getAuthPluginData1().size() + 1 +
                       sizeof(mysql_greet_encode.getBaseServerCap()) +
                       sizeof(mysql_greet_encode.getServerStatus());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), 0);
}

/*
 * Testing: Server Greetings Protocol 10 Server Capabilities only
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeP10ServerCapOnly) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  mysql_greet_encode.setAuthPluginData1(MySQLTestUtils::getAuthPluginData8());
  mysql_greet_encode.setBaseServerCap(MYSQL_SERVER_CAPAB);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);
  mysql_greet_encode.setExtServerCap(MYSQL_SERVER_EXT_CAPAB);
  Buffer::OwnedImpl buffer;
  mysql_greet_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_greet_encode.getProtocol()) + ver.size() + 1 +
                       sizeof(mysql_greet_encode.getThreadId()) +
                       mysql_greet_encode.getAuthPluginData1().size() + 1 +
                       sizeof(mysql_greet_encode.getBaseServerCap()) +
                       sizeof(mysql_greet_encode.getServerStatus());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), 0);
}

/*
 * Testing: Server Greetings Protocol 10 Server Capabilities with auth plugin data flag
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeP10ServerCapAuthPlugin) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  std::string auth_plugin_data(MySQLTestUtils::getAuthPluginData20());
  mysql_greet_encode.setAuthPluginData(auth_plugin_data);
  mysql_greet_encode.setServerCap(MYSQL_SERVER_CAP_AUTH_PLUGIN);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);
  mysql_greet_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());

  Buffer::OwnedImpl decode_data;
  mysql_greet_encode.encode(decode_data);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData1(), mysql_greet_encode.getAuthPluginData1());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData2(), mysql_greet_encode.getAuthPluginData2());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getServerCap(), mysql_greet_encode.getServerCap());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), mysql_greet_encode.getExtServerCap());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginName(), mysql_greet_encode.getAuthPluginName());
}

/*
 * Testing: Server Greetings Protocol 10 Server Capabilities with auth plugin data flag incomplete
 * - incomplete of auth-plugin-data2
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeP10ServerAuthPluginInCompleteAuthData2) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  mysql_greet_encode.setVersion(MySQLTestUtils::getVersion());
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  mysql_greet_encode.setAuthPluginData1(MySQLTestUtils::getAuthPluginData8());
  mysql_greet_encode.setServerCap(MYSQL_SERVER_CAP_AUTH_PLUGIN);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);
  Buffer::OwnedImpl decode_data;
  mysql_greet_encode.encode(decode_data);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData1(), mysql_greet_encode.getAuthPluginData1());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData2(), mysql_greet_encode.getAuthPluginData2());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getServerCap(), mysql_greet_encode.getServerCap());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), mysql_greet_encode.getExtServerCap());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginName(), mysql_greet_encode.getAuthPluginName());
}

/*
 * Testing: Server Greetings Protocol 10 Server Capabilities with security connection flag
 * - incomplete length of auth-plugin-data2
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeP10ServerSecurityConnectionInCompleteData2) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  mysql_greet_encode.setAuthPluginData1(MySQLTestUtils::getAuthPluginData8());
  mysql_greet_encode.setServerCap(MYSQL_SERVER_SECURE_CONNECTION);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);
  Buffer::OwnedImpl decode_data;
  mysql_greet_encode.encode(decode_data);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());

  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData1(), mysql_greet_encode.getAuthPluginData1());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData2(), mysql_greet_encode.getAuthPluginData2());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getServerCap(), mysql_greet_encode.getServerCap());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), mysql_greet_encode.getExtServerCap());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginName(), mysql_greet_encode.getAuthPluginName());
}

/*
 * Testing: Server Greetings Protocol 10 Server Capabilities with security connection flag
 */
TEST_F(MySQLCodecTest, MySQLServerChallengeP10ServerCapSecurityConnection) {
  ServerGreeting mysql_greet_encode{};
  mysql_greet_encode.setProtocol(MYSQL_PROTOCOL_10);
  std::string ver(MySQLTestUtils::getVersion());
  mysql_greet_encode.setVersion(ver);
  mysql_greet_encode.setThreadId(MYSQL_THREAD_ID);
  std::string auth_plugin_data(MySQLTestUtils::getAuthPluginData20());
  mysql_greet_encode.setAuthPluginData(auth_plugin_data);
  mysql_greet_encode.setServerCap(MYSQL_SERVER_SECURE_CONNECTION);
  mysql_greet_encode.setServerStatus(MYSQL_SERVER_STATUS);

  Buffer::OwnedImpl decode_data;
  mysql_greet_encode.encode(decode_data);

  ServerGreeting mysql_greet_decode{};
  mysql_greet_decode.decode(decode_data, GREETING_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData(), mysql_greet_encode.getAuthPluginData());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData1(), mysql_greet_encode.getAuthPluginData1());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginData2(), mysql_greet_encode.getAuthPluginData2());
  EXPECT_EQ(mysql_greet_decode.getVersion(), mysql_greet_encode.getVersion());
  EXPECT_EQ(mysql_greet_decode.getProtocol(), mysql_greet_encode.getProtocol());
  EXPECT_EQ(mysql_greet_decode.getThreadId(), mysql_greet_encode.getThreadId());
  EXPECT_EQ(mysql_greet_decode.getServerStatus(), mysql_greet_encode.getServerStatus());
  EXPECT_EQ(mysql_greet_decode.getServerCap(), mysql_greet_encode.getServerCap());
  EXPECT_EQ(mysql_greet_decode.getBaseServerCap(), mysql_greet_encode.getBaseServerCap());
  EXPECT_EQ(mysql_greet_decode.getExtServerCap(), mysql_greet_encode.getExtServerCap());
  EXPECT_EQ(mysql_greet_decode.getAuthPluginName(), mysql_greet_encode.getAuthPluginName());
}

/*
 * Test the MYSQL Client Login 41 message parser:
 * - message is encoded using the ClientLogin class
 *   - CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA set
 * - message is decoded using the ClientLogin class
 */
TEST_F(MySQLCodecTest, MySQLClLoginV41PluginAuthEncDec) {
  ClientLogin mysql_clogin_encode{};
  uint32_t client_capab = 0;
  client_capab |= (CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION);
  mysql_clogin_encode.setClientCap(client_capab);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  std::string user("user1");
  mysql_clogin_encode.setUsername(user);
  mysql_clogin_encode.setAuthResp(MySQLTestUtils::getAuthResp8());
  std::string db = "mysql_db";
  mysql_clogin_encode.setDb(db);
  mysql_clogin_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());

  Buffer::OwnedImpl decode_data;
  mysql_clogin_encode.encode(decode_data);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.isResponse41(), true);
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getBaseClientCap(), mysql_clogin_encode.getBaseClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), mysql_clogin_encode.getAuthResp());
  EXPECT_EQ(mysql_clogin_decode.getDb(), mysql_clogin_encode.getDb());
  EXPECT_EQ(mysql_clogin_decode.getAuthPluginName(), mysql_clogin_encode.getAuthPluginName());
}

/*
 * Test the MYSQL Client Login 41 message parser:
 * - message is encoded using the ClientLogin class
 *   - CLIENT_SECURE_CONNECTION set
 * - message is decoded using the ClientLogin class
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41SecureConnEncDec) {
  ClientLogin mysql_clogin_encode{};
  uint32_t client_capab = 0;
  client_capab |= (CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION);
  mysql_clogin_encode.setClientCap(client_capab);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  std::string user("user1");
  mysql_clogin_encode.setUsername(user);
  mysql_clogin_encode.setAuthResp(MySQLTestUtils::getAuthResp8());
  std::string db = "mysql_db";
  mysql_clogin_encode.setDb(db);
  mysql_clogin_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());
  Buffer::OwnedImpl decode_data;
  mysql_clogin_encode.encode(decode_data);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.isResponse41(), true);
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getBaseClientCap(), mysql_clogin_encode.getBaseClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), mysql_clogin_encode.getAuthResp());
  EXPECT_EQ(mysql_clogin_decode.getDb(), mysql_clogin_encode.getDb());
  EXPECT_EQ(mysql_clogin_decode.getAuthPluginName(), mysql_clogin_encode.getAuthPluginName());
}

/*
 * Test the MYSQL Client Login 41 message parser:
 * - message is encoded using the ClientLogin class
 * - message is decoded using the ClientLogin class
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41EncDec) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  mysql_clogin_encode.setUsername("user");
  mysql_clogin_encode.setDb("mysql.db");
  mysql_clogin_encode.setAuthResp(MySQLTestUtils::getAuthResp8());
  mysql_clogin_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());

  Buffer::OwnedImpl decode_data;
  mysql_clogin_encode.encode(decode_data);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.isResponse41(), true);
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getBaseClientCap(), mysql_clogin_encode.getBaseClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), mysql_clogin_encode.getAuthResp());
  EXPECT_EQ(mysql_clogin_decode.getDb(), mysql_clogin_encode.getDb());
  EXPECT_EQ(mysql_clogin_decode.getAuthPluginName(), mysql_clogin_encode.getAuthPluginName());

  EXPECT_TRUE(mysql_clogin_decode.getAuthPluginName().empty());
  EXPECT_TRUE(mysql_clogin_decode.getDb().empty());
}

/*
 * Test the MYSQL Client Login 320 message parser:
 * - message is encoded using the ClientLogin class
 * - message is decoded using the ClientLogin class
 */
TEST_F(MySQLCodecTest, MySQLClientLogin320EncDec) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(0);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  mysql_clogin_encode.setUsername("user");
  mysql_clogin_encode.setDb("mysql.db");
  mysql_clogin_encode.setAuthResp(MySQLTestUtils::getAuthResp8());
  mysql_clogin_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());

  Buffer::OwnedImpl decode_data;
  mysql_clogin_encode.encode(decode_data);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.isResponse320(), true);
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getBaseClientCap(), mysql_clogin_encode.getBaseClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), mysql_clogin_encode.getAuthResp());
  EXPECT_EQ(mysql_clogin_decode.getDb(), mysql_clogin_encode.getDb());
  EXPECT_EQ(mysql_clogin_decode.getAuthPluginName(), mysql_clogin_encode.getAuthPluginName());

  EXPECT_TRUE(mysql_clogin_decode.getAuthPluginName().empty());
  EXPECT_TRUE(mysql_clogin_decode.getDb().empty());
}

TEST_F(MySQLCodecTest, MySQLParseLengthEncodedInteger) {
  {
    // encode 2 byte value
    Buffer::InstancePtr buffer(new Buffer::OwnedImpl());
    uint64_t input_val = 5;
    uint64_t output_val = 0;
    BufferHelper::addUint8(*buffer, LENENCODINT_2BYTES);
    BufferHelper::addUint16(*buffer, input_val);
    EXPECT_EQ(BufferHelper::readLengthEncodedInteger(*buffer, output_val), MYSQL_SUCCESS);
    EXPECT_EQ(input_val, output_val);
  }

  {
    // encode 3 byte value
    Buffer::InstancePtr buffer(new Buffer::OwnedImpl());
    uint64_t input_val = 5;
    uint64_t output_val = 0;
    BufferHelper::addUint8(*buffer, LENENCODINT_3BYTES);
    BufferHelper::addUint16(*buffer, input_val);
    BufferHelper::addUint8(*buffer, 0);
    EXPECT_EQ(BufferHelper::readLengthEncodedInteger(*buffer, output_val), MYSQL_SUCCESS);
    EXPECT_EQ(input_val, output_val);
  }

  {
    // encode 8 byte value
    Buffer::InstancePtr buffer(new Buffer::OwnedImpl());
    uint64_t input_val = 5;
    uint64_t output_val = 0;
    BufferHelper::addUint8(*buffer, LENENCODINT_8BYTES);
    BufferHelper::addUint32(*buffer, input_val);
    BufferHelper::addUint32(*buffer, 0);
    EXPECT_EQ(BufferHelper::readLengthEncodedInteger(*buffer, output_val), MYSQL_SUCCESS);
    EXPECT_EQ(input_val, output_val);
  }

  {
    // encode invalid length header
    Buffer::InstancePtr buffer(new Buffer::OwnedImpl());
    uint64_t input_val = 5;
    uint64_t output_val = 0;
    BufferHelper::addUint8(*buffer, 0xff);
    BufferHelper::addUint32(*buffer, input_val);
    EXPECT_EQ(BufferHelper::readLengthEncodedInteger(*buffer, output_val), MYSQL_FAILURE);
  }
  {
    // encode and decode length header
    uint64_t input_vals[4] = {
        5,
        251 + 5,
        (1 << 16) + 5,
        (1 << 24) + 5,
    };
    for (uint64_t& input_val : input_vals) {
      Buffer::OwnedImpl buffer;
      uint64_t output_val = 0;
      BufferHelper::addLengthEncodedInteger(buffer, input_val);
      BufferHelper::readLengthEncodedInteger(buffer, output_val);
      EXPECT_EQ(input_val, output_val);
    }
  }
  {
    // encode decode uint24
    Buffer::OwnedImpl buffer;
    uint32_t val = 0xfffefd;
    BufferHelper::addUint32(buffer, val);
    uint32_t res = 0;
    BufferHelper::readUint24(buffer, res);
    EXPECT_EQ(val, res);
  }
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at Client Capability
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteClientCap) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int client_cap_len = sizeof(uint8_t);
  Buffer::OwnedImpl decode_data(buffer.toString().data(), client_cap_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), 0);
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at Extended Client Capability
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteExtClientCap) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t);
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), 0);
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at Max Packet
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteMaxPacket) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  mysql_clogin_encode.setExtendedClientCap(MYSQL_EXT_CL_PLG_AUTH_CL_DATA);
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA);
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), 0);
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at Charset
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteCharset) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  mysql_clogin_encode.setExtendedClientCap(MYSQL_EXT_CL_PLG_AUTH_CL_DATA);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len =
      sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA) + sizeof(MYSQL_MAX_PACKET);
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), 0);
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at Unset bytes
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteUnsetBytes) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  mysql_clogin_encode.setExtendedClientCap(MYSQL_EXT_CL_PLG_AUTH_CL_DATA);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  mysql_clogin_encode.setUsername("user1");

  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA) +
                       sizeof(MYSQL_MAX_PACKET) + sizeof(MYSQL_CHARSET);
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at username
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteUser) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  mysql_clogin_encode.setExtendedClientCap(MYSQL_EXT_CL_PLG_AUTH_CL_DATA);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  mysql_clogin_encode.setUsername("user1");

  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA) +
                       sizeof(MYSQL_MAX_PACKET) + sizeof(MYSQL_CHARSET) + UNSET_BYTES;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), "");
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at authlen
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteAuthLen) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  mysql_clogin_encode.setExtendedClientCap(MYSQL_EXT_CL_PLG_AUTH_CL_DATA);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  std::string user("user1");
  mysql_clogin_encode.setUsername(user);
  mysql_clogin_encode.setAuthResp(MySQLTestUtils::getAuthResp8());

  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA) +
                       sizeof(MYSQL_MAX_PACKET) + sizeof(MYSQL_CHARSET) + UNSET_BYTES +
                       user.length() + 1;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), "");
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at "authpasswd"
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteAuthPasswd) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41);
  mysql_clogin_encode.setExtendedClientCap(MYSQL_EXT_CL_PLG_AUTH_CL_DATA);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  std::string user("user1");
  mysql_clogin_encode.setUsername(user);
  std::string passwd = MySQLTestUtils::getAuthPluginData8();
  mysql_clogin_encode.setAuthResp(passwd);

  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA) +
                       sizeof(MYSQL_MAX_PACKET) + sizeof(MYSQL_CHARSET) + UNSET_BYTES +
                       user.length() + 3;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  ;
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), "");
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at "db name"
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteDbName) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41 | CLIENT_CONNECT_WITH_DB);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  std::string user("user1");
  mysql_clogin_encode.setUsername(user);
  std::string passwd = MySQLTestUtils::getAuthPluginData8();
  mysql_clogin_encode.setAuthResp(passwd);
  std::string db = "mysql.db";
  mysql_clogin_encode.setDb(db);
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA) +
                       sizeof(MYSQL_MAX_PACKET) + sizeof(MYSQL_CHARSET) + UNSET_BYTES +
                       user.length() + 1 + passwd.size() + 1;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), mysql_clogin_encode.getAuthResp());
  EXPECT_EQ(mysql_clogin_decode.getDb(), "");
}

/*
 * Negative Test the MYSQL Client Login 41 message parser:
 * Incomplete header at "auth plugin name"
 */
TEST_F(MySQLCodecTest, MySQLClientLogin41IncompleteAuthPluginName) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_PROTOCOL_41 | CLIENT_CONNECT_WITH_DB |
                                   CLIENT_PLUGIN_AUTH);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  std::string user("user1");
  mysql_clogin_encode.setUsername(user);
  std::string passwd = MySQLTestUtils::getAuthPluginData8();
  mysql_clogin_encode.setAuthResp(passwd);
  std::string db = "mysql.db";
  mysql_clogin_encode.setDb(db);
  mysql_clogin_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(MYSQL_EXT_CL_PLG_AUTH_CL_DATA) +
                       sizeof(MYSQL_MAX_PACKET) + sizeof(MYSQL_CHARSET) + UNSET_BYTES +
                       user.length() + 1 + passwd.size() + 1 + db.size() + 1;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getExtendedClientCap(), mysql_clogin_encode.getExtendedClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getCharset(), mysql_clogin_encode.getCharset());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), mysql_clogin_encode.getUsername());
  EXPECT_EQ(mysql_clogin_decode.getAuthResp(), mysql_clogin_encode.getAuthResp());
  EXPECT_EQ(mysql_clogin_decode.getDb(), mysql_clogin_encode.getDb());
  EXPECT_EQ(mysql_clogin_decode.getAuthPluginName(), "");
}

/*
 * Negative Test the MYSQL Client 320 login message parser:
 * Incomplete header at cap
 */
TEST_F(MySQLCodecTest, MySQLClient320LoginIncompleteClientCap) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(CLIENT_CONNECT_WITH_DB);
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = 0;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), 0);
}

/*
 * Negative Test the MYSQL Client 320 login message parser:
 * Incomplete auth len
 */
TEST_F(MySQLCodecTest, MySQLClientLogin320IncompleteMaxPacketSize) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(0);
  mysql_clogin_encode.setExtendedClientCap(0);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t);
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), 0);
}

/*
 * Negative Test the MYSQL Client login 320 message parser:
 * Incomplete username
 */
TEST_F(MySQLCodecTest, MySQLClientLogin320IncompleteUsername) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(0);
  mysql_clogin_encode.setExtendedClientCap(0);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setUsername("user");
  Buffer::OwnedImpl buffer;
  mysql_clogin_encode.encode(buffer);

  int incomplete_len = sizeof(uint16_t) + sizeof(uint16_t) + sizeof(uint8_t);
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
  EXPECT_EQ(mysql_clogin_decode.getUsername(), "");
}

/*
 * Test the MYSQL Client Login SSL message parser:
 * - message is encoded using the ClientLogin class
 * - message is decoded using the ClientLogin class
 */
TEST_F(MySQLCodecTest, MySQLClientLoginSSLEncDec) {
  ClientLogin mysql_clogin_encode{};
  mysql_clogin_encode.setClientCap(MYSQL_CLIENT_CAPAB_SSL | CLIENT_PROTOCOL_41 |
                                   CLIENT_PLUGIN_AUTH);
  mysql_clogin_encode.setMaxPacket(MYSQL_MAX_PACKET);
  mysql_clogin_encode.setCharset(MYSQL_CHARSET);
  Buffer::OwnedImpl decode_data;
  mysql_clogin_encode.encode(decode_data);

  ClientLogin mysql_clogin_decode{};
  mysql_clogin_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_clogin_decode.isSSLRequest(), true);
  EXPECT_EQ(mysql_clogin_decode.getClientCap(), mysql_clogin_encode.getClientCap());
  EXPECT_EQ(mysql_clogin_decode.getMaxPacket(), mysql_clogin_encode.getMaxPacket());
}

/*
 * Test the MYSQL Server Login Response OK message parser:
 * - message is encoded using the ClientLoginResponse class
 * - message is decoded using the ClientLoginResponse class
 */
TEST_F(MySQLCodecTest, MySQLLoginOkEncDec) {
  ClientLoginResponse mysql_loginok_encode{};
  mysql_loginok_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginok_encode.setAffectedRows(1);
  mysql_loginok_encode.setLastInsertId(MYSQL_UT_LAST_ID);
  mysql_loginok_encode.setServerStatus(MYSQL_UT_SERVER_OK);
  mysql_loginok_encode.setWarnings(MYSQL_UT_SERVER_WARNINGS);
  Buffer::OwnedImpl decode_data;
  mysql_loginok_encode.encode(decode_data);

  ClientLoginResponse mysql_loginok_decode{};
  mysql_loginok_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginok_decode.getRespCode(), mysql_loginok_encode.getRespCode());
  EXPECT_EQ(mysql_loginok_decode.getAffectedRows(), mysql_loginok_encode.getAffectedRows());
  EXPECT_EQ(mysql_loginok_decode.getLastInsertId(), mysql_loginok_encode.getLastInsertId());
  EXPECT_EQ(mysql_loginok_decode.getServerStatus(), mysql_loginok_encode.getServerStatus());
  EXPECT_EQ(mysql_loginok_decode.getWarnings(), mysql_loginok_encode.getWarnings());
}

/*
 * Test the MYSQL Server Login Response Err message parser:
 * - message is encoded using the ClientLoginResponse class
 * - message is decoded using the ClientLoginResponse class
 */
TEST_F(MySQLCodecTest, MySQLLoginErrEncDec) {
  ClientLoginResponse mysql_loginerr_encode{};
  mysql_loginerr_encode.setRespCode(MYSQL_RESP_ERR);
  mysql_loginerr_encode.setErrorCode(MYSQL_ERROR_CODE);
  mysql_loginerr_encode.setSqlStateMarker('#');
  mysql_loginerr_encode.setSqlState(MySQLTestUtils::getSqlState());
  mysql_loginerr_encode.setErrorMessage(MySQLTestUtils::getErrorMessage());
  Buffer::OwnedImpl decode_data;
  mysql_loginerr_encode.encode(decode_data);

  ClientLoginResponse mysql_loginok_decode{};
  mysql_loginok_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginok_decode.getRespCode(), mysql_loginerr_encode.getRespCode());
  EXPECT_EQ(mysql_loginok_decode.getErrorCode(), mysql_loginerr_encode.getErrorCode());
  EXPECT_EQ(mysql_loginok_decode.getSqlStateMarker(), mysql_loginerr_encode.getSqlStateMarker());
  EXPECT_EQ(mysql_loginok_decode.getSqlState(), mysql_loginerr_encode.getSqlState());
  EXPECT_EQ(mysql_loginok_decode.getErrorMessage(), mysql_loginerr_encode.getErrorMessage());
}

/*
 * Test the MYSQL Server Login Old Auth Switch message parser:
 * - message is encoded using the ClientLoginResponse class
 * - message is decoded using the ClientLoginResponse class
 */
TEST_F(MySQLCodecTest, MySQLLoginOldAuthSwitch) {
  ClientLoginResponse mysql_old_auth_switch_encode{};
  mysql_old_auth_switch_encode.setRespCode(MYSQL_RESP_AUTH_SWITCH);
  Buffer::OwnedImpl decode_data;
  mysql_old_auth_switch_encode.encode(decode_data);

  ClientLoginResponse mysql_old_auth_switch_decode{};
  mysql_old_auth_switch_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_old_auth_switch_decode.getRespCode(), mysql_old_auth_switch_encode.getRespCode());
}

/*
 * Test the MYSQL Server Login Auth Switch message parser:
 * - message is encoded using the ClientLoginResponse class
 * - message is decoded using the ClientLoginResponse class
 */
TEST_F(MySQLCodecTest, MySQLLoginAuthSwitch) {
  ClientLoginResponse mysql_auth_switch_encode{};
  mysql_auth_switch_encode.setRespCode(MYSQL_RESP_AUTH_SWITCH);
  mysql_auth_switch_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());
  mysql_auth_switch_encode.setAuthPluginData(MySQLTestUtils::getAuthPluginData20());
  Buffer::OwnedImpl decode_data;
  mysql_auth_switch_encode.encode(decode_data);

  ClientLoginResponse mysql_auth_switch_decode{};
  mysql_auth_switch_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_auth_switch_decode.getRespCode(), mysql_auth_switch_encode.getRespCode());
  EXPECT_EQ(mysql_auth_switch_decode.getAuthPluginName(),
            mysql_auth_switch_encode.getAuthPluginName());
  EXPECT_EQ(mysql_auth_switch_decode.getAuthPluginData(),
            mysql_auth_switch_encode.getAuthPluginData());
  EXPECT_EQ(mysql_auth_switch_decode.getAuthPluginData(), MySQLTestUtils::getAuthPluginData20());
  EXPECT_EQ(mysql_auth_switch_decode.getAuthPluginName(), MySQLTestUtils::getAuthPluginName());
}

/*
 * Test the MYSQL Server Login Auth More message parser:
 * - message is encoded using the ClientLoginResponse class
 * - message is decoded using the ClientLoginResponse class
 */
TEST_F(MySQLCodecTest, MySQLLoginAuthMore) {
  ClientLoginResponse mysql_auth_more_encode{};
  mysql_auth_more_encode.setRespCode(MYSQL_RESP_MORE);
  mysql_auth_more_encode.setAuthMoreData(MySQLTestUtils::getAuthPluginData20());
  Buffer::OwnedImpl decode_data;
  mysql_auth_more_encode.encode(decode_data);

  ClientLoginResponse mysql_auth_more_decode{};
  mysql_auth_more_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_auth_more_decode.getRespCode(), mysql_auth_more_encode.getRespCode());
  EXPECT_EQ(mysql_auth_more_decode.getAuthMoreData(), mysql_auth_more_encode.getAuthMoreData());
}

/*
 * Negative Test the MYSQL Server Login OK message parser:
 * - incomplete response code
 */
TEST_F(MySQLCodecTest, MySQLLoginOkIncompleteRespCode) {
  ClientLoginResponse mysql_loginok_encode{};
  mysql_loginok_encode.setRespCode(MYSQL_UT_RESP_OK);
  Buffer::OwnedImpl decode_data;

  ClientLoginResponse mysql_loginok_decode{};
  mysql_loginok_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginok_decode.getRespCode(), 0);
}

/*
 * Negative Test the MYSQL Server Login OK message parser:
 * - incomplete affected rows
 */
TEST_F(MySQLCodecTest, MySQLLoginOkIncompleteAffectedRows) {
  ClientLoginResponse mysql_loginok_encode{};
  mysql_loginok_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginok_encode.setAffectedRows(1);
  Buffer::OwnedImpl buffer;
  mysql_loginok_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_loginok_encode.getRespCode());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginok_decode{};
  mysql_loginok_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginok_decode.getRespCode(), mysql_loginok_encode.getRespCode());
}

/*
 * Negative Test the MYSQL Server Login OK message parser:
 * - incomplete Client Login OK last insert id
 */
TEST_F(MySQLCodecTest, MySQLLoginOkIncompleteLastInsertId) {
  ClientLoginResponse mysql_loginok_encode{};
  mysql_loginok_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginok_encode.setAffectedRows(1);
  mysql_loginok_encode.setLastInsertId(MYSQL_UT_LAST_ID);
  Buffer::OwnedImpl buffer;
  mysql_loginok_encode.encode(buffer);

  int incomplete_len =
      sizeof(mysql_loginok_encode.getRespCode()) + sizeof(mysql_loginok_encode.getAffectedRows());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginok_decode{};
  mysql_loginok_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginok_decode.getRespCode(), mysql_loginok_encode.getRespCode());
  EXPECT_EQ(mysql_loginok_decode.getAffectedRows(), mysql_loginok_encode.getAffectedRows());
}

/*
 * Negative Test the MYSQL Server Login OK message parser:
 * - incomplete server status
 */
TEST_F(MySQLCodecTest, MySQLLoginOkIncompleteServerStatus) {
  ClientLoginResponse mysql_loginok_encode{};
  mysql_loginok_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginok_encode.setAffectedRows(1);
  mysql_loginok_encode.setLastInsertId(MYSQL_UT_LAST_ID);
  mysql_loginok_encode.setServerStatus(MYSQL_UT_SERVER_OK);
  Buffer::OwnedImpl buffer;
  mysql_loginok_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_loginok_encode.getRespCode()) +
                       sizeof(mysql_loginok_encode.getAffectedRows()) +
                       sizeof(mysql_loginok_encode.getLastInsertId());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginok_decode{};
  mysql_loginok_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginok_decode.getRespCode(), mysql_loginok_encode.getRespCode());
  EXPECT_EQ(mysql_loginok_decode.getAffectedRows(), mysql_loginok_encode.getAffectedRows());
  EXPECT_EQ(mysql_loginok_decode.getLastInsertId(), mysql_loginok_encode.getLastInsertId());
  EXPECT_EQ(mysql_loginok_decode.getServerStatus(), 0);
}

/*
 * Negative Test the MYSQL Server Login OK message parser:
 * - incomplete warnings
 */
TEST_F(MySQLCodecTest, MySQLLoginOkIncompleteWarnings) {
  ClientLoginResponse mysql_loginok_encode{};
  mysql_loginok_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginok_encode.setAffectedRows(1);
  mysql_loginok_encode.setLastInsertId(MYSQL_UT_LAST_ID);
  mysql_loginok_encode.setServerStatus(MYSQL_UT_SERVER_OK);
  mysql_loginok_encode.setWarnings(MYSQL_UT_SERVER_WARNINGS);
  Buffer::OwnedImpl buffer;
  mysql_loginok_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_loginok_encode.getRespCode()) +
                       sizeof(mysql_loginok_encode.getAffectedRows()) +
                       sizeof(mysql_loginok_encode.getLastInsertId()) +
                       sizeof(mysql_loginok_encode.getServerStatus());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginok_decode{};
  mysql_loginok_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginok_decode.getRespCode(), mysql_loginok_encode.getRespCode());
  EXPECT_EQ(mysql_loginok_decode.getAffectedRows(), mysql_loginok_encode.getAffectedRows());
  EXPECT_EQ(mysql_loginok_decode.getLastInsertId(), mysql_loginok_encode.getLastInsertId());
  EXPECT_EQ(mysql_loginok_decode.getServerStatus(), mysql_loginok_encode.getServerStatus());
  EXPECT_EQ(mysql_loginok_decode.getWarnings(), 0);
}

/*
 * Negative Test the MYSQL Server Login Err message parser:
 * - incomplete response code
 */
TEST_F(MySQLCodecTest, MySQLLoginErrIncompleteRespCode) {
  ClientLoginResponse mysql_loginerr_encode{};
  mysql_loginerr_encode.setRespCode(MYSQL_RESP_ERR);
  Buffer::OwnedImpl decode_data;

  ClientLoginResponse mysql_loginerr_decode{};
  mysql_loginerr_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginerr_decode.getRespCode(), 0);
}

/*
 * Negative Test the MYSQL Server Login ERR message parser:
 * - incomplete error code
 */
TEST_F(MySQLCodecTest, MySQLLoginErrIncompleteErrorcode) {
  ClientLoginResponse mysql_loginerr_encode{};
  mysql_loginerr_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginerr_encode.setErrorCode(MYSQL_ERROR_CODE);
  Buffer::OwnedImpl buffer;
  mysql_loginerr_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_loginerr_encode.getRespCode());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginerr_decode{};
  mysql_loginerr_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginerr_decode.getRespCode(), mysql_loginerr_encode.getRespCode());
  EXPECT_EQ(mysql_loginerr_decode.getErrorCode(), 0);
}

/*
 * Negative Test the MYSQL Server Login ERR message parser:
 * - incomplete sql state marker
 */
TEST_F(MySQLCodecTest, MySQLLoginErrIncompleteStateMarker) {
  ClientLoginResponse mysql_loginerr_encode{};
  mysql_loginerr_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginerr_encode.setErrorCode(MYSQL_ERROR_CODE);
  mysql_loginerr_encode.setSqlStateMarker('#');
  Buffer::OwnedImpl buffer;
  mysql_loginerr_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_loginerr_encode.getRespCode()) +
                       sizeof(mysql_loginerr_encode.getSqlStateMarker());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginerr_decode{};
  mysql_loginerr_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginerr_decode.getRespCode(), mysql_loginerr_encode.getRespCode());
  EXPECT_EQ(mysql_loginerr_decode.getErrorCode(), mysql_loginerr_encode.getErrorCode());
  EXPECT_EQ(mysql_loginerr_decode.getSqlStateMarker(), 0);
}

/*
 * Negative Test the MYSQL Server Login ERR message parser:
 * - incomplete sql state
 */
TEST_F(MySQLCodecTest, MySQLLoginErrIncompleteSqlState) {
  ClientLoginResponse mysql_loginerr_encode{};
  mysql_loginerr_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginerr_encode.setErrorCode(MYSQL_ERROR_CODE);
  mysql_loginerr_encode.setSqlStateMarker('#');
  mysql_loginerr_encode.setSqlState(MySQLTestUtils::getSqlState());
  Buffer::OwnedImpl buffer;
  mysql_loginerr_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_loginerr_encode.getRespCode()) +
                       sizeof(mysql_loginerr_encode.getSqlStateMarker()) +
                       sizeof(mysql_loginerr_encode.getSqlStateMarker());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginerr_decode{};
  mysql_loginerr_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginerr_decode.getRespCode(), mysql_loginerr_encode.getRespCode());
  EXPECT_EQ(mysql_loginerr_decode.getErrorCode(), mysql_loginerr_encode.getErrorCode());
  EXPECT_EQ(mysql_loginerr_decode.getSqlStateMarker(), mysql_loginerr_encode.getSqlStateMarker());
  EXPECT_EQ(mysql_loginerr_decode.getSqlState(), "");
}

/*
 * Negative Test the MYSQL Server Login ERR message parser:
 * - incomplete error message
 */
TEST_F(MySQLCodecTest, MySQLLoginErrIncompleteErrorMessage) {
  ClientLoginResponse mysql_loginerr_encode{};
  mysql_loginerr_encode.setRespCode(MYSQL_UT_RESP_OK);
  mysql_loginerr_encode.setErrorCode(MYSQL_ERROR_CODE);
  mysql_loginerr_encode.setSqlStateMarker('#');
  mysql_loginerr_encode.setSqlState(MySQLTestUtils::getSqlState());
  Buffer::OwnedImpl buffer;
  mysql_loginerr_encode.setErrorMessage(MySQLTestUtils::getErrorMessage());
  mysql_loginerr_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_loginerr_encode.getRespCode()) +
                       sizeof(mysql_loginerr_encode.getSqlStateMarker()) +
                       sizeof(mysql_loginerr_encode.getSqlStateMarker()) +
                       mysql_loginerr_encode.getSqlState().size();
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_loginerr_decode{};
  mysql_loginerr_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_loginerr_decode.getRespCode(), mysql_loginerr_encode.getRespCode());
  EXPECT_EQ(mysql_loginerr_decode.getErrorCode(), mysql_loginerr_encode.getErrorCode());
  EXPECT_EQ(mysql_loginerr_decode.getSqlStateMarker(), mysql_loginerr_encode.getSqlStateMarker());
  EXPECT_EQ(mysql_loginerr_decode.getSqlState(), mysql_loginerr_encode.getSqlState());
  EXPECT_EQ(mysql_loginerr_decode.getErrorMessage(), "");
}

/*
 * Negative Test the MYSQL Server Login Auth Switch message parser:
 * - incomplete response code
 */
TEST_F(MySQLCodecTest, MySQLLoginAuthSwitchIncompleteRespCode) {
  ClientLoginResponse mysql_login_auth_switch_encode{};
  mysql_login_auth_switch_encode.setRespCode(MYSQL_RESP_AUTH_SWITCH);
  Buffer::OwnedImpl decode_data;

  ClientLoginResponse mysql_login_auth_switch_decode{};
  mysql_login_auth_switch_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_login_auth_switch_decode.getRespCode(), 0);
}

/*
 * Negative Test the MYSQL Server Login ERR message parser:
 * - incomplete auth plugin name
 */
TEST_F(MySQLCodecTest, MySQLLoginAuthSwitchIncompletePluginName) {
  ClientLoginResponse mysql_login_auth_switch_encode{};
  mysql_login_auth_switch_encode.setRespCode(MYSQL_RESP_AUTH_SWITCH);
  mysql_login_auth_switch_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());
  Buffer::OwnedImpl buffer;
  mysql_login_auth_switch_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_login_auth_switch_encode.getRespCode());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_login_auth_switch_decode{};
  mysql_login_auth_switch_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_login_auth_switch_decode.getRespCode(),
            mysql_login_auth_switch_encode.getRespCode());
  EXPECT_EQ(mysql_login_auth_switch_decode.getAuthPluginName(), "");
}

/*
 * Negative Test the MYSQL Server Login Auth Switch message parser:
 * - incomplete auth plugin data
 */
TEST_F(MySQLCodecTest, MySQLLoginAuthSwitchIncompletePluginData) {
  ClientLoginResponse mysql_login_auth_switch_encode{};
  mysql_login_auth_switch_encode.setRespCode(MYSQL_RESP_AUTH_SWITCH);
  mysql_login_auth_switch_encode.setAuthPluginName(MySQLTestUtils::getAuthPluginName());
  mysql_login_auth_switch_encode.setAuthPluginData(MySQLTestUtils::getAuthPluginData20());
  Buffer::OwnedImpl buffer;
  mysql_login_auth_switch_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_login_auth_switch_encode.getRespCode()) +
                       mysql_login_auth_switch_encode.getAuthPluginName().size() + 1;
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_login_auth_switch_decode{};
  mysql_login_auth_switch_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_login_auth_switch_decode.getRespCode(),
            mysql_login_auth_switch_encode.getRespCode());
  EXPECT_EQ(mysql_login_auth_switch_decode.getAuthPluginName(),
            mysql_login_auth_switch_encode.getAuthPluginName());
  EXPECT_EQ(mysql_login_auth_switch_decode.getAuthPluginData(), "");
}

/*
 * Negative Test the MYSQL Server Auth More message parser:
 * - incomplete response code
 */
TEST_F(MySQLCodecTest, MySQLLoginAuthMoreIncompleteRespCode) {
  ClientLoginResponse mysql_login_auth_more_encode{};
  mysql_login_auth_more_encode.setRespCode(MYSQL_RESP_MORE);
  Buffer::OwnedImpl decode_data;

  ClientLoginResponse mysql_login_auth_more_decode{};
  mysql_login_auth_more_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_login_auth_more_decode.getRespCode(), 0);
}

/*
 * Negative Test the MYSQL Server Auth More message parser:
 * - incomplete auth plugin name
 */
TEST_F(MySQLCodecTest, MySQLLoginAuthMoreIncompletePluginData) {
  ClientLoginResponse mysql_login_auth_more_encode{};
  mysql_login_auth_more_encode.setRespCode(MYSQL_RESP_AUTH_SWITCH);
  mysql_login_auth_more_encode.setAuthMoreData(MySQLTestUtils::getAuthPluginData20());
  Buffer::OwnedImpl buffer;
  mysql_login_auth_more_encode.encode(buffer);

  int incomplete_len = sizeof(mysql_login_auth_more_encode.getRespCode());
  Buffer::OwnedImpl decode_data(buffer.toString().data(), incomplete_len);

  ClientLoginResponse mysql_login_auth_more_decode{};
  mysql_login_auth_more_decode.decode(decode_data, CHALLENGE_SEQ_NUM, decode_data.length());
  EXPECT_EQ(mysql_login_auth_more_decode.getRespCode(), mysql_login_auth_more_encode.getRespCode());
  EXPECT_EQ(mysql_login_auth_more_decode.getAuthMoreData(), "");
}

TEST_F(MySQLCodecTest, MySQLCommandError) {
  Buffer::InstancePtr decode_data(new Buffer::OwnedImpl(""));
  Command mysql_cmd_decode{};
  decode_data->drain(4);
  mysql_cmd_decode.decode(*decode_data, 0, 0);
  EXPECT_EQ(mysql_cmd_decode.getCmd(), Command::Cmd::Null);
}

TEST_F(MySQLCodecTest, MySQLCommandInitDb) {
  Command mysql_cmd_encode{};
  mysql_cmd_encode.setCmd(Command::Cmd::InitDb);
  std::string db = "mysqlDB";
  mysql_cmd_encode.setData(db);
  Buffer::OwnedImpl decode_data;
  mysql_cmd_encode.encode(decode_data);

  BufferHelper::encodeHdr(decode_data, 0);

  Command mysql_cmd_decode{};
  decode_data.drain(4);
  mysql_cmd_decode.decode(decode_data, 0, db.length() + 1);
  EXPECT_EQ(mysql_cmd_decode.getDb(), db);
}

TEST_F(MySQLCodecTest, MySQLCommandCreateDb) {
  Command mysql_cmd_encode{};
  mysql_cmd_encode.setCmd(Command::Cmd::CreateDb);
  std::string db = "mysqlDB";
  mysql_cmd_encode.setData(db);
  Buffer::OwnedImpl decode_data;
  mysql_cmd_encode.encode(decode_data);

  BufferHelper::encodeHdr(decode_data, 0);

  Command mysql_cmd_decode{};
  decode_data.drain(4);
  mysql_cmd_decode.decode(decode_data, 0, db.length() + 1);
  EXPECT_EQ(mysql_cmd_decode.getDb(), db);
}

TEST_F(MySQLCodecTest, MySQLCommandDropDb) {
  Command mysql_cmd_encode{};
  mysql_cmd_encode.setCmd(Command::Cmd::DropDb);
  std::string db = "mysqlDB";
  mysql_cmd_encode.setData(db);
  Buffer::OwnedImpl decode_data;
  mysql_cmd_encode.encode(decode_data);

  BufferHelper::encodeHdr(decode_data, 0);

  Command mysql_cmd_decode{};
  decode_data.drain(4);
  mysql_cmd_decode.decode(decode_data, 0, db.length() + 1);
  EXPECT_EQ(mysql_cmd_decode.getDb(), db);
}

TEST_F(MySQLCodecTest, MySQLCommandOther) {
  Command mysql_cmd_encode{};
  mysql_cmd_encode.setCmd(Command::Cmd::FieldList);
  Buffer::OwnedImpl decode_data;
  mysql_cmd_encode.encode(decode_data);

  BufferHelper::encodeHdr(decode_data, 0);

  Command mysql_cmd_decode{};
  decode_data.drain(4);
  mysql_cmd_decode.decode(decode_data, 0, 0);
  EXPECT_EQ(mysql_cmd_decode.getCmd(), Command::Cmd::FieldList);
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
