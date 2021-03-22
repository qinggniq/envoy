#include "extensions/filters/network/mysql_proxy/message_helper.h"

#include "extensions/filters/network/mysql_proxy/mysql_codec_command.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

Buffer::OwnedImpl MessageHelper::encodePacket(const MySQLCodec& codec, uint8_t seq) {
  Buffer::OwnedImpl buffer;
  codec.encode(buffer);
  BufferHelper::encodeHdr(buffer, seq);
  return buffer;
}

ClientLogin MessageHelper::encodeClientLogin(AuthMethod auth_method, const std::string& username,
                                             const std::string& password, const std::string& db,
                                             const std::vector<uint8_t>& seed) {
  ClientLogin client_login{};
  client_login.setClientCap(CLIENT_SECURE_CONNECTION | CLIENT_LONG_PASSWORD | CLIENT_TRANSACTIONS |
                            CLIENT_MULTI_STATEMENTS | CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA |
                            CLIENT_CONNECT_WITH_DB);
  client_login.setMaxPacket(0);
  client_login.setUsername(username);
  if (auth_method == AuthMethod::OldPassword) {
    client_login.setAuthResp(AuthHelper::oldPasswordSignature(
        password, std::vector<uint8_t>(seed.data(), seed.data() + 8)));
  } else {
    client_login.setClientCap(client_login.getClientCap() | CLIENT_PROTOCOL_41);
    client_login.setAuthResp(AuthHelper::nativePasswordSignature(
        password, std::vector<uint8_t>(seed.data(), seed.data() + 20)));
    client_login.setClientCap(client_login.getClientCap() | CLIENT_PLUGIN_AUTH);
    client_login.setAuthPluginName("mysql_native_password");
  }
  client_login.setDb(db);
  client_login.setCharset(DEFAULT_MYSQL_CHARSET);
  return client_login;
}

ClientLogin MessageHelper::encodeSslUpgrade() {
  ClientLogin client_login{};
  client_login.setClientCap(CLIENT_SSL);
  client_login.setMaxPacket(0);
  client_login.setCharset(DEFAULT_MYSQL_CHARSET);
  return client_login;
}

ServerGreeting MessageHelper::encodeGreeting(const std::vector<uint8_t>& seed,
                                             const std::string& auth_plugin_name) {
  ServerGreeting greet{};
  greet.setProtocol(MYSQL_PROTOCOL_10);
  greet.setVersion("5.7.6");
  greet.setAuthPluginData(seed);
  greet.setThreadId(10);
  greet.setServerCharset(DEFAULT_MYSQL_CHARSET);
  greet.setServerStatus(DEFALUT_MYSQL_SERVER_STATUS);
  greet.setServerCap(CLIENT_LONG_PASSWORD | CLIENT_LONG_FLAG | CLIENT_CONNECT_WITH_DB |
                     CLIENT_PROTOCOL_41 | CLIENT_TRANSACTIONS | CLIENT_SECURE_CONNECTION);
  greet.setAuthPluginName(auth_plugin_name);
  return greet;
}

OkMessage MessageHelper::encodeOk() {
  OkMessage ok{};
  ok.setAffectedRows(0);
  ok.setLastInsertId(0);
  ok.setWarnings(0);
  return ok;
}

AuthSwitchMessage MessageHelper::encodeAuthSwitch(const std::vector<uint8_t>& seed) {
  return encodeAuthSwitch(seed, "mysql_native_password");
}

AuthSwitchMessage MessageHelper::encodeAuthSwitch(const std::vector<uint8_t>& seed,
                                                  const std::string& auth_plugin_name) {
  AuthSwitchMessage auth_switch{};
  auth_switch.setAuthPluginName(auth_plugin_name);
  auth_switch.setAuthPluginData(seed);
  return auth_switch;
}

AuthMoreMessage MessageHelper::encodeAuthMore(const std::vector<uint8_t>& seed) {
  AuthMoreMessage auth_more{};
  auth_more.setAuthMoreData(seed);
  return auth_more;
}

ErrMessage MessageHelper::encodeErr(uint16_t error_code, uint8_t sql_marker,
                                    std::string&& sql_state, std::string&& error_message) {
  ErrMessage resp;
  resp.setErrorCode(error_code);
  resp.setSqlStateMarker(sql_marker);
  resp.setSqlState(std::move(sql_state));
  resp.setErrorMessage(std::move(error_message));
  return resp;
}

ErrMessage MessageHelper::passwordLengthError(int len) {
  return encodeErr(ER_PASSWD_LENGTH, MYSQL_SQL_STATE_MARKER, "HY000",
                   fmt::format("Password hash should be a {}-digit hexadecimal number", len));
}

ErrMessage MessageHelper::authError(const std::string& username, const std::string& destination,
                                    bool using_password) {
  return encodeErr(ER_ACCESS_DENIED_ERROR, MYSQL_SQL_STATE_MARKER, "28000",
                   fmt::format("Access denied for user '{}'@'{}' to database 'using password: {}'",
                               username, destination, using_password ? "YES" : "NO"));
}

ErrMessage MessageHelper::dbError(const std::string& db) {
  return encodeErr(ER_ER_BAD_DB_ERROR, MYSQL_SQL_STATE_MARKER, "42000",
                   fmt::format("Unknown database {}", db));
}

ErrMessage MessageHelper::injectError() {
  return encodeErr(30001, MYSQL_SQL_STATE_MARKER, "45000", "Envoy Inject Error");
}

ClientSwitchResponse MessageHelper::encodeSwithResponse(const std::vector<uint8_t>& auth_resp) {
  ClientSwitchResponse resp;
  resp.setAuthPluginResp(auth_resp);
  return resp;
}

Command MessageHelper::encodeCommand(Command::Cmd cmd, const std::string& data,
                                     const std::string db, bool is_query) {
  Command command{};
  command.setCmd(cmd);
  command.setData(data);
  command.setDb(db);
  command.setIsQuery(is_query);
  return command;
}
CommandResponse MessageHelper::encodeCommandResponse(const std::string& data) {
  CommandResponse resp{};
  resp.setData(data);
  return resp;
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
