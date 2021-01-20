#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin_resp.h"

#include "common/common/logger.h"
#include "envoy/buffer/buffer.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "source/extensions/filters/network/mysql_proxy/_virtual_includes/proxy_lib/extensions/filters/network/mysql_proxy/mysql_utils.h"
#include <bits/stdint-uintn.h>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

void ClientLoginResponse::setRespCode(uint8_t resp_code) { resp_code_ = resp_code; }
// Ok
void ClientLoginResponse::setAffectedRows(uint8_t affected_rows) { affected_rows_ = affected_rows; }
void ClientLoginResponse::setLastInsertId(uint8_t last_insert_id) {
  last_insert_id_ = last_insert_id;
}
void ClientLoginResponse::setServerStatus(uint16_t status) { server_status_ = status; }
void ClientLoginResponse::setWarnings(uint16_t warnings) { warnings_ = warnings; }
void ClientLoginResponse::setInfo(const std::string& info) { info_ = info; }
// Err
void ClientLoginResponse::setErrorCode(uint16_t error_code) { error_code_ = error_code; }
void ClientLoginResponse::setSqlStateMarker(uint8_t marker) { marker_ = marker; }
void ClientLoginResponse::setSqlState(const std::string& state) { sql_state_ = state; }
void ClientLoginResponse::setErrorMessage(const std::string& message) { error_message_ = message; }
// AuthSwitch
void ClientLoginResponse::setAuthPluginData(const std::string& data) { auth_plugin_data_ = data; }
void ClientLoginResponse::setAuthPluginName(const std::string& name) { auth_plugin_name_ = name; }
void ClientLoginResponse::setAuthMoreData(const std::string& data) { more_plugin_data_ = data; }
int ClientLoginResponse::parseMessage(Buffer::Instance& buffer, uint32_t len) {
  uint8_t resp_code;
  if (BufferHelper::peekUint8(buffer, resp_code) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing response code in mysql Login response msg");
    return MYSQL_FAILURE;
  }
  switch (resp_code) {
  case MYSQL_RESP_AUTH_SWITCH:
    return parseAuthSwitch(buffer, len);
  case MYSQL_RESP_OK:
    return parseOk(buffer, len);
  case MYSQL_RESP_ERR:
    return parseErr(buffer, len);
  case MYSQL_RESP_MORE:
    return parseAuthMore(buffer, len);
  }
  ENVOY_LOG(info, "unknown mysql Login resp msg type");
}

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthSwitchRequest
int ClientLoginResponse::parseAuthSwitch(Buffer::Instance& buffer, uint32_t) {
  // OldAuthSwitchRequest
  type_ = OldAuthSwitch;
  if (BufferHelper::readUint8(buffer, resp_code_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing response code in mysql Login response msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::endOfBuffer(buffer)) {
    return MYSQL_SUCCESS;
  }
  type_ = PluginAuthSwitch;
  if (BufferHelper::readString(buffer, auth_plugin_name_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing auth plugin name mysql Login response msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readStringEof(buffer, auth_plugin_data_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing auth plugin data code in mysql Login Ok msg");
    return MYSQL_FAILURE;
  }
  return MYSQL_SUCCESS;
}

// https://dev.mysql.com/doc/internals/en/packet-OK_Packet.html
int ClientLoginResponse::parseOk(Buffer::Instance& buffer, uint32_t) {
  type_ = Ok;
  if (BufferHelper::readUint8(buffer, resp_code_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing response code in mysql Login response msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readLengthEncodedInteger(buffer, affected_rows_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing affected_rows in mysql Login Ok msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readLengthEncodedInteger(buffer, last_insert_id_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing last_insert_id in mysql Login Ok msg");
    return MYSQL_FAILURE;
  }

  if (BufferHelper::readUint16(buffer, server_status_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing server_status in mysql Login Ok msg");
    return MYSQL_FAILURE;
  }
  // the exist of warning feild is determined by server cap flag, but a decoder can not know the
  // cap flag, so just assume the CLIENT_PROTOCOL_41 is always set. ref
  // https://github.com/mysql/mysql-connector-j/blob/release/8.0/src/main/protocol-impl/java/com/mysql/cj/protocol/a/result/OkPacket.java#L48
  if (BufferHelper::readUint16(buffer, warnings_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing warnings in mysql Login Ok msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readString(buffer, info_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing info in mysql Login Ok msg");
    return MYSQL_FAILURE;
  }
  return MYSQL_SUCCESS;
}

// https://dev.mysql.com/doc/internals/en/packet-ERR_Packet.html
int ClientLoginResponse::parseErr(Buffer::Instance& buffer, uint32_t) {
  type_ = Err;
  if (BufferHelper::readUint8(buffer, resp_code_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing response code in mysql Login response msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readUint16(buffer, error_code_) != MYSQL_RESP_OK) {
    ENVOY_LOG(info, "error parsing error code in mysql Login error msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readUint8(buffer, marker_) != MYSQL_RESP_OK) {
    ENVOY_LOG(info, "error parsing sql state marker in mysql Login error msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readStringBySize(buffer, MYSQL_SQL_STATE_LEN, sql_state_) != MYSQL_RESP_OK) {
    ENVOY_LOG(info, "error parsing sql state in mysql Login error msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readStringEof(buffer, error_message_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing error message in mysql Login error msg");
    return MYSQL_FAILURE;
  }
  return MYSQL_SUCCESS;
}

// https://dev.mysql.com/doc/internals/en/connection-phase-packets.html#packet-Protocol::AuthMoreData
int ClientLoginResponse::parseAuthMore(Buffer::Instance& buffer, uint32_t) {
  type_ = AuthMoreData;
  if (BufferHelper::readUint8(buffer, resp_code_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing response code in mysql Login response msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readStringEof(buffer, more_plugin_data_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing more plugin data in mysql Login auth more msg");
    return MYSQL_FAILURE;
  }
  return MYSQL_SUCCESS;
}

void ClientLoginResponse::encode(Buffer::Instance& out) {
  switch (resp_code_) {
  case MYSQL_RESP_AUTH_SWITCH:
    encodeAuthSwitch(out);
    break;
  case MYSQL_RESP_OK:
    encodeOk(out);
    break;
  case MYSQL_RESP_ERR:
    encodeErr(out);
    break;
  case MYSQL_RESP_MORE:
    encodeAuthMore(out);
    break;
  }
}

void ClientLoginResponse::encodeAuthSwitch(Buffer::Instance& out) {
  BufferHelper::addUint8(out, resp_code_);
  if (auth_plugin_name_.empty()) {
    // OldAuthSwitch
    return;
  }
  BufferHelper::addString(out, auth_plugin_name_);
  BufferHelper::addUint8(out, 0);
  BufferHelper::addString(out, auth_plugin_data_);
  BufferHelper::addUint8(out, -1);
}

void ClientLoginResponse::encodeOk(Buffer::Instance& out) {
  BufferHelper::addUint8(out, resp_code_);
  BufferHelper::addLengthEncodedInteger(out, affected_rows_);
  BufferHelper::addLengthEncodedInteger(out, last_insert_id_);
  BufferHelper::addUint16(out, server_status_);
  BufferHelper::addUint16(out, warnings_);
  BufferHelper::addString(out, info_);
  BufferHelper::addUint8(out, -1);
}

void ClientLoginResponse::encodeErr(Buffer::Instance& out) {
  BufferHelper::addUint8(out, resp_code_);
  BufferHelper::addUint16(out, error_code_);
  BufferHelper::addUint8(out, marker_);
  BufferHelper::addString(out, sql_state_);
  BufferHelper::addString(out, error_message_);
  BufferHelper::addUint8(out, -1);
}

void ClientLoginResponse::encodeAuthMore(Buffer::Instance& out) {
  BufferHelper::addUint8(out, resp_code_);
  BufferHelper::addString(out, more_plugin_data_);
  BufferHelper::addUint8(out, -1);
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
