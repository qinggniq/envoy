#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin.h"

#include "common/common/logger.h"
#include "envoy/buffer/buffer.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include <bits/stdint-uintn.h>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

void ClientLogin::setClientCap(uint32_t client_cap) { client_cap_ = client_cap; }

void ClientLogin::setBaseClientCap(uint16_t base_cap) { base_cap_ = base_cap; }

void ClientLogin::setExtendedClientCap(uint16_t extended_client_cap) {
  ext_cap_ = extended_client_cap;
}

void ClientLogin::setMaxPacket(uint32_t max_packet) { max_packet_ = max_packet; }

void ClientLogin::setCharset(uint8_t charset) { charset_ = charset; }

void ClientLogin::setUsername(const std::string& username) {
  if (username.length() <= MYSQL_MAX_USER_LEN) {
    username_.assign(username);
  }
}

void ClientLogin::setDb(const std::string& db) { db_ = db; }

void ClientLogin::setAuthResp(const std::string& auth_resp) { auth_resp_.assign(auth_resp); }

void ClientLogin::setAuthPluginName(const std::string& auth_plugin_name) {
  auth_plugin_name_ = auth_plugin_name;
}

bool ClientLogin::isResponse41() const { return client_cap_ & MYSQL_CLIENT_CAPAB_41VS320; }

bool ClientLogin::isResponse320() const { return !(client_cap_ & MYSQL_CLIENT_CAPAB_41VS320); }

bool ClientLogin::isSSLRequest() const { return client_cap_ & MYSQL_CLIENT_CAPAB_SSL; }

bool ClientLogin::isConnectWithDb() const { return client_cap_ & MYSQL_CLIENT_CONNECT_WITH_DB; }

bool ClientLogin::isClientAuthLenClData() const {
  return client_cap_ & MYSQL_EXT_CL_PLG_AUTH_CL_DATA;
}

bool ClientLogin::isClientSecureConnection() const {
  return client_cap_ & MYSQL_CLIENT_SECURE_CONNECTION;
}

int ClientLogin::parseMessage(Buffer::Instance& buffer, uint32_t package_len) {
  auto buffer_len = buffer.length();
  /* 4.0 uses 2 byte, 4.1+ uses 4 bytes, but the proto-flag is in the lower 2
   * bytes */
  if (BufferHelper::peekUint16(buffer, base_cap_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error when paring cap client login message");
    return MYSQL_FAILURE;
  }
  if (client_cap_ & MYSQL_CLIENT_CAPAB_SSL) {
    if (BufferHelper::readUint32(buffer, client_cap_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when paring cap client ssl message");
      return MYSQL_FAILURE;
    }
    if (BufferHelper::readUint32(buffer, max_packet_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when paring max packet client ssl message");
      return MYSQL_FAILURE;
    }
    if (BufferHelper::readUint8(buffer, charset_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when paring character client ssl message");
      return MYSQL_FAILURE;
    }
    if (BufferHelper::readBytes(buffer, UNSET_BYTES) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when paring reserved data of client ssl message");
      return MYSQL_FAILURE;
    }
    return MYSQL_SUCCESS;
  }
  if (client_cap_ & CLIENT_PROTOCOL_41) {
    if (BufferHelper::readUint32(buffer, client_cap_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when paring cap client login message");
      return MYSQL_FAILURE;
    }
    if (BufferHelper::readUint32(buffer, max_packet_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when paring mas packet client login message");
      return MYSQL_FAILURE;
    }
    if (BufferHelper::readUint8(buffer, charset_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when paring charset client login message");
      return MYSQL_FAILURE;
    }
    if (BufferHelper::readBytes(buffer, UNSET_BYTES) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when skiping bytes client login message");
      return MYSQL_FAILURE;
    }
    if (BufferHelper::readString(buffer, username_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error when parsing username client login message");
      return MYSQL_FAILURE;
    }
    if (client_cap_ & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
      uint64_t auth_len;
      if (BufferHelper::readLengthEncodedInteger(buffer, auth_len) != MYSQL_SUCCESS) {
        ENVOY_LOG(info, "error when parsing username client login message");
        return MYSQL_FAILURE;
      }
      if (BufferHelper::readStringBySize(buffer, auth_len, auth_resp_) != MYSQL_SUCCESS) {
        ENVOY_LOG(info, "error when parsing auth resp client login message");
        return MYSQL_FAILURE;
      }

    } else if (client_cap_ & CLIENT_SECURE_CONNECTION) {
      uint8_t auth_len;
      if (BufferHelper::readUint8(buffer, auth_len) != MYSQL_SUCCESS) {
        ENVOY_LOG(info, "error when parsing auth resp length client login message");
        return MYSQL_FAILURE;
      }
      if (BufferHelper::readStringBySize(buffer, auth_len, auth_resp_) != MYSQL_SUCCESS) {
        ENVOY_LOG(info, "error when parsing auth resp client login message");
        return MYSQL_FAILURE;
      }
    } else {
      if (BufferHelper::readString(buffer, auth_resp_) != MYSQL_SUCCESS) {
        ENVOY_LOG(info, "error when parsing auth resp client login message");
        return MYSQL_FAILURE;
      }
    }

    if ((client_cap_ & CLIENT_CONNECT_WITH_DB) &&
        (BufferHelper::readString(buffer, db_) != MYSQL_SUCCESS)) {
      ENVOY_LOG(info, "error when parsing db name client login message");
      return MYSQL_FAILURE;
    }
    if ((client_cap_ & CLIENT_PLUGIN_AUTH) &&
        (BufferHelper::readString(buffer, db_) != MYSQL_SUCCESS)) {
      ENVOY_LOG(info, "error when parsing auth plugin name client login message");
      return MYSQL_FAILURE;
    }
  }

  if (BufferHelper::readUint16(buffer, base_cap_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error when paring cap client login message");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readUint24(buffer, max_packet_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error when paring max packet client login message");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readString(buffer, username_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error when paring username client login message");
    return MYSQL_FAILURE;
  }
  // there are more
  auto remain_len = package_len - (buffer_len - buffer.length());
  if ((remain_len > 0) && (BufferHelper::readStringBySize(buffer, remain_len, auth_resp_))) {
    ENVOY_LOG(info, "error when paring auth resp  client login message");
    return MYSQL_FAILURE;
  }

  return MYSQL_SUCCESS;
}

void ClientLogin::encode(Buffer::Instance& out) {
  uint8_t enc_end_string = 0;
  if (client_cap_ & CLIENT_SSL) {
    BufferHelper::addUint32(out, client_cap_);
    BufferHelper::addUint32(out, max_packet_);
    BufferHelper::addUint8(out, charset_);
    for (int i = 0; i < UNSET_BYTES; i++) {
      BufferHelper::addUint8(out, 0);
    }
    return;
  }
  if (!(client_cap_ & CLIENT_PROTOCOL_41)) {
    BufferHelper::addUint16(out, base_cap_);
    BufferHelper::addUint24(out, max_packet_);
    BufferHelper::addString(out, username_);
    BufferHelper::addUint8(out, enc_end_string);
    if (!auth_resp_.empty()) {
      BufferHelper::addString(out, auth_resp_);
    }
    if (client_cap_ & CLIENT_CONNECT_WITH_DB) {
      BufferHelper::addString(out, auth_resp_);
      BufferHelper::addUint8(out, enc_end_string);
      BufferHelper::addString(out, db_);
      BufferHelper::addUint8(out, enc_end_string);
    } else {
      BufferHelper::addString(out, auth_resp_);
      BufferHelper::addUint8(out, -1);
    }
  } else {
    BufferHelper::addUint32(out, client_cap_);
    BufferHelper::addUint32(out, max_packet_);
    BufferHelper::addUint8(out, charset_);
    for (int idx = 0; idx < UNSET_BYTES; idx++) {
      BufferHelper::addUint8(out, 0);
    }
    if (!username_.empty()) {
      BufferHelper::addString(out, username_);
    }
    BufferHelper::addUint8(out, enc_end_string);
    if (client_cap_ & CLIENT_PLUGIN_AUTH_LENENC_CLIENT_DATA) {
      BufferHelper::addLengthEncodedInteger(out, auth_resp_.size());
      BufferHelper::addString(out, auth_resp_);
    } else if (client_cap_ & MYSQL_CLIENT_SECURE_CONNECTION) {
      /* server supports the secure-auth (4.1+) which is 255 bytes max
       *
       * if ->len is longer than 255, wrap around ... should be reported back
       * to the upper layers
       */
      BufferHelper::addUint8(out, auth_resp_.size());
      BufferHelper::addStringBySize(out, auth_resp_.size() & 0xff, auth_resp_);
    } else {
      BufferHelper::addString(out, auth_resp_);
      BufferHelper::addUint8(out, enc_end_string);
    }
    if ((client_cap_ & CLIENT_CONNECT_WITH_DB) && !db_.empty()) {
      BufferHelper::addString(out, db_);
      BufferHelper::addUint8(out, enc_end_string);
    }
    if ((client_cap_ & CLIENT_PLUGIN_AUTH) && !auth_plugin_name_.empty()) {
      BufferHelper::addString(out, auth_plugin_name_);
      BufferHelper::addUint8(out, enc_end_string);
    }
    if (client_cap_ & CLIENT_CONNECT_ATTRS) {
      ENVOY_LOG(info, "proxy can not support connection attribute");
    }
  }
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
