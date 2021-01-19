#include "extensions/filters/network/mysql_proxy/mysql_codec_greeting.h"

#include "envoy/buffer/buffer.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "source/extensions/filters/network/mysql_proxy/_virtual_includes/proxy_lib/extensions/filters/network/mysql_proxy/mysql_utils.h"
#include <bits/stdint-uintn.h>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

void ServerGreeting::setProtocol(uint8_t protocol) { protocol_ = protocol; }

void ServerGreeting::setVersion(const std::string& version) { version_.assign(version); }

void ServerGreeting::setThreadId(uint32_t thread_id) { thread_id_ = thread_id; }

void ServerGreeting::setAuthPluginData(const std::string& data) { auth_plugin_data_ = data; }

void ServerGreeting::setServerCap(uint32_t server_cap) { server_cap_ = server_cap; }

void ServerGreeting::setBaseServerCap(uint16_t base_server_cap) {
  base_server_cap_ = base_server_cap;
}

void ServerGreeting::setExtServerCap(uint16_t ext_server_cap) { ext_server_cap_ = ext_server_cap; }

void ServerGreeting::setServerCharset(uint8_t server_charset) { server_charset_ = server_charset; }

void ServerGreeting::setServerStatus(uint16_t server_status) { server_status_ = server_status; }

int ServerGreeting::parseMessage(Buffer::Instance& buffer, uint32_t len) {
  uint32_t buffer_length = buffer.length();
  // parse logic from
  // https://github.com/mysql/mysql-proxy/blob/ca6ad61af9088147a568a079c44d0d322f5bee59/src/network-mysqld-packet.c#L1171
  if (BufferHelper::readUint8(buffer, protocol_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing protocol in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readString(buffer, version_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing version in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readUint32(buffer, thread_id_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing thread_id in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  // read auth plugin data part 1, which is 8 byte.
  std::string auth_plugin_data1;
  if (BufferHelper::readStringBySize(buffer, 8, auth_plugin_data1) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing auth_plugin_data1 in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  auth_plugin_data_ += auth_plugin_data1;
  if (BufferHelper::readBytes(buffer, 1) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing fill placeholder in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (protocol_ == MYSQL_PROTOCOL_9) {
    // End of HandshakeV9 greeting
    goto CHECK;
  }
  if (BufferHelper::readUint16(buffer, base_server_cap_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing server_cap in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::endOfBuffer(buffer)) {
    // HandshakeV10 can terminate after Server Capabilities
    goto CHECK;
  }
  if (BufferHelper::readUint8(buffer, server_charset_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing server_language in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readUint16(buffer, server_status_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing server_status in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (BufferHelper::readUint16(buffer, ext_server_cap_) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing ext_server_cap in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  uint8_t auth_plugin_data_len;
  if (BufferHelper::readUint8(buffer, auth_plugin_data_len) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing auth_plugin_data_len in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (!auth_plugin_data_len) {
    goto CHECK;
  }
  if (BufferHelper::readBytes(buffer, 10) != MYSQL_SUCCESS) {
    ENVOY_LOG(info, "error parsing reserved in mysql Greeting msg");
    return MYSQL_FAILURE;
  }
  if (server_cap_ & CLIENT_PLUGIN_AUTH) {
    int auth_plugin_data_len2 = 0;
    if (auth_plugin_data_len > 8) {
      auth_plugin_data_len2 = auth_plugin_data_len - 8;
    }
    std::string auth_plugin_data2;
    if (BufferHelper::readStringBySize(buffer, auth_plugin_data_len2, auth_plugin_data2) !=
        MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error skiping auth_plugin_data2 in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
    auth_plugin_data_ += auth_plugin_data2;
    int skiped_bytes = 12 > auth_plugin_data_len2 ? auth_plugin_data_len2 : 12;
    if (BufferHelper::readBytes(buffer, skiped_bytes) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error skiping in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
    /* Bug#59453 ... MySQL 5.5.7-9 and 5.6.0-1 don't send a trailing \0
     *
     * if there is no trailing \0, get the rest of the packet
     */
    // buffer might containe the next package frame, so we need to make sure the tail \0 is not
    // belong to next package frame
    char end = MYSQL_STR_END;
    ssize_t index = buffer.search(&end, sizeof(end), 0);
    uint32_t remain_len = len - (buffer_length - buffer.length());
    // this frame have tail
    if (index != -1 && index < remain_len) {
      remain_len = index;
    }
    if (BufferHelper::readStringBySize(buffer, remain_len, auth_plugin_name_) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error parsing auth_plugin_name in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
  } else if (server_cap_ & CLIENT_SECURE_CONNECTION) {
    std::string auth_plugin_data2;
    if (BufferHelper::readStringBySize(buffer, 12, auth_plugin_data2) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error parsing auth_plugin_data2 in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
    auth_plugin_data_ += auth_plugin_data2;
    if (BufferHelper::readBytes(buffer, 1) != MYSQL_SUCCESS) {
      ENVOY_LOG(info, "error skiping in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
  }
CHECK:
  /* some final assertions */
  if (server_cap_ & CLIENT_PLUGIN_AUTH) {
    if (auth_plugin_data_.size() != auth_plugin_data_len) {
      ENVOY_LOG(info, "error parsing auth plugin data in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
  } else if (server_cap_ & CLIENT_SECURE_CONNECTION) {
    if (auth_plugin_data_.size() != 20) {
      ENVOY_LOG(info, "error parsing auth plugin data in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
  } else {
    /* old auth */
    if (auth_plugin_data_.size() != 8) {
      ENVOY_LOG(info, "error parsing auth plugin data in mysql Greeting msg");
      return MYSQL_FAILURE;
    }
  }
  return MYSQL_SUCCESS;
}

void ServerGreeting::encode(Buffer::Instance& out) {
  // https://github.com/mysql/mysql-proxy/blob/ca6ad61af9088147a568a079c44d0d322f5bee59/src/network-mysqld-packet.c#L1339
  uint8_t enc_end_string = 0;
  BufferHelper::addUint8(out, protocol_);
  if (!version_.empty()) {
    BufferHelper::addString(out, version_);
  } else {
    BufferHelper::addString(out, "5.0.99");
  }
  BufferHelper::addUint8(out, enc_end_string);
  BufferHelper::addUint32(out, thread_id_);
  if (!auth_plugin_data_.empty()) {
    BufferHelper::addString(out, auth_plugin_data_.substr(0, 8));
  } else {
    BufferHelper::addString(out, "01234567");
  }
  BufferHelper::addUint8(out, enc_end_string);
  if (protocol_ == MYSQL_PROTOCOL_9) {
    return;
  }
  BufferHelper::addUint16(out, base_server_cap_);
  BufferHelper::addUint8(out, server_charset_);
  BufferHelper::addUint16(out, server_status_);
  BufferHelper::addUint16(out, ext_server_cap_);

  if (server_cap_ & CLIENT_PLUGIN_AUTH) {
    BufferHelper::addUint8(out, auth_plugin_data_.size());
  } else {
    BufferHelper::addUint8(out, 0);
  }
  // reserved
  for (int i = 0; i < 10; i++) {
    BufferHelper::addUint8(out, 0);
  }
  if (server_cap_ & CLIENT_PLUGIN_AUTH) {
    BufferHelper::addString(out, auth_plugin_data_.substr(8));
    BufferHelper::addString(out, auth_plugin_name_);
    // TODO(qinggniq) judge version 5.5.7-9 and 5.6.0-1 which should not add tail
    BufferHelper::addUint8(out, enc_end_string);
  } else if (server_cap_ & CLIENT_SECURE_CONNECTION) {
    if (!auth_plugin_data_.empty()) {
      BufferHelper::addString(out, auth_plugin_data_.substr(8));
    } else {
      BufferHelper::addString(out, "890123456789");
    }
    BufferHelper::addUint8(out, enc_end_string);
  }
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
