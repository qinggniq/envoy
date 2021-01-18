#pragma once
#include "common/buffer/buffer_impl.h"

#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include <bits/stdint-uintn.h>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

class ServerGreeting : public MySQLCodec {
public:
  // MySQLCodec
  int parseMessage(Buffer::Instance& buffer, uint32_t len) override;
  void encode(Buffer::Instance&) override;

  uint8_t getProtocol() const { return protocol_; }
  const std::string& getVersion() const { return version_; }
  uint32_t getThreadId() const { return thread_id_; }
  const std::string& getAuthPluginData() const { return auth_plugin_data_; };

  int getServerCharset() const { return server_charset_; }
  int getServerStatus() const { return server_status_; }
  uint32_t getServerCap() const { return server_cap_; }
  uint16_t getBaseServerCap() const { return base_server_cap_; }
  uint16_t getExtServerCap() const { return ext_server_cap_; }
  const std::string& getAuthPluginName() const { return auth_plugin_name_; }

  void setProtocol(uint8_t protocol);
  void setVersion(const std::string& version);
  void setThreadId(uint32_t thread_id);
  void setAuthPluginData(const std::string& salt);
  void setServerCap(uint32_t server_cap);
  void setBaseServerCap(uint16_t base_server_cap);
  void setExtServerCap(uint16_t ext_server_cap);

  void setServerCharset(uint8_t server_language);
  void setServerStatus(uint16_t server_status);

private:
  uint8_t protocol_;
  std::string version_;
  uint32_t thread_id_;
  std::string auth_plugin_data_;
  union {
    uint32_t server_cap_;
    struct {
      uint16_t ext_server_cap_;
      uint16_t base_server_cap_;
    };
  };
  uint8_t server_charset_;
  uint16_t server_status_;
  std::string auth_plugin_name_;
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
