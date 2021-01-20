#pragma once
#include <bits/stdint-uintn.h>
#include <cstdint>

#include "common/buffer/buffer_impl.h"

#include "envoy/buffer/buffer.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "source/extensions/filters/network/mysql_proxy/_virtual_includes/proxy_lib/extensions/filters/network/mysql_proxy/mysql_codec_clogin.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

enum ClientLoginResponseType { Unknown, Ok, Err, OldAuthSwitch, PluginAuthSwitch, AuthMoreData };

// ClientLoginResponse colud be
// Protocol::OldAuthSwitchRequest, Protocol::AuthSwitchRequest when server want switch auth method
// or OK_Packet, ERR_Packet when server auth ok or error
class ClientLoginResponse : public MySQLCodec {
public:
  // MySQLCodec
  int parseMessage(Buffer::Instance& buffer, uint32_t len) override;
  void encode(Buffer::Instance&) override;
  ~ClientLoginResponse() override {
    auth_plugin_data_.clear();
    more_plugin_data_.clear();
    info_.clear();
    sql_state_.clear();
    auth_plugin_name_.clear();
    error_message_.clear();
  }
  ClientLoginResponseType type() const { return type_; }
  bool isOldAuthSwitchRequest() const { return type_ == OldAuthSwitch; }

  // common
  uint8_t getRespCode() const { return resp_code_; }

  // Ok
  uint64_t getAffectedRows() const { return affected_rows_; }
  uint64_t getLastInsertId() const { return last_insert_id_; }
  uint16_t getServerStatus() const { return server_status_; }
  uint16_t getWarnings() const { return warnings_; }
  std::string getInfo() const { return info_; }

  // Err
  uint16_t getErrorCode() const { return error_code_; }
  uint8_t getSqlStateMarker() const { return marker_; }
  std::string getSqlState() const { return sql_state_; }
  std::string getErrorMessage() const { return error_message_; }

  // PluginAuthSwitch
  std::string getAuthPluginData() const { return auth_plugin_data_; }
  std::string getAuthPluginName() const { return auth_plugin_name_; }

  // AuthMoreData
  std::string getAuthMoreData() const { return more_plugin_data_; }

  // common
  void setRespCode(uint8_t resp_code);
  // Ok
  void setAffectedRows(uint8_t affected_rows);
  void setLastInsertId(uint8_t last_insert_id);
  void setServerStatus(uint16_t status);
  void setWarnings(uint16_t warnings);
  void setInfo(const std::string& info);
  // Err
  void setErrorCode(uint16_t error_code);
  void setSqlStateMarker(uint8_t marker);
  void setSqlState(const std::string&);
  void setErrorMessage(const std::string&);
  // AuthSwitch
  void setAuthPluginData(const std::string& data);
  void setAuthPluginName(const std::string& name);

  // AuthMoreData
  void setAuthMoreData(const std::string&);

private:
  int parseAuthSwitch(Buffer::Instance& buffer, uint32_t len);
  int parseOk(Buffer::Instance& buffer, uint32_t len);
  int parseErr(Buffer::Instance& buffer, uint32_t len);
  int parseAuthMore(Buffer::Instance& buffer, uint32_t len);
  void encodeAuthSwitch(Buffer::Instance&);
  void encodeOk(Buffer::Instance&);
  void encodeErr(Buffer::Instance&);
  void encodeAuthMore(Buffer::Instance&);
  ClientLoginResponseType type_{Unknown};
  uint8_t resp_code_;
  uint64_t affected_rows_;
  uint64_t last_insert_id_;
  union {
    uint16_t server_status_; // OK packet
    uint16_t error_code_;    // Err packet
  };
  union {
    uint16_t warnings_; // OK packet
    uint8_t marker_;    // Err packet
  };
  union {
    std::string auth_plugin_data_; // PluginAuthSwitch
    std::string more_plugin_data_; // AuthMoreData
    std::string info_;             // Ok
    std::string sql_state_;        // Err
  };
  union {
    std::string auth_plugin_name_; // PluginAuthSwitch
    std::string error_message_;    // Err
  };
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
