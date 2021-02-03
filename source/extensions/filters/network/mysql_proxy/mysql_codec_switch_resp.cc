#include "extensions/filters/network/mysql_proxy/mysql_codec_switch_resp.h"

#include "envoy/buffer/buffer.h"

#include "common/common/logger.h"

#include "extensions/filters/network/mysql_proxy/mysql_codec.h"
#include "extensions/filters/network/mysql_proxy/mysql_utils.h"

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

DecodeStatus ClientSwitchResponse::parseMessage(Buffer::Instance& buffer, uint32_t) {
  if (BufferHelper::readStringEof(buffer, auth_plugin_resp_) != DecodeStatus::Success) {
    ENVOY_LOG(info, "error when parsing auth plugin data in client switch response");
    return DecodeStatus::Failure;
  }
  return DecodeStatus::Success;
}

void ClientSwitchResponse::encode(Buffer::Instance& out) {
  BufferHelper::addString(out, auth_plugin_resp_);
  BufferHelper::addUint8(out, EOF);
}

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
