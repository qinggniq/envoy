#pragma once
#include <bits/stdint-uintn.h>
#include <cstdint>
#include <unistd.h>

#include "envoy/buffer/buffer.h"
#include "envoy/common/platform.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/byte_order.h"
#include "common/common/logger.h"

#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_clogin_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_command.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_greeting.h"
#include "extensions/filters/network/mysql_proxy/mysql_codec_switch_resp.h"
#include "extensions/filters/network/mysql_proxy/mysql_session.h"

#include <openssl/sha.h>
#include <openssl/digest.h>
#include <functional>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

/**
 * IO helpers for reading/writing MySQL data from/to a buffer.
 * MySQL uses unsigned integer values in Little Endian format only.
 */
class BufferHelper : public Logger::Loggable<Logger::Id::filter> {
public:
  static void addUint8(Buffer::Instance& buffer, uint8_t val);
  static void addUint16(Buffer::Instance& buffer, uint16_t val);
  static void addUint24(Buffer::Instance& buffer, uint32_t val);
  static void addUint32(Buffer::Instance& buffer, uint32_t val);
  static void addLengthEncodedInteger(Buffer::Instance& buffer, uint64_t val);
  static void addString(Buffer::Instance& buffer, const std::string& str);
  static void addStringBySize(Buffer::Instance& buffer, size_t len, const std::string& str);
  static std::string encodeHdr(const std::string& cmd_str, uint8_t seq);
  static bool endOfBuffer(Buffer::Instance& buffer);
  static int readUint8(Buffer::Instance& buffer, uint8_t& val);
  static int readUint16(Buffer::Instance& buffer, uint16_t& val);
  static int readUint24(Buffer::Instance& buffer, uint32_t& val);
  static int readUint32(Buffer::Instance& buffer, uint32_t& val);
  static int readLengthEncodedInteger(Buffer::Instance& buffer, uint64_t& val);
  static int readBytes(Buffer::Instance& buffer, size_t skip_bytes);
  static int readString(Buffer::Instance& buffer, std::string& str);
  static int readStringBySize(Buffer::Instance& buffer, size_t len, std::string& str);
  static int readStringEof(Buffer::Instance& buffer, std::string& str);
  static int readAll(Buffer::Instance& buffer, std::string& str);
  static int peekUint32(Buffer::Instance& buffer, uint32_t& val);
  static int peekUint16(Buffer::Instance& buffer, uint16_t& val);
  static int peekUint8(Buffer::Instance& buffer, uint8_t& val);
  static void consumeHdr(Buffer::Instance& buffer);
  static int peekHdr(Buffer::Instance& buffer, uint32_t& len, uint8_t& seq);
};

/**
 * MySQL auth method.
 */
enum AuthMethod {
  OldPassword,
  NativePassword,
  PluginAuth,
};

/**
 * Auth helpers for auth MySQL client and server.
 * Now MySQL Proxy only support OldPassword and NativePassword auth method.
 */
class AuthHelper : public Logger::Loggable<Logger::Id::filter> {
public:
  // judge the auth mehod by cap flag
  static AuthMethod authMethod(uint16_t cap, uint16_t ext_cap);

  static std::string oldPasswordSignature(const std::string& password, const std::string& seed);
  static std::string nativePasswordSignature(const std::string& password, const std::string& seed);

  static std::string oldPasswordHashHash(const std::string& password);
  static std::string nativePasswordHashHash(const std::string& password);

  static bool oldPasswordVerify(const std::string& password, const std::string& seed,
                                const std::string sig);

  static bool nativePasswordVerify(const std::string& password, const std::string& seed,
                                   const std::string sig);

private:
  // client use password and seed cacluate the signature as auth response
  template <const EVP_MD* (*ShaType)(), int DigestSize>
  static std::string signature(const std::string& password, const std::string& seed);
  // server use password hash function sha(sha(password)) store into user table
  template <const EVP_MD* (*ShaType)(), int DigestSize>
  static std::string passwordHashHash(const std::string& password);
  /*
   * Verify function.
   * @password: the downstream auth password.
   * @seed: random seed sent by server.
   * @sig: client auth response calculated by @signature
   * return:
   * whether auth success.
   */
  template <const EVP_MD* (*ShaType)(), int DigestSize>
  static bool verify(const std::string& password, const std::string& seed, const std::string& sig);
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
