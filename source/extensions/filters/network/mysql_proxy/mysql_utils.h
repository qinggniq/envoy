#pragma once

#include "envoy/buffer/buffer.h"
#include "envoy/common/platform.h"

#include "common/buffer/buffer_impl.h"
#include "common/common/byte_order.h"
#include "common/common/logger.h"

#include "extensions/filters/network/mysql_proxy/mysql_codec.h"

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
  static void addBytes(Buffer::Instance& buffer, const char* data, int size);
  static void addString(Buffer::Instance& buffer, const std::string& str) {
    addBytes(buffer, str.data(), str.size());
  }
  static void addVector(Buffer::Instance& buffer, const std::vector<uint8_t>& data) {
    addBytes(buffer, reinterpret_cast<const char*>(data.data()), data.size());
  }
  static void encodeHdr(Buffer::Instance& pkg, uint8_t seq);
  static bool endOfBuffer(Buffer::Instance& buffer);
  static DecodeStatus readUint8(Buffer::Instance& buffer, uint8_t& val);
  static DecodeStatus readUint16(Buffer::Instance& buffer, uint16_t& val);
  static DecodeStatus readUint24(Buffer::Instance& buffer, uint32_t& val);
  static DecodeStatus readUint32(Buffer::Instance& buffer, uint32_t& val);
  static DecodeStatus readLengthEncodedInteger(Buffer::Instance& buffer, uint64_t& val);
  static DecodeStatus skipBytes(Buffer::Instance& buffer, size_t skip_bytes);
  static DecodeStatus readString(Buffer::Instance& buffer, std::string& str);
  static DecodeStatus readVector(Buffer::Instance& buffer, std::vector<uint8_t>& data);
  static DecodeStatus readStringBySize(Buffer::Instance& buffer, size_t len, std::string& str);
  static DecodeStatus readVectorBySize(Buffer::Instance& buffer, size_t len,
                                       std::vector<uint8_t>& vec);
  static DecodeStatus readAll(Buffer::Instance& buffer, std::string& str);
  static DecodeStatus peekUint32(Buffer::Instance& buffer, uint32_t& val);
  static DecodeStatus peekUint8(Buffer::Instance& buffer, uint8_t& val);
  static void consumeHdr(Buffer::Instance& buffer);
  static DecodeStatus peekHdr(Buffer::Instance& buffer, uint32_t& len, uint8_t& seq);
};

class AuthHelperTest;
/**
 * MySQL auth method.
 */
enum class AuthMethod : uint8_t {
  Unknown,
  OldPassword,
  NativePassword,
  Sha256Password,
  CacheSha2Password,
  ClearPassword
};

/**
 * Auth helpers for auth MySQL client and server.
 * Now MySQL Proxy only support OldPassword and NativePassword auth method.
 */
class AuthHelper : public Logger::Loggable<Logger::Id::filter> {
public:
  static AuthMethod authMethod(uint32_t cap, const std::string& auth_plugin_name);

  static std::vector<uint8_t> generateSeed();

  static std::vector<uint8_t> oldPasswordSignature(const std::string& password,
                                                   const std::vector<uint8_t>& seed);

  static std::vector<uint8_t> nativePasswordSignature(const std::string& password,
                                                      const std::vector<uint8_t>& seed);

  static std::vector<uint32_t> oldHash(const std::string& text) {
    return oldHash(text.data(), text.size());
  }
  static std::vector<uint32_t> oldHash(const std::vector<uint8_t>& text) {
    return oldHash(reinterpret_cast<const char*>(text.data()), text.size());
  }
  /*
   * Generate binary hash from raw text string
   * Used for Pre-4.1 password handling
   */
  static std::vector<uint32_t> oldHash(const char* text, int size);
  static std::vector<uint8_t> nativeHash(const std::string& text) {
    return nativeHash(text.data(), text.size());
  }
  static std::vector<uint8_t> nativeHash(const std::vector<uint8_t>& text) {
    return nativeHash(reinterpret_cast<const char*>(text.data()), text.size());
  }
  static std::vector<uint8_t> nativeHash(const char* data, int len);

private:
  struct RandStruct {
    RandStruct(uint32_t seed1, uint32_t seed2);
    double myRnd();
    uint32_t seed1_, seed2_, max_value_;
    double max_value_dbl_;
  };

private:
  static constexpr int SCRAMBLE_LENGTH_323 = 8;
  static constexpr int SEED_LENGTH = 20;
};

} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
