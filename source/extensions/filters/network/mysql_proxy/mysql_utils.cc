#include "extensions/filters/network/mysql_proxy/mysql_utils.h"
#include "source/extensions/filters/network/mysql_proxy/_virtual_includes/codec_lib/extensions/filters/network/mysql_proxy/mysql_codec.h"
#include <bits/stdint-uintn.h>
#include <iterator>

namespace Envoy {
namespace Extensions {
namespace NetworkFilters {
namespace MySQLProxy {

void BufferHelper::addUint8(Buffer::Instance& buffer, uint8_t val) {
  buffer.writeLEInt<uint8_t>(val);
}

void BufferHelper::addUint16(Buffer::Instance& buffer, uint16_t val) {
  buffer.writeLEInt<uint16_t>(val);
}

void BufferHelper::addUint32(Buffer::Instance& buffer, uint32_t val) {
  buffer.writeLEInt<uint32_t>(val);
}

void BufferHelper::addString(Buffer::Instance& buffer, const std::string& str) { buffer.add(str); }

std::string BufferHelper::encodeHdr(const std::string& cmd_str, uint8_t seq) {
  Buffer::OwnedImpl buffer;
  // First byte contains sequence number, next 3 bytes contain cmd string size
  uint32_t header = (seq << 24) | (cmd_str.length() & MYSQL_HDR_PKT_SIZE_MASK);
  addUint32(buffer, header);

  std::string e_string = buffer.toString();
  e_string.append(cmd_str);
  return e_string;
}

bool BufferHelper::endOfBuffer(Buffer::Instance& buffer) { return buffer.length() == 0; }

int BufferHelper::readUint8(Buffer::Instance& buffer, uint8_t& val) {
  try {
    val = buffer.peekLEInt<uint8_t>(0);
    buffer.drain(sizeof(uint8_t));
    return MYSQL_SUCCESS;
  } catch (EnvoyException& e) {
    // buffer underflow
    return MYSQL_FAILURE;
  }
}

int BufferHelper::readUint16(Buffer::Instance& buffer, uint16_t& val) {
  try {
    val = buffer.peekLEInt<uint16_t>(0);
    buffer.drain(sizeof(uint16_t));
    return MYSQL_SUCCESS;
  } catch (EnvoyException& e) {
    // buffer underflow
    return MYSQL_FAILURE;
  }
}

int BufferHelper::readUint32(Buffer::Instance& buffer, uint32_t& val) {
  try {
    val = buffer.peekLEInt<uint32_t>(0);
    buffer.drain(sizeof(uint32_t));
    return MYSQL_SUCCESS;
  } catch (EnvoyException& e) {
    // buffer underflow
    return MYSQL_FAILURE;
  }
}

// Implementation of MySQL lenenc encoder based on
// https://dev.mysql.com/doc/internals/en/integer.html#packet-Protocol::LengthEncodedInteger
int BufferHelper::readLengthEncodedInteger(Buffer::Instance& buffer, uint64_t& val) {
  uint8_t byte_val = 0;
  if (readUint8(buffer, byte_val) == MYSQL_FAILURE) {
    return MYSQL_FAILURE;
  }
  if (byte_val < LENENCODINT_1BYTE) {
    val = byte_val;
    return MYSQL_SUCCESS;
  }

  try {
    if (byte_val == LENENCODINT_2BYTES) {
      val = buffer.peekLEInt<uint64_t, sizeof(uint16_t)>(0);
      buffer.drain(sizeof(uint16_t));
    } else if (byte_val == LENENCODINT_3BYTES) {
      val = buffer.peekLEInt<uint64_t, sizeof(uint8_t) * 3>(0);
      buffer.drain(sizeof(uint8_t) * 3);
    } else if (byte_val == LENENCODINT_8BYTES) {
      val = buffer.peekLEInt<uint64_t>(0);
      buffer.drain(sizeof(uint64_t));
    } else {
      return MYSQL_FAILURE;
    }
  } catch (EnvoyException& e) {
    // buffer underflow
    return MYSQL_FAILURE;
  }

  return MYSQL_SUCCESS;
}

int BufferHelper::readBytes(Buffer::Instance& buffer, size_t skip_bytes) {
  if (buffer.length() < skip_bytes) {
    return MYSQL_FAILURE;
  }
  buffer.drain(skip_bytes);
  return MYSQL_SUCCESS;
}

int BufferHelper::readString(Buffer::Instance& buffer, std::string& str) {
  char end = MYSQL_STR_END;
  ssize_t index = buffer.search(&end, sizeof(end), 0);
  if (index == -1) {
    return MYSQL_FAILURE;
  }
  if (static_cast<int>(buffer.length()) < (index + 1)) {
    return MYSQL_FAILURE;
  }
  str.assign(std::string(static_cast<char*>(buffer.linearize(index)), index));
  str = str.substr(0);
  buffer.drain(index + 1);
  return MYSQL_SUCCESS;
}

int BufferHelper::readStringBySize(Buffer::Instance& buffer, size_t len, std::string& str) {
  if (buffer.length() < len) {
    return MYSQL_FAILURE;
  }
  str.assign(std::string(static_cast<char*>(buffer.linearize(len)), len));
  str = str.substr(0);
  buffer.drain(len);
  return MYSQL_SUCCESS;
}

int BufferHelper::peekUint32(Buffer::Instance& buffer, uint32_t& val) {
  try {
    val = buffer.peekLEInt<uint32_t>(0);
    return MYSQL_SUCCESS;
  } catch (EnvoyException& e) {
    // buffer underflow
    return MYSQL_FAILURE;
  }
}

void BufferHelper::consumeHdr(Buffer::Instance& buffer) { buffer.drain(sizeof(uint32_t)); }

int BufferHelper::peekHdr(Buffer::Instance& buffer, uint32_t& len, uint8_t& seq) {
  uint32_t val = 0;
  if (peekUint32(buffer, val) != MYSQL_SUCCESS) {
    return MYSQL_FAILURE;
  }
  seq = htobe32(val) & MYSQL_HDR_SEQ_MASK;
  len = val & MYSQL_HDR_PKT_SIZE_MASK;
  ENVOY_LOG(trace, "mysql_proxy: MYSQL-hdrseq {}, len {}", seq, len);
  return MYSQL_SUCCESS;
}

AuthMethod AuthHelper::authMethod(uint16_t cap, uint16_t ext_cap) {
  /*
   * https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_connection_phase.html
   */
  bool v41 = cap & MYSQL_CLIENT_CAPAB_41VS320;
  bool sconn = cap & MYSQL_CLIENT_SECURE_CONNECTION;
  bool plugin = ext_cap & MYSQL_EXT_CL_PLUGIN_AUTH;
  if (!v41 || !sconn) {
    return AuthMethod::OldPassword;
  }
  if (v41 && sconn && !plugin) {
    return AuthMethod::NativePassword;
  }
  return AuthMethod::PluginAuth;
}

std::string AuthHelper::oldPasswordSignature(const std::string& password, const std::string& seed) {
  return signature<EVP_sha1, SHA_DIGEST_LENGTH>(password, seed);
}

std::string AuthHelper::nativePasswordSignature(const std::string& password,
                                                const std::string& seed) {
  return signature<EVP_sha256, SHA256_DIGEST_LENGTH>(password, seed);
}

template <const EVP_MD* (*ShaType)(), int DigestSize>
std::string AuthHelper::signature(const std::string& password, const std::string& seed) {
  // hashstage1 = sha(password)
  std::vector<uint8_t> hashstage1(DigestSize);
  bssl::ScopedEVP_MD_CTX ctx;
  auto rc = EVP_DigestInit(ctx.get(), ShaType());
  RELEASE_ASSERT(rc == 1, "Failed to init digest context");
  rc = EVP_DigestUpdate(ctx.get(), password.data(), password.size());
  RELEASE_ASSERT(rc == 1, "Failed to update digest");
  rc = EVP_DigestFinal(ctx.get(), hashstage1.data(), nullptr);
  RELEASE_ASSERT(rc == 1, "Failed to finalize digest");

  // hashstage2 = sha(hashstage1)
  rc = EVP_MD_CTX_reset(ctx.get());
  RELEASE_ASSERT(rc == 1, "Failed to reset digest context");
  std::vector<uint8_t> hashstage2(DigestSize);
  rc = EVP_DigestUpdate(ctx.get(), hashstage1.data(), hashstage1.size());
  RELEASE_ASSERT(rc == 1, "Failed to update digest");
  rc = EVP_DigestFinal(ctx.get(), hashstage2.data(), nullptr);
  RELEASE_ASSERT(rc == 1, "Failed to finalize digest");
  rc = EVP_MD_CTX_reset(ctx.get());
  RELEASE_ASSERT(rc == 1, "Failed to reset digest context");

  // toBeXored = sha(hashstage1, seed)
  std::vector<uint8_t> to_be_xored(DigestSize);
  rc = EVP_DigestUpdate(ctx.get(), seed.data(), seed.size());
  RELEASE_ASSERT(rc == 1, "Failed to update digest");
  rc = EVP_DigestUpdate(ctx.get(), hashstage2.data(), hashstage2.size());
  RELEASE_ASSERT(rc == 1, "Failed to update digest");
  rc = EVP_DigestFinal(ctx.get(), to_be_xored.data(), nullptr);
  RELEASE_ASSERT(rc == 1, "Failed to finalize digest");

  for (int i = 0; i < DigestSize; i++) {
    to_be_xored[i] = to_be_xored[i] ^ hashstage1[i];
  }
  return std::string(to_be_xored.begin(), to_be_xored.end());
}

std::string AuthHelper::oldPasswordHashHash(const std::string& password) {
  return passwordHashHash<EVP_sha1, SHA_DIGEST_LENGTH>(password);
}

std::string AuthHelper::nativePasswordHashHash(const std::string& password) {
  return passwordHashHash<EVP_sha256, SHA256_DIGEST_LENGTH>(password);
}

template <const EVP_MD* (*ShaType)(), int DigestSize>
std::string passwordHashHash(const std::string& password) {
  // passwordHash = sha(sha(password))
  std::vector<uint8_t> passwordHash(DigestSize);
  bssl::ScopedEVP_MD_CTX ctx;
  auto rc = EVP_DigestInit(ctx.get(), ShaType());
  RELEASE_ASSERT(rc == 1, "Failed to init digest context");
  rc = EVP_DigestUpdate(ctx.get(), password.data(), password.size());
  RELEASE_ASSERT(rc == 1, "Failed to update digest");
  rc = EVP_DigestFinal(ctx.get(), passwordHash.data(), nullptr);
  RELEASE_ASSERT(rc == 1, "Failed to finalize digest");

  rc = EVP_MD_CTX_reset(ctx.get());
  RELEASE_ASSERT(rc == 1, "Failed to reset digest context");
  rc = EVP_DigestUpdate(ctx.get(), passwordHash.data(), passwordHash.size());
  RELEASE_ASSERT(rc == 1, "Failed to update digest");
  rc = EVP_DigestFinal(ctx.get(), passwordHash.data(), nullptr);
  RELEASE_ASSERT(rc == 1, "Failed to finalize digest");
  rc = EVP_MD_CTX_reset(ctx.get());
  RELEASE_ASSERT(rc == 1, "Failed to reset digest context");
  return std::string(passwordHash.begin(), passwordHash.end());
}

bool AuthHelper::oldPasswordVerify(const std::string& password, const std::string& seed,
                                   const std::string sig) {
  return verify<EVP_sha1, SHA_DIGEST_LENGTH>(password, seed, sig);
}

bool AuthHelper::nativePasswordVerify(const std::string& password, const std::string& seed,
                                      const std::string sig) {
  return verify<EVP_sha1, SHA_DIGEST_LENGTH>(password, seed, sig);
}

template <const EVP_MD* (*ShaType)(), int DigestSize>
bool AuthHelper::verify(const std::string& password, const std::string& seed,
                        const std::string& sig) {
  if (sig.size() != DigestSize) {
    return false;
  }
  auto expected_sig = signature<ShaType, DigestSize>(password, seed);
  // https://dev.mysql.com/doc/internals/en/old-password-authentication.html
  // note: If the server announces Secure Password Authentication in the Initial Handshake Packet
  // the client may use the first 8 byte of its 20-byte auth_plugin_data as input.
  // in the mean while, seed length should be equal to sig size
  auto len = sig.size() < expected_sig.size() ? sig.size() : expected_sig.size();
  for (int i = 0; i < len; i++) {
    if (sig[i] != expected_sig[i]) {
      return false;
    }
  }
  return true;
}
} // namespace MySQLProxy
} // namespace NetworkFilters
} // namespace Extensions
} // namespace Envoy
