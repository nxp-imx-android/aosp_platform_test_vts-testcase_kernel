#pragma once

#include <gtest/gtest.h>
#include <stdint.h>

#include <string>
#include <vector>

namespace android {
namespace kernel {

class Cipher {
 public:
  virtual ~Cipher() {}
  bool Encrypt(const std::vector<uint8_t> &key, const uint8_t *iv,
               const uint8_t *src, uint8_t *dst, int nbytes) const {
    if (key.size() != keysize()) {
      ADD_FAILURE() << "Bad key size";
      return false;
    }
    return DoEncrypt(key.data(), iv, src, dst, nbytes);
  }
  virtual bool DoEncrypt(const uint8_t *key, const uint8_t *iv,
                         const uint8_t *src, uint8_t *dst,
                         int nbytes) const = 0;
  virtual int keysize() const = 0;
  virtual int ivsize() const = 0;
};

// aes_256_xts.cpp

constexpr int kAesBlockSize = 16;
constexpr int kAes256KeySize = 32;
constexpr int kAes256XtsKeySize = 2 * kAes256KeySize;

class Aes256XtsCipher : public Cipher {
 public:
  bool DoEncrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *src,
                 uint8_t *dst, int nbytes) const;
  int keysize() const { return kAes256XtsKeySize; }
  int ivsize() const { return kAesBlockSize; }
};

// adiantum.cpp

constexpr int kAdiantumKeySize = 32;

// It's variable-length in general, but the Linux kernel always uses 32.
constexpr int kAdiantumIVSize = 32;

class AdiantumCipher : public Cipher {
 public:
  bool DoEncrypt(const uint8_t *key, const uint8_t *iv, const uint8_t *src,
                 uint8_t *dst, int nbytes) const;
  int keysize() const { return kAdiantumKeySize; }
  int ivsize() const { return kAdiantumIVSize; }
};

// utils.cpp

std::string Errno();

void RandomBytesForTesting(std::vector<uint8_t> &bytes);

std::vector<uint8_t> GenerateTestKey(size_t size);

std::string BytesToHex(const std::vector<uint8_t> &bytes);

template <size_t N>
static inline std::string BytesToHex(const uint8_t (&array)[N]) {
  return BytesToHex(std::vector<uint8_t>(&array[0], &array[N]));
}

bool GetFirstApiLevel(int *first_api_level);

bool FindRawPartition(const std::string &mountpoint,
                      std::string *raw_partition);

bool VerifyDataRandomness(const std::vector<uint8_t> &bytes);

}  // namespace kernel
}  // namespace android
