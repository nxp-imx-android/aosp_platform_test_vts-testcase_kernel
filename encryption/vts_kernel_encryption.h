#pragma once

#include <stdint.h>

namespace android {
namespace kernel {

constexpr int kAesBlockSize = 16;
constexpr int kAes256KeySize = 32;
constexpr int kAes256XtsKeySize = 2 * kAes256KeySize;

bool Aes256XtsEncrypt(const uint8_t key[kAes256XtsKeySize],
                      const uint8_t iv[kAesBlockSize], const uint8_t *src,
                      uint8_t *dst, int nbytes);

constexpr int kAdiantumKeySize = 32;

// It's variable-length in general, but the Linux kernel always uses 32.
constexpr int kAdiantumIVSize = 32;

bool AdiantumEncrypt(const uint8_t key[kAdiantumKeySize],
                     const uint8_t iv[kAdiantumIVSize], const uint8_t *src,
                     uint8_t *dst, int nbytes);

}  // namespace kernel
}  // namespace android
