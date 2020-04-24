/*
 * Copyright (C) 2020 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// Utility functions for VtsKernelEncryptionTest.

#include <LzmaLib.h>
#include <android-base/properties.h>
#include <errno.h>
#include <fstab/fstab.h>
#include <gtest/gtest.h>

#include "Keymaster.h"
#include "vts_kernel_encryption.h"

namespace android {
namespace kernel {

// hw-wrapped key size in bytes
constexpr int kHwWrappedKeySize = 32;

std::string Errno() { return std::string(": ") + strerror(errno); }

// Generates some "random" bytes.  Not secure; this is for testing only.
void RandomBytesForTesting(std::vector<uint8_t> &bytes) {
  for (size_t i = 0; i < bytes.size(); i++) {
    bytes[i] = rand();
  }
}

// Generates a "random" key.  Not secure; this is for testing only.
std::vector<uint8_t> GenerateTestKey(size_t size) {
  std::vector<uint8_t> key(size);
  RandomBytesForTesting(key);
  return key;
}

std::string BytesToHex(const std::vector<uint8_t> &bytes) {
  std::ostringstream o;
  for (uint8_t b : bytes) {
    o << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  }
  return o.str();
}

bool GetFirstApiLevel(int *first_api_level) {
  *first_api_level =
      android::base::GetIntProperty("ro.product.first_api_level", 0);
  if (*first_api_level == 0) {
    ADD_FAILURE() << "ro.product.first_api_level is unset";
    return false;
  }
  GTEST_LOG_(INFO) << "ro.product.first_api_level = " << *first_api_level;
  return true;
}

// Finds the raw partition of the filesystem mounted on |mountpoint|.  This
// means the partition listed in the fstab, which for userdata with metadata
// encryption enabled will differ from the /proc/mounts block device.
bool FindRawPartition(const std::string &mountpoint,
                      std::string *raw_partition) {
  android::fs_mgr::Fstab fstab;
  if (!android::fs_mgr::ReadDefaultFstab(&fstab)) {
    ADD_FAILURE() << "Failed to read default fstab";
    return false;
  }
  const fs_mgr::FstabEntry *entry = GetEntryForMountPoint(&fstab, mountpoint);
  if (entry == nullptr) {
    ADD_FAILURE() << "No mountpoint entry for " << mountpoint;
    return false;
  }
  *raw_partition = entry->blk_device;
  GTEST_LOG_(INFO) << "Raw partition is " << *raw_partition;
  return true;
}

// Returns true if the given data seems to be random.
//
// Check compressibility rather than byte frequencies.  Compressibility is a
// stronger test since it also detects repetitions.
//
// To check compressibility, use LZMA rather than DEFLATE/zlib/gzip because LZMA
// compression is stronger and supports a much larger dictionary.  DEFLATE is
// limited to a 32 KiB dictionary.  So, data repeating after 32 KiB (or more)
// would not be detected with DEFLATE.  But LZMA can detect it.
bool VerifyDataRandomness(const std::vector<uint8_t> &bytes) {
  // To avoid flakiness, allow the data to be compressed a tiny bit by chance.
  // There is at most a 2^-32 chance that random data can be compressed to be 4
  // bytes shorter.  In practice it's even lower due to compression overhead.
  size_t destLen = bytes.size() - std::min<size_t>(4, bytes.size());
  std::vector<uint8_t> dest(destLen);
  uint8_t outProps[LZMA_PROPS_SIZE];
  size_t outPropsSize = LZMA_PROPS_SIZE;
  int ret;

  ret = LzmaCompress(dest.data(), &destLen, bytes.data(), bytes.size(),
                     outProps, &outPropsSize,
                     6,               // compression level (0 <= level <= 9)
                     bytes.size(),    // dictionary size
                     -1, -1, -1, -1,  // lc, lp, bp, fb (-1 selects the default)
                     1);              // number of threads

  if (ret == SZ_ERROR_OUTPUT_EOF) return true;  // incompressible

  if (ret == SZ_OK) {
    ADD_FAILURE() << "Data is not random!  Compressed " << bytes.size()
                  << " to " << destLen << " bytes";
  } else {
    ADD_FAILURE() << "LZMA compression error: ret=" << ret;
  }
  return false;
}

static bool TryPrepareHwWrappedKey(Keymaster &keymaster,
                                   const std::string &enc_key_string,
                                   std::string *exported_key_string,
                                   bool rollback_resistance) {
  // This key is used to drive a CMAC-based KDF
  auto paramBuilder =
      km::AuthorizationSetBuilder().AesEncryptionKey(kHwWrappedKeySize * 8);
  if (rollback_resistance) {
    paramBuilder.Authorization(km::TAG_ROLLBACK_RESISTANCE);
  }
  paramBuilder.Authorization(km::TAG_STORAGE_KEY);

  std::string wrapped_key_blob;
  if (keymaster.importKey(paramBuilder, km::KeyFormat::RAW, enc_key_string,
                          &wrapped_key_blob) &&
      keymaster.exportKey(wrapped_key_blob, exported_key_string)) {
    return true;
  }
  // It's fine for Keymaster not to support hardware-wrapped keys, but
  // if generateKey works, importKey must too.
  if (keymaster.generateKey(paramBuilder, &wrapped_key_blob) &&
      keymaster.exportKey(wrapped_key_blob, exported_key_string)) {
    ADD_FAILURE() << "generateKey succeeded but importKey failed";
  }
  return false;
}

bool CreateHwWrappedKey(std::vector<uint8_t> *enc_key,
                        std::vector<uint8_t> *exported_key) {
  *enc_key = GenerateTestKey(kHwWrappedKeySize);

  Keymaster keymaster;
  if (!keymaster) {
    ADD_FAILURE() << "Unable to find keymaster";
    return false;
  }
  std::string enc_key_string(enc_key->begin(), enc_key->end());
  std::string exported_key_string;
  // Make two attempts to create a key, first with and then without
  // rollback resistance.
  if (TryPrepareHwWrappedKey(keymaster, enc_key_string, &exported_key_string,
                             true) ||
      TryPrepareHwWrappedKey(keymaster, enc_key_string, &exported_key_string,
                             false)) {
    exported_key->assign(exported_key_string.begin(),
                         exported_key_string.end());
    return true;
  }
  GTEST_LOG_(INFO) << "Skipping test because device doesn't support "
                      "hardware-wrapped keys";
  return false;
}

}  // namespace kernel
}  // namespace android
