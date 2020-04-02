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

#include <android-base/properties.h>
#include <errno.h>
#include <fstab/fstab.h>
#include <gtest/gtest.h>

#include "vts_kernel_encryption.h"

namespace android {
namespace kernel {

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

}  // namespace kernel
}  // namespace android
