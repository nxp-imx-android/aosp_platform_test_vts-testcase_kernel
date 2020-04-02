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

//
// Test that metadata encryption with dm-default-key is working correctly.
//
// To do this, we create a temporary default-key mapping over the raw userdata
// partition, read from it, and verify that the data got decrypted correctly.
// We only test decryption, since this avoids having to find a region on disk
// that can safely be modified.  This should be good enough since the device
// wouldn't work anyway if decryption didn't invert encryption.
//
// Note that this temporary default-key mapping will overlap the device's "real"
// default-key mapping, if the device has one.  The kernel allows this.
//
// We don't use a loopback device, since dm-default-key over a loopback device
// can't use the real inline encryption hardware.
//
// Currently, we test parameters matching the following fstab settings:
//
//    metadata_encryption=aes-256-xts
//    metadata_encryption=adiantum
//
// We don't currently test hardware-wrapped keys ("wrappedkey_v0").
//
// We don't currently check which one of these settings, if any, the device is
// actually using; we just try to test everything we can.
//
// Also, we don't specifically test that file contents aren't encrypted twice.
// That's already implied by the file-based encryption test cases, provided that
// the device actually has metadata encryption enabled.
//

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <asm/byteorder.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <libdm/dm.h>
#include <linux/types.h>
#include <stdlib.h>
#include <unistd.h>

#include <chrono>

#include "vts_kernel_encryption.h"

using namespace android::dm;

namespace android {
namespace kernel {

#define cpu_to_le64 __cpu_to_le64
#define le64_to_cpu __le64_to_cpu

// Name to assign to the dm-default-key test device
constexpr const char *kTestDmDeviceName = "vts-test-default-key";

// Filesystem whose underlying partition the test will use
constexpr const char *kTestMountpoint = "/data";

// Size of the dm-default-key crypto sector size (data unit size) in bytes
constexpr int kCryptoSectorSize = 4096;

// Size of the test data in crypto sectors
constexpr int kTestDataSectors = 256;

// Size of the test data in bytes
constexpr int kTestDataBytes = kTestDataSectors * kCryptoSectorSize;

// Device-mapper API sector size in bytes.
// This is unrelated to the crypto sector size.
constexpr int kDmApiSectorSize = 512;

// Checks whether the kernel supports version 2 or higher of dm-default-key.
static bool IsDmDefaultKeyV2Supported(DeviceMapper &dm) {
  DmTargetTypeInfo info;
  if (!dm.GetTargetByName("default-key", &info)) {
    GTEST_LOG_(INFO) << "dm-default-key not enabled";
    return false;
  }
  if (!info.IsAtLeast(2, 0, 0)) {
    // The legacy version of dm-default-key (which was never supported by the
    // Android common kernels) used a vendor-specific on-disk format, so it's
    // not testable by a vendor-independent test.
    GTEST_LOG_(INFO) << "Detected legacy dm-default-key";
    return false;
  }
  return true;
}

class MetadataEncryptionTest : public ::testing::Test {
 protected:
  void SetUp() override;
  void TearDown() override;
  bool CreateTestDevice(const std::string &cipher,
                        const std::vector<uint8_t> &key);
  void VerifyDecryption(const std::vector<uint8_t> &key, const Cipher &cipher);
  void DoTest(const std::string &cipher_string, const Cipher &cipher);
  bool skip_test_ = false;
  DeviceMapper *dm_ = nullptr;
  std::string raw_partition_;
  std::string dm_device_path_;
};

// Test setup procedure.  Checks for the needed kernel support, finds the raw
// partition to use, and does other preparations.  skip_test_ is set to true if
// the test should be skipped.
void MetadataEncryptionTest::SetUp() {
  dm_ = &DeviceMapper::Instance();

  if (!IsDmDefaultKeyV2Supported(*dm_)) {
    int first_api_level;
    ASSERT_TRUE(GetFirstApiLevel(&first_api_level));
    // Devices launching with R or higher must support dm-default-key v2.
    ASSERT_LE(first_api_level, __ANDROID_API_Q__);
    GTEST_LOG_(INFO)
        << "Skipping test because dm-default-key v2 is unsupported";
    skip_test_ = true;
    return;
  }

  ASSERT_TRUE(FindRawPartition(kTestMountpoint, &raw_partition_));

  dm_->DeleteDevice(kTestDmDeviceName);
}

void MetadataEncryptionTest::TearDown() {
  dm_->DeleteDevice(kTestDmDeviceName);
}

// Creates the test dm-default-key mapping using the given |cipher| and |key|.
// If the dm device creation fails, then it is assumed the kernel doesn't
// support the given cipher with dm-default-key, and a failure is not added.
bool MetadataEncryptionTest::CreateTestDevice(const std::string &cipher,
                                              const std::vector<uint8_t> &key) {
  static_assert(kTestDataBytes % kDmApiSectorSize == 0);
  std::unique_ptr<DmTargetDefaultKey> target =
      std::make_unique<DmTargetDefaultKey>(0, kTestDataBytes / kDmApiSectorSize,
                                           cipher.c_str(), BytesToHex(key),
                                           raw_partition_, 0);
  target->SetSetDun();

  DmTable table;
  if (!table.AddTarget(std::move(target))) {
    ADD_FAILURE() << "Failed to add default-key target to table";
    return false;
  }
  if (!table.valid()) {
    ADD_FAILURE() << "Device-mapper table failed to validate";
    return false;
  }
  if (!dm_->CreateDevice(kTestDmDeviceName, table, &dm_device_path_,
                         std::chrono::seconds(5))) {
    GTEST_LOG_(INFO) << "Unable to create default-key mapping" << Errno()
                     << ".  Assuming that the cipher \"" << cipher
                     << "\" is unsupported and skipping the test.";
    return false;
  }
  GTEST_LOG_(INFO) << "Created default-key mapping at " << dm_device_path_
                   << " using cipher \"" << cipher << "\" and key "
                   << BytesToHex(key);
  return true;
}

void MetadataEncryptionTest::VerifyDecryption(const std::vector<uint8_t> &key,
                                              const Cipher &cipher) {
  // Read some raw data, using direct I/O to avoid getting any stale cached
  // data.  Direct I/O requires using a hardware sector size aligned buffer.
  // Aligning to kCryptoSectorSize is good enough.

  GTEST_LOG_(INFO) << "Reading raw data from " << raw_partition_;
  std::unique_ptr<void, void (*)(void *)> raw_data_mem(
      aligned_alloc(kCryptoSectorSize, kTestDataBytes), free);
  ASSERT_TRUE(raw_data_mem != nullptr);
  uint8_t *raw_data = static_cast<uint8_t *>(raw_data_mem.get());

  android::base::unique_fd raw_fd(
      open(raw_partition_.c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC));
  ASSERT_GE(raw_fd, 0) << "Failed to open raw partition " << raw_partition_
                       << Errno();
  ASSERT_TRUE(android::base::ReadFully(raw_fd, raw_data, kTestDataBytes))
      << "Failed to read from raw partition " << raw_partition_ << Errno();

  // Read the corresponding decrypted data.
  GTEST_LOG_(INFO) << "Reading decrypted data from " << dm_device_path_;
  std::vector<uint8_t> decrypted_data(kTestDataBytes);
  android::base::unique_fd dm_fd(
      open(dm_device_path_.c_str(), O_RDONLY | O_CLOEXEC));
  ASSERT_GE(dm_fd, 0) << "Failed to open test dm device " << dm_device_path_
                      << Errno();
  ASSERT_TRUE(
      android::base::ReadFully(dm_fd, decrypted_data.data(), kTestDataBytes))
      << "Failed to read from default-key mapping " << dm_device_path_
      << Errno();

  // Verify that the decrypted data encrypts to the raw data.

  GTEST_LOG_(INFO) << "Verifying correctness of decrypted data";

  // Initialize the IV for crypto sector 0.
  ASSERT_GE(cipher.ivsize(), sizeof(__le64));
  std::unique_ptr<__le64> iv(new (::operator new(cipher.ivsize())) __le64);
  memset(iv.get(), 0, cipher.ivsize());

  std::vector<uint8_t> encrypted_sector(kCryptoSectorSize);
  static_assert(kTestDataBytes % kCryptoSectorSize == 0);

  for (size_t i = 0; i < kTestDataBytes; i += kCryptoSectorSize) {
    ASSERT_TRUE(cipher.Encrypt(key, reinterpret_cast<const uint8_t *>(iv.get()),
                               &decrypted_data[i], encrypted_sector.data(),
                               kCryptoSectorSize));
    std::vector<uint8_t> raw_sector(raw_data + i,
                                    raw_data + i + kCryptoSectorSize);
    ASSERT_EQ(encrypted_sector, raw_sector);

    // Update the IV by incrementing the crypto sector number.
    *iv = cpu_to_le64(le64_to_cpu(*iv) + 1);
  }
}

void MetadataEncryptionTest::DoTest(const std::string &cipher_string,
                                    const Cipher &cipher) {
  if (skip_test_) return;

  std::vector<uint8_t> key = GenerateTestKey(cipher.keysize());

  if (!CreateTestDevice(cipher_string, key)) return;

  VerifyDecryption(key, cipher);
}

// Tests dm-default-key parameters matching metadata_encryption=aes-256-xts.
TEST_F(MetadataEncryptionTest, TestAes256Xts) {
  DoTest("aes-xts-plain64", Aes256XtsCipher());
}

// Tests dm-default-key parameters matching metadata_encryption=adiantum.
TEST_F(MetadataEncryptionTest, TestAdiantum) {
  DoTest("xchacha12,aes-adiantum-plain64", AdiantumCipher());
}

}  // namespace kernel
}  // namespace android
