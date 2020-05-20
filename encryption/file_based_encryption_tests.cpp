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
// Test that file contents encryption is working, via:
//
// - Correctness tests.  These test the standard FBE settings supported by
//   Android R and higher.
//
// - Randomness test.  This runs on all devices that use FBE, even old ones.
//
// The correctness tests cover the following settings:
//
//    fileencryption=aes-256-xts:aes-256-cts:v2
//    fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized
//    fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0
//    fileencryption=adiantum:adiantum:v2
//
// On devices launching with R or higher those are equivalent to simply:
//
//    fileencryption=
//    fileencryption=::inlinecrypt_optimized
//    fileencryption=::inlinecrypt_optimized+wrappedkey_v0
//    fileencryption=adiantum
//
// The tests don't check which one of those settings, if any, the device is
// actually using; they just try to test everything they can.
// "fileencryption=aes-256-xts" is guaranteed to be available if the kernel
// supports any "fscrypt v2" features at all.  The others may not be available,
// so the tests take that into account and skip testing them when unavailable.
//
// None of these tests should ever fail.  In particular, vendors must not break
// any standard FBE settings, regardless of what the device actually uses.  If
// any test fails, make sure to check things like the byte order of keys.
//

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/unique_fd.h>
#include <asm/byteorder.h>
#include <errno.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <limits.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "vts_kernel_encryption.h"

#ifndef F2FS_IOCTL_MAGIC
#define F2FS_IOCTL_MAGIC 0xf5
#endif
#ifndef F2FS_IOC_SET_PIN_FILE
#define F2FS_IOC_SET_PIN_FILE _IOW(F2FS_IOCTL_MAGIC, 13, __u32)
#endif

#ifndef FS_IOC_GET_ENCRYPTION_NONCE
#define FS_IOC_GET_ENCRYPTION_NONCE _IOR('f', 27, __u8[16])
#endif

namespace android {
namespace kernel {

// Assumed size of filesystem blocks, in bytes
constexpr int kFilesystemBlockSize = 4096;

// Size of the test file in filesystem blocks
constexpr int kTestFileBlocks = 256;

// Size of the test file in bytes
constexpr int kTestFileBytes = kFilesystemBlockSize * kTestFileBlocks;

// fscrypt master key size in bytes
constexpr int kFscryptMasterKeySize = 64;

// fscrypt maximum IV size in bytes
constexpr int kFscryptMaxIVSize = 32;

// fscrypt per-file nonce size in bytes
constexpr int kFscryptFileNonceSize = 16;

// fscrypt HKDF context bytes, from kernel fs/crypto/fscrypt_private.h
enum FscryptHkdfContext {
  HKDF_CONTEXT_KEY_IDENTIFIER = 1,
  HKDF_CONTEXT_PER_FILE_ENC_KEY = 2,
  HKDF_CONTEXT_DIRECT_KEY = 3,
  HKDF_CONTEXT_IV_INO_LBLK_64_KEY = 4,
  HKDF_CONTEXT_DIRHASH_KEY = 5,
};

struct FscryptFileNonce {
  uint8_t bytes[kFscryptFileNonceSize];
};

// Format of the initialization vector
union FscryptIV {
  struct {
    __le32 lblk_num;      // file logical block number, starts at 0
    __le32 inode_number;  // only used for IV_INO_LBLK_64
    uint8_t file_nonce[kFscryptFileNonceSize];  // only used for DIRECT_KEY
  };
  uint8_t bytes[kFscryptMaxIVSize];
};

struct TestFileInfo {
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> actual_ciphertext;
  uint64_t inode_number;
  FscryptFileNonce nonce;
};

//
// Checks whether the kernel has support for the following fscrypt features:
//
// - Filesystem-level keyring (FS_IOC_ADD_ENCRYPTION_KEY and
//   FS_IOC_REMOVE_ENCRYPTION_KEY)
// - v2 encryption policies
// - The IV_INO_LBLK_64 encryption policy flag
// - The FS_IOC_GET_ENCRYPTION_NONCE ioctl
//
// To do this it's sufficient to just check whether FS_IOC_ADD_ENCRYPTION_KEY is
// available, as the other features were added in the same AOSP release.
//
// The easiest way to do this is to just execute the ioctl with a NULL argument.
// If available it will fail with EFAULT; otherwise it will fail with ENOTTY.
//
static bool IsFscryptV2Supported(const std::string &mountpoint) {
  android::base::unique_fd fd(
      open(mountpoint.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (fd < 0) {
    ADD_FAILURE() << "Failed to open " << mountpoint << Errno();
    return false;
  }

  if (ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, nullptr) == 0) {
    ADD_FAILURE()
        << "FS_IOC_ADD_ENCRYPTION_KEY(nullptr) unexpectedly succeeded on "
        << mountpoint;
    return false;
  }
  switch (errno) {
    case EFAULT:
      return true;
    case ENOTTY:
      GTEST_LOG_(INFO) << "No support for FS_IOC_ADD_ENCRYPTION_KEY on "
                       << mountpoint;
      return false;
    default:
      ADD_FAILURE()
          << "Unexpected error from FS_IOC_ADD_ENCRYPTION_KEY(nullptr) on "
          << mountpoint << Errno();
      return false;
  }
}

// Helper class to pin / unpin a file on f2fs, to prevent f2fs from moving the
// file's blocks while the test is accessing them via the underlying device.
//
// This can be used without checking the filesystem type, since on other
// filesystem types F2FS_IOC_SET_PIN_FILE will just fail and do nothing.
class ScopedF2fsFilePinning {
 public:
  explicit ScopedF2fsFilePinning(int fd) : fd_(fd) {
    __u32 set = 1;
    ioctl(fd_, F2FS_IOC_SET_PIN_FILE, &set);
  }

  ~ScopedF2fsFilePinning() {
    __u32 set = 0;
    ioctl(fd_, F2FS_IOC_SET_PIN_FILE, &set);
  }

 private:
  int fd_;
};

// Reads the raw data of the file specified by |fd| from its underlying block
// device |blk_device|.  The file is |expected_file_size| bytes long; this is
// assumed to be a multiple of the filesystem block size kFilesystemBlockSize.
static bool ReadRawDataOfFile(int fd, const std::string &blk_device,
                              int expected_file_size,
                              std::vector<uint8_t> *raw_data) {
  int max_extents = expected_file_size / kFilesystemBlockSize;

  EXPECT_TRUE(expected_file_size % kFilesystemBlockSize == 0);

  // It's not entirely clear how F2FS_IOC_SET_PIN_FILE interacts with dirty
  // data, so do an extra sync here and don't just rely on FIEMAP_FLAG_SYNC.
  if (fsync(fd) != 0) {
    ADD_FAILURE() << "Failed to sync file" << Errno();
    return false;
  }

  ScopedF2fsFilePinning pinned_file(fd);  // no-op on non-f2fs

  // Query the file's extents.
  size_t allocsize = offsetof(struct fiemap, fm_extents[max_extents]);
  std::unique_ptr<struct fiemap> map(
      new (::operator new(allocsize)) struct fiemap);
  memset(map.get(), 0, allocsize);
  map->fm_flags = FIEMAP_FLAG_SYNC;
  map->fm_length = expected_file_size;
  map->fm_extent_count = max_extents;
  if (ioctl(fd, FS_IOC_FIEMAP, map.get()) != 0) {
    ADD_FAILURE() << "Failed to get extents of file" << Errno();
    return false;
  }

  // Read the raw data, using direct I/O to avoid getting any stale cached data.
  // Direct I/O requires using a block size aligned buffer.

  std::unique_ptr<void, void (*)(void *)> buf_mem(
      aligned_alloc(kFilesystemBlockSize, expected_file_size), free);
  if (buf_mem == nullptr) {
    ADD_FAILURE() << "Out of memory";
    return false;
  }
  uint8_t *buf = static_cast<uint8_t *>(buf_mem.get());
  int offset = 0;

  android::base::unique_fd blk_fd(
      open(blk_device.c_str(), O_RDONLY | O_DIRECT | O_CLOEXEC));
  if (blk_fd < 0) {
    ADD_FAILURE() << "Failed to open raw block device " << blk_device
                  << Errno();
    return false;
  }

  for (int i = 0; i < map->fm_mapped_extents; i++) {
    const struct fiemap_extent &extent = map->fm_extents[i];

    GTEST_LOG_(INFO) << "Extent " << i + 1 << " of " << map->fm_mapped_extents
                     << " is logical offset " << extent.fe_logical
                     << ", physical offset " << extent.fe_physical
                     << ", length " << extent.fe_length << ", flags 0x"
                     << std::hex << extent.fe_flags << std::dec;
    // Make sure the flags indicate that fe_physical is actually valid.
    if (extent.fe_flags & (FIEMAP_EXTENT_UNKNOWN | FIEMAP_EXTENT_UNWRITTEN)) {
      ADD_FAILURE() << "Unsupported extent flags: 0x" << std::hex
                    << extent.fe_flags << std::dec;
      return false;
    }
    if (extent.fe_length % kFilesystemBlockSize != 0) {
      ADD_FAILURE() << "Extent is not aligned to filesystem block size";
      return false;
    }
    if (extent.fe_length > expected_file_size - offset) {
      ADD_FAILURE() << "File is longer than expected";
      return false;
    }
    if (pread(blk_fd, &buf[offset], extent.fe_length, extent.fe_physical) !=
        extent.fe_length) {
      ADD_FAILURE() << "Error reading raw data from block device" << Errno();
      return false;
    }
    offset += extent.fe_length;
  }
  if (offset != expected_file_size) {
    ADD_FAILURE() << "File is shorter than expected";
    return false;
  }
  *raw_data = std::vector<uint8_t>(&buf[0], &buf[offset]);
  return true;
}

// Writes |plaintext| to a file |path| located on the block device |blk_device|.
// Returns in |ciphertext| the file's raw ciphertext read from |blk_device|.
static bool WriteTestFile(const std::vector<uint8_t> &plaintext,
                          const std::string &path,
                          const std::string &blk_device,
                          std::vector<uint8_t> *ciphertext) {
  GTEST_LOG_(INFO) << "Creating test file " << path << " containing "
                   << plaintext.size() << " bytes of data";
  android::base::unique_fd fd(
      open(path.c_str(), O_WRONLY | O_CREAT | O_CLOEXEC, 0600));
  if (fd < 0) {
    ADD_FAILURE() << "Failed to create " << path << Errno();
    return false;
  }
  if (!android::base::WriteFully(fd, plaintext.data(), plaintext.size())) {
    ADD_FAILURE() << "Error writing to " << path << Errno();
    return false;
  }

  GTEST_LOG_(INFO) << "Reading the raw ciphertext of " << path << " from disk";
  if (!ReadRawDataOfFile(fd, blk_device, plaintext.size(), ciphertext)) {
    ADD_FAILURE() << "Failed to read the raw ciphertext of " << path;
    return false;
  }
  return true;
}

class FBEPolicyTest : public ::testing::Test {
 protected:
  // Location of the test directory and file.  Since it's not possible to
  // override an existing encryption policy, in order for these tests to set
  // their own encryption policy the parent directory must be unencrypted.
  static constexpr const char *kTestMountpoint = "/data";
  static constexpr const char *kTestDir = "/data/unencrypted/vts-test-dir";
  static constexpr const char *kTestFile =
      "/data/unencrypted/vts-test-dir/file";

  void SetUp() override;
  void TearDown() override;
  void RemoveTestDirectory();
  bool SetMasterKey(const std::vector<uint8_t> &master_key, uint32_t flags = 0,
                    bool required = true);
  bool SetEncryptionPolicy(int contents_mode, int filenames_mode, int flags,
                           bool required);
  bool GenerateTestFile(TestFileInfo *info);
  bool DeriveEncryptionKey(const std::vector<uint8_t> &master_key,
                           const std::vector<uint8_t> &hdkf_info,
                           std::vector<uint8_t> &enc_key);
  bool DerivePerModeEncryptionKey(const std::vector<uint8_t> &master_key,
                                  int mode, FscryptHkdfContext context,
                                  std::vector<uint8_t> &enc_key);
  bool DerivePerFileEncryptionKey(const std::vector<uint8_t> &master_key,
                                  const FscryptFileNonce &nonce,
                                  std::vector<uint8_t> &enc_key);
  void VerifyCiphertext(const std::vector<uint8_t> &enc_key,
                        const FscryptIV &starting_iv, const Cipher &cipher,
                        const TestFileInfo &file_info);
  struct fscrypt_key_specifier master_key_specifier_;
  bool skip_test_ = false;
  bool key_added_ = false;
  FilesystemInfo fs_info_;
};

// Test setup procedure.  Creates a test directory kTestDir and does other
// preparations. skip_test_ is set to true if the test should be skipped.
void FBEPolicyTest::SetUp() {
  if (!IsFscryptV2Supported(kTestMountpoint)) {
    int first_api_level;
    ASSERT_TRUE(GetFirstApiLevel(&first_api_level));
    // Devices launching with R or higher must support fscrypt v2.
    ASSERT_LE(first_api_level, __ANDROID_API_Q__);
    GTEST_LOG_(INFO) << "Skipping test because fscrypt v2 is unsupported";
    skip_test_ = true;
    return;
  }

  ASSERT_TRUE(GetFilesystemInfo(kTestMountpoint, &fs_info_));

  RemoveTestDirectory();
  if (mkdir(kTestDir, 0700) != 0) {
    FAIL() << "Failed to create " << kTestDir << Errno();
  }
}

void FBEPolicyTest::TearDown() {
  RemoveTestDirectory();

  // Remove the test key from kTestMountpoint.
  if (key_added_) {
    android::base::unique_fd mntfd(
        open(kTestMountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (mntfd < 0) {
      FAIL() << "Failed to open " << kTestMountpoint << Errno();
    }
    struct fscrypt_remove_key_arg arg;
    memset(&arg, 0, sizeof(arg));
    arg.key_spec = master_key_specifier_;

    if (ioctl(mntfd, FS_IOC_REMOVE_ENCRYPTION_KEY, &arg) != 0) {
      FAIL() << "FS_IOC_REMOVE_ENCRYPTION_KEY failed on " << kTestMountpoint
             << Errno();
    }
  }
}

void FBEPolicyTest::RemoveTestDirectory() {
  if (unlink(kTestFile) != 0 && errno != ENOENT && errno != ENOPKG) {
    FAIL() << "Failed to remove file " << kTestFile << Errno();
  }
  if (rmdir(kTestDir) != 0 && errno != ENOENT) {
    FAIL() << "Failed to remove directory " << kTestDir << Errno();
  }
}

// Adds |master_key| to kTestMountpoint and places the resulting key identifier
// in master_key_specifier_.
bool FBEPolicyTest::SetMasterKey(const std::vector<uint8_t> &master_key,
                                 uint32_t flags, bool required) {
  size_t allocsize = sizeof(struct fscrypt_add_key_arg) + master_key.size();
  std::unique_ptr<struct fscrypt_add_key_arg> arg(
      new (::operator new(allocsize)) struct fscrypt_add_key_arg);
  memset(arg.get(), 0, allocsize);
  arg->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
  arg->__flags = flags;
  arg->raw_size = master_key.size();
  std::copy(master_key.begin(), master_key.end(), arg->raw);

  GTEST_LOG_(INFO) << "Adding fscrypt master key, flags are 0x" << std::hex
                   << flags << std::dec << ", raw bytes are "
                   << BytesToHex(master_key);
  android::base::unique_fd mntfd(
      open(kTestMountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (mntfd < 0) {
    ADD_FAILURE() << "Failed to open " << kTestMountpoint << Errno();
    return false;
  }
  if (ioctl(mntfd, FS_IOC_ADD_ENCRYPTION_KEY, arg.get()) != 0) {
    if ((errno == EINVAL || errno == EOPNOTSUPP) && !required) {
      GTEST_LOG_(INFO) << "Skipping test because FS_IOC_ADD_ENCRYPTION_KEY "
                       << "with this key is unsupported" << Errno();
    } else {
      ADD_FAILURE() << "FS_IOC_ADD_ENCRYPTION_KEY failed on " << kTestMountpoint
                    << Errno();
    }
    return false;
  }
  master_key_specifier_ = arg->key_spec;
  GTEST_LOG_(INFO) << "Master key identifier is "
                   << BytesToHex(master_key_specifier_.u.identifier);
  key_added_ = true;
  return true;
}

// Sets a v2 encryption policy on the test directory.  The policy will use the
// test key and the specified encryption modes and flags.  If required=false,
// then a failure won't be added if the kernel doesn't support the policy.
bool FBEPolicyTest::SetEncryptionPolicy(int contents_mode, int filenames_mode,
                                        int flags, bool required) {
  if (!key_added_) {
    ADD_FAILURE() << "SetEncryptionPolicy called but no key added";
    return false;
  }

  struct fscrypt_policy_v2 policy;
  memset(&policy, 0, sizeof(policy));
  policy.version = FSCRYPT_POLICY_V2;
  policy.contents_encryption_mode = contents_mode;
  policy.filenames_encryption_mode = filenames_mode;
  // Always give PAD_16, to match the policies that Android sets for real.
  // It doesn't affect contents encryption, though.
  policy.flags = flags | FSCRYPT_POLICY_FLAGS_PAD_16;
  memcpy(policy.master_key_identifier, master_key_specifier_.u.identifier,
         FSCRYPT_KEY_IDENTIFIER_SIZE);

  android::base::unique_fd dirfd(
      open(kTestDir, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (dirfd < 0) {
    ADD_FAILURE() << "Failed to open " << kTestDir << Errno();
    return false;
  }
  GTEST_LOG_(INFO) << "Setting encryption policy on " << kTestDir;
  if (ioctl(dirfd, FS_IOC_SET_ENCRYPTION_POLICY, &policy) != 0) {
    if (errno == EINVAL && !required) {
      GTEST_LOG_(INFO) << "Skipping test because encryption policy is "
                          "unsupported on this filesystem / kernel";
      return false;
    }
    ADD_FAILURE() << "FS_IOC_SET_ENCRYPTION_POLICY failed on " << kTestDir
                  << " using contents_mode=" << contents_mode
                  << ", filenames_mode=" << filenames_mode << ", flags=0x"
                  << std::hex << flags << std::dec << Errno();
    return false;
  }
  if (!required) {
    // Setting an encryption policy that uses modes that aren't enabled in the
    // kernel's crypto API (e.g. FSCRYPT_MODE_ADIANTUM when the kernel lacks
    // CONFIG_CRYPTO_ADIANTUM) will still succeed, but actually creating a file
    // will fail with ENOPKG.  Make sure to check for this case.
    android::base::unique_fd fd(
        open(kTestFile, O_WRONLY | O_CREAT | O_CLOEXEC, 0600));
    if (fd < 0 && errno == ENOPKG) {
      GTEST_LOG_(INFO)
          << "Skipping test because encryption policy is "
             "unsupported on this kernel, due to missing crypto API support";
      return false;
    }
    unlink(kTestFile);
  }
  return true;
}

// Generates some test data, writes it to a file in the test directory, and
// returns in |info| the file's plaintext, the file's raw ciphertext read from
// disk, and other information about the file.
bool FBEPolicyTest::GenerateTestFile(TestFileInfo *info) {
  info->plaintext.resize(kTestFileBytes);
  RandomBytesForTesting(info->plaintext);

  if (!WriteTestFile(info->plaintext, kTestFile, fs_info_.raw_blk_device,
                     &info->actual_ciphertext))
    return false;

  android::base::unique_fd fd(open(kTestFile, O_RDONLY | O_CLOEXEC));
  if (fd < 0) {
    ADD_FAILURE() << "Failed to open " << kTestFile << Errno();
    return false;
  }

  // Get the file's inode number.
  struct stat stbuf;
  if (fstat(fd, &stbuf) != 0) {
    ADD_FAILURE() << "Failed to stat " << kTestFile << Errno();
    return false;
  }
  info->inode_number = stbuf.st_ino;
  GTEST_LOG_(INFO) << "Inode number: " << info->inode_number;

  // Get the file's nonce.
  if (ioctl(fd, FS_IOC_GET_ENCRYPTION_NONCE, info->nonce.bytes) != 0) {
    ADD_FAILURE() << "FS_IOC_GET_ENCRYPTION_NONCE failed on " << kTestFile
                  << Errno();
    return false;
  }
  GTEST_LOG_(INFO) << "File nonce: " << BytesToHex(info->nonce.bytes);
  return true;
}

static std::vector<uint8_t> InitHkdfInfo(FscryptHkdfContext context) {
  return {
      'f', 's', 'c', 'r', 'y', 'p', 't', '\0', static_cast<uint8_t>(context)};
}

bool FBEPolicyTest::DeriveEncryptionKey(const std::vector<uint8_t> &master_key,
                                        const std::vector<uint8_t> &hkdf_info,
                                        std::vector<uint8_t> &out) {
  if (HKDF(out.data(), out.size(), EVP_sha512(), master_key.data(),
           master_key.size(), nullptr, 0, hkdf_info.data(),
           hkdf_info.size()) != 1) {
    ADD_FAILURE() << "BoringSSL HKDF-SHA512 call failed";
    return false;
  }
  GTEST_LOG_(INFO) << "Derived encryption key " << BytesToHex(out)
                   << " using HKDF info " << BytesToHex(hkdf_info);
  return true;
}

// Derives a per-mode encryption key from |master_key|, |mode|, |context|, and
// (if needed for the context) the filesystem UUID.
bool FBEPolicyTest::DerivePerModeEncryptionKey(
    const std::vector<uint8_t> &master_key, int mode,
    FscryptHkdfContext context, std::vector<uint8_t> &enc_key) {
  std::vector<uint8_t> hkdf_info = InitHkdfInfo(context);

  hkdf_info.push_back(mode);
  if (context == HKDF_CONTEXT_IV_INO_LBLK_64_KEY)
    hkdf_info.insert(hkdf_info.end(), fs_info_.uuid.bytes,
                     std::end(fs_info_.uuid.bytes));

  return DeriveEncryptionKey(master_key, hkdf_info, enc_key);
}

// Derives a per-file encryption key from |master_key| and |nonce|.
bool FBEPolicyTest::DerivePerFileEncryptionKey(
    const std::vector<uint8_t> &master_key, const FscryptFileNonce &nonce,
    std::vector<uint8_t> &enc_key) {
  std::vector<uint8_t> hkdf_info = InitHkdfInfo(HKDF_CONTEXT_PER_FILE_ENC_KEY);

  hkdf_info.insert(hkdf_info.end(), nonce.bytes, std::end(nonce.bytes));

  return DeriveEncryptionKey(master_key, hkdf_info, enc_key);
}

void FBEPolicyTest::VerifyCiphertext(const std::vector<uint8_t> &enc_key,
                                     const FscryptIV &starting_iv,
                                     const Cipher &cipher,
                                     const TestFileInfo &file_info) {
  const std::vector<uint8_t> &plaintext = file_info.plaintext;

  GTEST_LOG_(INFO) << "Verifying correctness of encrypted data";
  FscryptIV iv = starting_iv;

  std::vector<uint8_t> computed_ciphertext(plaintext.size());

  // Encrypt each filesystem block of file contents.
  for (size_t i = 0; i < plaintext.size(); i += kFilesystemBlockSize) {
    int block_size =
        std::min<size_t>(kFilesystemBlockSize, plaintext.size() - i);

    ASSERT_GE(sizeof(iv.bytes), cipher.ivsize());
    ASSERT_TRUE(cipher.Encrypt(enc_key, iv.bytes, &plaintext[i],
                               &computed_ciphertext[i], block_size));

    // Update the IV by incrementing the file logical block number.
    iv.lblk_num = __cpu_to_le32(__le32_to_cpu(iv.lblk_num) + 1);
    ASSERT_NE(__le32_to_cpu(iv.lblk_num), 0);
  }

  ASSERT_EQ(file_info.actual_ciphertext, computed_ciphertext);
}

// Tests a policy matching fileencryption=aes-256-xts:aes-256-cts:v2
// (or simply fileencryption= on devices launched with R or higher)
TEST_F(FBEPolicyTest, TestAesV2Policy) {
  if (skip_test_) return;

  auto master_key = GenerateTestKey(kFscryptMasterKeySize);
  ASSERT_TRUE(SetMasterKey(master_key));

  if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
                           0, true))
    return;

  TestFileInfo file_info;
  ASSERT_TRUE(GenerateTestFile(&file_info));

  std::vector<uint8_t> enc_key(kAes256XtsKeySize);
  ASSERT_TRUE(DerivePerFileEncryptionKey(master_key, file_info.nonce, enc_key));

  FscryptIV iv;
  memset(&iv, 0, sizeof(iv));

  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
}

// Tests a policy matching
// fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized
// (or simply fileencryption=::inlinecrypt_optimized on
// devices launched with R or higher)
TEST_F(FBEPolicyTest, TestAesV2InlineCryptOptimizedPolicy) {
  if (skip_test_) return;

  auto master_key = GenerateTestKey(kFscryptMasterKeySize);
  ASSERT_TRUE(SetMasterKey(master_key));

  // On ext4, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 is only supported when the
  // filesystem has EXT4_FEATURE_COMPAT_STABLE_INODES, which only happens when
  // inlinecrypt_optimized is selected in the fstab.  So we don't require
  // setting this type of policy to work on ext4.
  if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
                           FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
                           fs_info_.type != "ext4"))
    return;

  TestFileInfo file_info;
  ASSERT_TRUE(GenerateTestFile(&file_info));

  std::vector<uint8_t> enc_key(kAes256XtsKeySize);
  ASSERT_TRUE(DerivePerModeEncryptionKey(master_key, FSCRYPT_MODE_AES_256_XTS,
                                         HKDF_CONTEXT_IV_INO_LBLK_64_KEY,
                                         enc_key));

  FscryptIV iv;
  memset(&iv, 0, sizeof(iv));
  ASSERT_LE(file_info.inode_number, UINT32_MAX);
  iv.inode_number = __cpu_to_le32(file_info.inode_number);

  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
}

// Tests a policy matching fileencryption=adiantum:adiantum:v2 (or simply
// fileencryption=adiantum on devices launched with R or higher)
TEST_F(FBEPolicyTest, TestAdiantumV2Policy) {
  if (skip_test_) return;

  auto master_key = GenerateTestKey(kFscryptMasterKeySize);
  ASSERT_TRUE(SetMasterKey(master_key));

  // Adiantum support isn't required (since CONFIG_CRYPTO_ADIANTUM can be unset
  // in the kernel config), so we may skip the test here.
  if (!SetEncryptionPolicy(FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_ADIANTUM,
                           FSCRYPT_POLICY_FLAG_DIRECT_KEY, false))
    return;

  TestFileInfo file_info;
  ASSERT_TRUE(GenerateTestFile(&file_info));

  std::vector<uint8_t> enc_key(kAdiantumKeySize);
  ASSERT_TRUE(DerivePerModeEncryptionKey(master_key, FSCRYPT_MODE_ADIANTUM,
                                         HKDF_CONTEXT_DIRECT_KEY, enc_key));

  FscryptIV iv;
  memset(&iv, 0, sizeof(iv));
  memcpy(iv.file_nonce, file_info.nonce.bytes, kFscryptFileNonceSize);

  VerifyCiphertext(enc_key, iv, AdiantumCipher(), file_info);
}

// Tests a policy matching
// fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized+wrappedkey_v0
// (or simply
// fileencryption=::inlinecrypt_optimized+wrappedkey_v0 on devices launched
// with R or higher)
TEST_F(FBEPolicyTest, TestHwWrappedKeyPolicy) {
  if (skip_test_) return;

  std::vector<uint8_t> master_key, exported_key;
  if (!CreateHwWrappedKey(&master_key, &exported_key)) return;

  // If this fails, it just means fscrypt doesn't have support for hardware
  // wrapped keys, which is OK.
  if (!SetMasterKey(exported_key, __FSCRYPT_ADD_KEY_FLAG_HW_WRAPPED, false))
    return;

  // On ext4, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 is only supported when the
  // filesystem has EXT4_FEATURE_COMPAT_STABLE_INODES, which only happens when
  // inlinecrypt_optimized is selected in the fstab.  So we don't require
  // setting this type of policy to work on ext4.
  if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
                           FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
                           fs_info_.type != "ext4"))
    return;

  TestFileInfo file_info;
  ASSERT_TRUE(GenerateTestFile(&file_info));

  FscryptIV iv;
  memset(&iv, 0, sizeof(iv));
  ASSERT_LE(file_info.inode_number, UINT32_MAX);
  iv.inode_number = __cpu_to_le32(file_info.inode_number);

  std::vector<uint8_t> enc_key;
  ASSERT_TRUE(DeriveHwWrappedEncryptionKey(master_key, &enc_key));
  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
}

// Tests that if the device uses FBE, then the ciphertext for file contents in
// encrypted directories seems to be random.
//
// This isn't as strong a test as the correctness tests, but it's useful because
// it applies regardless of the encryption format and key.  Thus it runs even on
// old devices, including ones that used a vendor-specific encryption format.
TEST(FBETest, TestFileContentsRandomness) {
  constexpr const char *path = "/data/local/tmp/vts-test-file";

  if (android::base::GetProperty("ro.crypto.type", "") != "file") {
    // FBE has been required since Android Q.
    int first_api_level;
    ASSERT_TRUE(GetFirstApiLevel(&first_api_level));
    ASSERT_LE(first_api_level, __ANDROID_API_P__)
        << "File-based encryption is required";
    GTEST_LOG_(INFO)
        << "Skipping test because device doesn't use file-based encryption";
    return;
  }
  FilesystemInfo fs_info;
  ASSERT_TRUE(GetFilesystemInfo("/data", &fs_info));

  std::vector<uint8_t> zeroes(kTestFileBytes, 0);
  std::vector<uint8_t> ciphertext;
  ASSERT_TRUE(WriteTestFile(zeroes, path, fs_info.raw_blk_device, &ciphertext));

  GTEST_LOG_(INFO) << "Verifying randomness of ciphertext";

  ASSERT_TRUE(VerifyDataRandomness(ciphertext));

  ASSERT_EQ(unlink(path), 0);
}

}  // namespace kernel
}  // namespace android
