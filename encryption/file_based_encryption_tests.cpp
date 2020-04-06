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
// Test that file contents encryption is producing the correct ciphertext
// on-disk.  This is useful for verifying that vendors' inline encryption
// hardware is working correctly, for example.
//
// This test checks fscrypt policies equivalent to the following fstab settings:
//
//    fileencryption=aes-256-xts:aes-256-cts:v2
//    fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized
//    fileencryption=adiantum:adiantum:v2
//
// On devices launching with R or higher those are equivalent to simply:
//
//    fileencryption=aes-256-xts
//    fileencryption=aes-256-xts:aes-256-cts:inlinecrypt_optimized
//    fileencryption=adiantum
//
// This test doesn't currently check which one of those settings, if any, the
// device is actually using; it just tries to test everything it can.
// "fileencryption=aes-256-xts" is guaranteed to be available if the kernel
// supports any "fscrypt v2" features at all.  The others may not be available,
// so this test takes that into account and skips testing them when unavailable.
//
// This test doesn't currently test hardware-wrapped keys ("wrappedkey_v0").
//
// This test should never fail.  In particular, vendors must not break any
// standard fscrypt functionality, regardless of what the device actually uses.
// If it does fail, make sure to check things like the byte order of keys.
//

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <errno.h>
#include <ext4_utils/ext4.h>
#include <ext4_utils/ext4_sb.h>
#include <ext4_utils/ext4_utils.h>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <limits.h>
#include <linux/fiemap.h>
#include <linux/fs.h>
#include <linux/fscrypt.h>
#include <linux/magic.h>
#include <mntent.h>
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

// Location of the test directory and file.  Since it's not possible to override
// an existing encryption policy, in order for this test to set its own
// encryption policy the parent directory must be unencrypted.
constexpr const char *kTestMountpoint = "/data";
constexpr const char *kTestDir = "/data/unencrypted/vts-test-dir";
constexpr const char *kTestFile = "/data/unencrypted/vts-test-dir/file";

// Assumed size of filesystem blocks, in bytes
constexpr int kFilesystemBlockSize = 4096;

// Size of the test file in filesystem blocks
constexpr int kTestFileBlocks = 256;

// Size of the test file in bytes
constexpr int kTestFileBytes = kFilesystemBlockSize * kTestFileBlocks;

// Size of a filesystem UUID, in bytes
constexpr int kFilesystemUuidSize = 16;

// Offset in bytes to the filesystem superblock, relative to the beginning of
// the block device
constexpr int kExt4SuperBlockOffset = 1024;
constexpr int kF2fsSuperBlockOffset = 1024;

// For F2FS: the offsets in bytes to the filesystem magic number and filesystem
// UUID, relative to the beginning of the block device
constexpr int kF2fsMagicOffset = kF2fsSuperBlockOffset;
constexpr int kF2fsUuidOffset = kF2fsSuperBlockOffset + 108;

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

struct FilesystemUuid {
  uint8_t bytes[kFilesystemUuidSize];
};

struct FscryptFileNonce {
  uint8_t bytes[kFscryptFileNonceSize];
};

// Format of the initialization vector
union FscryptIV {
  struct {
    __le32 lblk_num;      // file logical block number, starts at 0
    __le32 inode_number;  // only used for IV_INO_LBLK_64
    u8 file_nonce[kFscryptFileNonceSize];  // only used for DIRECT_KEY
  };
  u8 bytes[kFscryptMaxIVSize];
};

struct TestFileInfo {
  std::vector<uint8_t> plaintext;
  std::vector<uint8_t> actual_ciphertext;
  uint64_t inode_number;
  FscryptFileNonce nonce;
};

// Given a mountpoint, gets the corresponding block device and filesystem type
// from /proc/mounts.  This block device is the one on which the filesystem is
// directly located.  In the case of device-mapper that means something like
// /dev/mapper/dm-5, not the underlying device like /dev/block/by-name/userdata.
static bool GetFsBlockDeviceAndType(const std::string &mountpoint,
                                    std::string *fs_blk_device,
                                    std::string *fs_type) {
  std::unique_ptr<FILE, int (*)(FILE *)> mnts(setmntent("/proc/mounts", "re"),
                                              endmntent);
  if (!mnts) {
    ADD_FAILURE() << "Failed to open /proc/mounts" << Errno();
    return false;
  }
  struct mntent *mnt;
  while ((mnt = getmntent(mnts.get())) != nullptr) {
    if (mnt->mnt_dir == mountpoint) {
      *fs_blk_device = mnt->mnt_fsname;
      *fs_type = mnt->mnt_type;
      GTEST_LOG_(INFO) << kTestMountpoint << " is " << *fs_blk_device
                       << " mounted with type " << *fs_type;
      return true;
    }
  }
  ADD_FAILURE() << "No /proc/mounts entry found for " << mountpoint;
  return false;
}

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
static bool IsFscryptV2Supported() {
  android::base::unique_fd fd(
      open(kTestMountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (fd < 0) {
    ADD_FAILURE() << "Failed to open " << kTestMountpoint << Errno();
    return false;
  }

  if (ioctl(fd, FS_IOC_ADD_ENCRYPTION_KEY, nullptr) == 0) {
    ADD_FAILURE()
        << "FS_IOC_ADD_ENCRYPTION_KEY(nullptr) unexpectedly succeeded on "
        << kTestMountpoint;
    return false;
  }
  switch (errno) {
    case EFAULT:
      return true;
    case ENOTTY:
      GTEST_LOG_(INFO) << "No support for FS_IOC_ADD_ENCRYPTION_KEY on "
                       << kTestMountpoint;
      return false;
    default:
      ADD_FAILURE()
          << "Unexpected error from FS_IOC_ADD_ENCRYPTION_KEY(nullptr) on "
          << kTestMountpoint << Errno();
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

class FileBasedEncryptionTest : public ::testing::Test {
 protected:
  void SetUp() override;
  void TearDown() override;
  void RemoveTestDirectory();
  bool FindFilesystemTypeAndUuid();
  bool SetEncryptionPolicy(int contents_mode, int filenames_mode, int flags,
                           bool required);
  bool GenerateTestFile(TestFileInfo *info);
  bool DeriveEncryptionKey(const std::vector<uint8_t> &hdkf_info,
                           std::vector<uint8_t> &enc_key);
  bool DerivePerModeEncryptionKey(int mode, FscryptHkdfContext context,
                                  std::vector<uint8_t> &enc_key);
  bool DerivePerFileEncryptionKey(const FscryptFileNonce &nonce,
                                  std::vector<uint8_t> &enc_key);
  void VerifyCiphertext(const std::vector<uint8_t> &enc_key,
                        const FscryptIV &starting_iv, const Cipher &cipher,
                        const TestFileInfo &file_info);
  std::vector<uint8_t> master_key_;
  struct fscrypt_key_specifier master_key_specifier_;
  bool skip_test_ = false;
  bool key_added_ = false;
  std::string raw_partition_;
  std::string fs_type_;
  FilesystemUuid fs_uuid_;
};

// Test setup procedure.  Creates a test directory kTestDir, generates and adds
// an encryption key to kTestMountpoint, and does other preparations.
// skip_test_ is set to true if the test should be skipped.
void FileBasedEncryptionTest::SetUp() {
  if (!IsFscryptV2Supported()) {
    int first_api_level;
    ASSERT_TRUE(GetFirstApiLevel(&first_api_level));
    // Devices launching with R or higher must support fscrypt v2.
    ASSERT_LE(first_api_level, __ANDROID_API_Q__);
    GTEST_LOG_(INFO) << "Skipping test because fscrypt v2 is unsupported";
    skip_test_ = true;
    return;
  }

  ASSERT_TRUE(FindFilesystemTypeAndUuid());

  ASSERT_TRUE(FindRawPartition(kTestMountpoint, &raw_partition_));

  RemoveTestDirectory();
  if (mkdir(kTestDir, 0700) != 0) {
    FAIL() << "Failed to create " << kTestDir << Errno();
  }

  // Generate an fscrypt master key and add it to kTestMountpoint.
  // This gives us back the key identifier to use in the encryption policy.

  master_key_ = GenerateTestKey(kFscryptMasterKeySize);

  size_t allocsize = sizeof(struct fscrypt_add_key_arg) + master_key_.size();
  std::unique_ptr<struct fscrypt_add_key_arg> arg(
      new (::operator new(allocsize)) struct fscrypt_add_key_arg);
  memset(arg.get(), 0, allocsize);
  arg->key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
  arg->raw_size = master_key_.size();
  std::copy(master_key_.begin(), master_key_.end(), arg->raw);

  GTEST_LOG_(INFO) << "Adding fscrypt master key, raw bytes are "
                   << BytesToHex(master_key_);
  android::base::unique_fd mntfd(
      open(kTestMountpoint, O_RDONLY | O_DIRECTORY | O_CLOEXEC));
  if (mntfd < 0) {
    FAIL() << "Failed to open " << kTestMountpoint << Errno();
  }
  if (ioctl(mntfd, FS_IOC_ADD_ENCRYPTION_KEY, arg.get()) != 0) {
    FAIL() << "FS_IOC_ADD_ENCRYPTION_KEY failed on " << kTestMountpoint
           << Errno();
  }
  master_key_specifier_ = arg->key_spec;
  GTEST_LOG_(INFO) << "Master key identifier is "
                   << BytesToHex(master_key_specifier_.u.identifier);
  key_added_ = true;
}

void FileBasedEncryptionTest::TearDown() {
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

void FileBasedEncryptionTest::RemoveTestDirectory() {
  if (unlink(kTestFile) != 0 && errno != ENOENT && errno != ENOPKG) {
    FAIL() << "Failed to remove file " << kTestFile << Errno();
  }
  if (rmdir(kTestDir) != 0 && errno != ENOENT) {
    FAIL() << "Failed to remove directory " << kTestDir << Errno();
  }
}

// Finds the type and UUID of the filesystem mounted on kTestMountpoint.
//
// Unfortunately there's no kernel API to get the UUID; instead we have to read
// it from the filesystem superblock.
bool FileBasedEncryptionTest::FindFilesystemTypeAndUuid() {
  std::string fs_blk_device;
  if (!GetFsBlockDeviceAndType(kTestMountpoint, &fs_blk_device, &fs_type_)) {
    ADD_FAILURE() << "Failed to find filesystem block device and type";
    return false;
  }

  android::base::unique_fd fd(
      open(fs_blk_device.c_str(), O_RDONLY | O_CLOEXEC));
  if (fd < 0) {
    ADD_FAILURE() << "Failed to open fs block device " << fs_blk_device
                  << Errno();
    return false;
  }

  if (fs_type_ == "ext4") {
    struct ext4_super_block sb;

    if (pread(fd, &sb, sizeof(sb), kExt4SuperBlockOffset) != sizeof(sb)) {
      ADD_FAILURE() << "Error reading ext4 superblock from " << fs_blk_device
                    << Errno();
      return false;
    }
    if (sb.s_magic != cpu_to_le16(EXT4_SUPER_MAGIC)) {
      ADD_FAILURE() << "Failed to find ext4 superblock on " << fs_blk_device;
      return false;
    }
    static_assert(sizeof(sb.s_uuid) == kFilesystemUuidSize);
    memcpy(fs_uuid_.bytes, sb.s_uuid, kFilesystemUuidSize);
  } else if (fs_type_ == "f2fs") {
    // Android doesn't have an f2fs equivalent of libext4_utils, so we have to
    // hard-code the offset to the magic number and UUID.

    __le32 magic;
    if (pread(fd, &magic, sizeof(magic), kF2fsMagicOffset) != sizeof(magic)) {
      ADD_FAILURE() << "Error reading f2fs superblock from " << fs_blk_device
                    << Errno();
      return false;
    }
    if (magic != cpu_to_le32(F2FS_SUPER_MAGIC)) {
      ADD_FAILURE() << "Failed to find f2fs superblock on " << fs_blk_device;
      return false;
    }
    if (pread(fd, fs_uuid_.bytes, kFilesystemUuidSize, kF2fsUuidOffset) !=
        kFilesystemUuidSize) {
      ADD_FAILURE() << "Failed to read f2fs filesystem UUID from "
                    << fs_blk_device << Errno();
      return false;
    }
  } else {
    ADD_FAILURE() << "Unknown filesystem type " << fs_type_;
    return false;
  }
  GTEST_LOG_(INFO) << "Filesystem UUID is " << BytesToHex(fs_uuid_.bytes);
  return true;
}

// Sets a v2 encryption policy on the test directory.  The policy will use the
// test key and the specified encryption modes and flags.  If required=false,
// then a failure won't be added if the kernel doesn't support the policy.
bool FileBasedEncryptionTest::SetEncryptionPolicy(int contents_mode,
                                                  int filenames_mode, int flags,
                                                  bool required) {
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
bool FileBasedEncryptionTest::GenerateTestFile(TestFileInfo *info) {
  // Generate the test data.
  info->plaintext.resize(kTestFileBytes);
  RandomBytesForTesting(info->plaintext);

  // Write the test data to the file.
  GTEST_LOG_(INFO) << "Creating test file " << kTestFile << " containing "
                   << kTestFileBytes << " bytes of data (" << kTestFileBlocks
                   << " blocks)";
  android::base::unique_fd fd(
      open(kTestFile, O_WRONLY | O_CREAT | O_CLOEXEC, 0600));
  if (fd < 0) {
    ADD_FAILURE() << "Failed to create " << kTestFile << Errno();
    return false;
  }
  if (!android::base::WriteFully(fd, info->plaintext.data(),
                                 info->plaintext.size())) {
    ADD_FAILURE() << "Error writing to " << kTestFile << Errno();
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

  // Read the file's raw ciphertext.
  GTEST_LOG_(INFO) << "Reading the raw ciphertext from disk";
  if (!ReadRawDataOfFile(fd, raw_partition_, kTestFileBytes,
                         &info->actual_ciphertext)) {
    ADD_FAILURE() << "Failed to read the raw ciphertext";
    return false;
  }
  return true;
}

static std::vector<uint8_t> InitHkdfInfo(FscryptHkdfContext context) {
  return {
      'f', 's', 'c', 'r', 'y', 'p', 't', '\0', static_cast<uint8_t>(context)};
}

bool FileBasedEncryptionTest::DeriveEncryptionKey(
    const std::vector<uint8_t> &hkdf_info, std::vector<uint8_t> &out) {
  if (HKDF(out.data(), out.size(), EVP_sha512(), master_key_.data(),
           master_key_.size(), nullptr, 0, hkdf_info.data(),
           hkdf_info.size()) != 1) {
    ADD_FAILURE() << "BoringSSL HKDF-SHA512 call failed";
    return false;
  }
  GTEST_LOG_(INFO) << "Derived encryption key " << BytesToHex(out)
                   << " using HKDF info " << BytesToHex(hkdf_info);
  return true;
}

// Derives a per-mode encryption key from the master key, |mode|, |context|, and
// (if needed for the context) the filesystem UUID.
bool FileBasedEncryptionTest::DerivePerModeEncryptionKey(
    int mode, FscryptHkdfContext context, std::vector<uint8_t> &enc_key) {
  std::vector<uint8_t> hkdf_info = InitHkdfInfo(context);

  hkdf_info.push_back(mode);
  if (context == HKDF_CONTEXT_IV_INO_LBLK_64_KEY)
    hkdf_info.insert(hkdf_info.end(), fs_uuid_.bytes, std::end(fs_uuid_.bytes));

  return DeriveEncryptionKey(hkdf_info, enc_key);
}

// Derives a per-file encryption key from the master key and |nonce|.
bool FileBasedEncryptionTest::DerivePerFileEncryptionKey(
    const FscryptFileNonce &nonce, std::vector<uint8_t> &enc_key) {
  std::vector<uint8_t> hkdf_info = InitHkdfInfo(HKDF_CONTEXT_PER_FILE_ENC_KEY);

  hkdf_info.insert(hkdf_info.end(), nonce.bytes, std::end(nonce.bytes));

  return DeriveEncryptionKey(hkdf_info, enc_key);
}

void FileBasedEncryptionTest::VerifyCiphertext(
    const std::vector<uint8_t> &enc_key, const FscryptIV &starting_iv,
    const Cipher &cipher, const TestFileInfo &file_info) {
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
    iv.lblk_num = cpu_to_le32(le32_to_cpu(iv.lblk_num) + 1);
    ASSERT_NE(le32_to_cpu(iv.lblk_num), 0);
  }

  ASSERT_EQ(file_info.actual_ciphertext, computed_ciphertext);
}

// Tests a policy matching fileencryption=aes-256-xts:aes-256-cts:v2
// (or simply fileencryption=aes-256-xts on devices launched with R or higher)
TEST_F(FileBasedEncryptionTest, TestAesV2Policy) {
  if (skip_test_) return;

  if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
                           0, true))
    return;

  TestFileInfo file_info;
  if (!GenerateTestFile(&file_info)) return;

  std::vector<uint8_t> enc_key(kAes256XtsKeySize);
  if (!DerivePerFileEncryptionKey(file_info.nonce, enc_key)) return;

  FscryptIV iv;
  memset(&iv, 0, sizeof(iv));

  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
}

// Tests a policy matching
// fileencryption=aes-256-xts:aes-256-cts:v2+inlinecrypt_optimized
// (or simply fileencryption=aes-256-xts:aes-256-cts:inlinecrypt_optimized on
// devices launched with R or higher)
TEST_F(FileBasedEncryptionTest, TestAesV2InlineCryptOptimizedPolicy) {
  if (skip_test_) return;

  // On ext4, FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64 is only supported when the
  // filesystem has EXT4_FEATURE_COMPAT_STABLE_INODES, which only happens when
  // inlinecrypt_optimized is selected in the fstab.  So we don't require
  // setting this type of policy to work on ext4.
  if (!SetEncryptionPolicy(FSCRYPT_MODE_AES_256_XTS, FSCRYPT_MODE_AES_256_CTS,
                           FSCRYPT_POLICY_FLAG_IV_INO_LBLK_64,
                           fs_type_ != "ext4"))
    return;

  TestFileInfo file_info;
  if (!GenerateTestFile(&file_info)) return;

  std::vector<uint8_t> enc_key(kAes256XtsKeySize);
  if (!DerivePerModeEncryptionKey(FSCRYPT_MODE_AES_256_XTS,
                                  HKDF_CONTEXT_IV_INO_LBLK_64_KEY, enc_key))
    return;

  FscryptIV iv;
  memset(&iv, 0, sizeof(iv));
  ASSERT_LE(file_info.inode_number, UINT32_MAX);
  iv.inode_number = cpu_to_le32(file_info.inode_number);

  VerifyCiphertext(enc_key, iv, Aes256XtsCipher(), file_info);
}

// Tests a policy matching fileencryption=adiantum:adiantum:v2 (or simply
// fileencryption=adiantum on devices launched with R or higher)
TEST_F(FileBasedEncryptionTest, TestAdiantumV2Policy) {
  if (skip_test_) return;

  // Adiantum support isn't required (since CONFIG_CRYPTO_ADIANTUM can be unset
  // in the kernel config), so we may skip the test here.
  if (!SetEncryptionPolicy(FSCRYPT_MODE_ADIANTUM, FSCRYPT_MODE_ADIANTUM,
                           FSCRYPT_POLICY_FLAG_DIRECT_KEY, false))
    return;

  TestFileInfo file_info;
  if (!GenerateTestFile(&file_info)) return;

  std::vector<uint8_t> enc_key(kAdiantumKeySize);
  if (!DerivePerModeEncryptionKey(FSCRYPT_MODE_ADIANTUM,
                                  HKDF_CONTEXT_DIRECT_KEY, enc_key))
    return;

  FscryptIV iv;
  memset(&iv, 0, sizeof(iv));
  memcpy(iv.file_nonce, file_info.nonce.bytes, kFscryptFileNonceSize);

  VerifyCiphertext(enc_key, iv, AdiantumCipher(), file_info);
}

}  // namespace kernel
}  // namespace android
