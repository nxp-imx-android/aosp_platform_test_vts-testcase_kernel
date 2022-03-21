/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <filesystem>

#include <android-base/properties.h>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <kver/kernel_release.h>
#include <vintf/VintfObject.h>
#include <vintf/parse_string.h>

#include "ramdisk_utils.h"

using android::base::GetBoolProperty;
using android::base::GetProperty;
using android::kver::KernelRelease;
using android::vintf::Level;
using android::vintf::RuntimeInfo;
using android::vintf::Version;
using android::vintf::VintfObject;
using testing::IsSupersetOf;

class GenericBootImageTest : public testing::Test {
 public:
  void SetUp() override {
    auto vintf = VintfObject::GetInstance();
    ASSERT_NE(nullptr, vintf);
    runtime_info = vintf->getRuntimeInfo(RuntimeInfo::FetchFlag::CPU_VERSION);
    ASSERT_NE(nullptr, runtime_info);
  }
  std::shared_ptr<const RuntimeInfo> runtime_info;
};

TEST_F(GenericBootImageTest, KernelReleaseFormat) {
  // On "GKI 2.0" with 5.10+ kernels, VTS runs once with the device kernel,
  // so this test is meaningful.
  if (runtime_info->kernelVersion().dropMinor() < Version{5, 10}) {
    GTEST_SKIP() << "Exempt generic kernel image (GKI) test on kernel "
                 << runtime_info->kernelVersion()
                 << ". Only required on 5.10+.";
  }

  const std::string& release = runtime_info->osRelease();
  ASSERT_TRUE(
      KernelRelease::Parse(release, true /* allow_suffix */).has_value())
      << "Kernel release '" << release
      << "' does not have generic kernel image (GKI) release format. It must "
         "match this regex:\n"
      << R"(^(?P<w>\d+)[.](?P<x>\d+)[.](?P<y>\d+)-(?P<z>android\d+)-(?P<k>\d+).*$)"
      << "\nExample: 5.4.42-android12-0-something";
}

TEST_F(GenericBootImageTest, GenericRamdisk) {
  // On "GKI 2.0" with 5.10+ kernels, VTS runs once with the device kernel,
  // so this test is meaningful.
  if (runtime_info->kernelVersion().dropMinor() < Version{5, 10}) {
    GTEST_SKIP() << "Exempt generic ramdisk test on kernel "
                 << runtime_info->kernelVersion()
                 << ". Only required on 5.10+.";
  }

  using std::filesystem::recursive_directory_iterator;

  std::string slot_suffix = GetProperty("ro.boot.slot_suffix", "");
  // Launching devices with T+ using android13+ kernels have the ramdisk in
  // init_boot instead of boot
  std::string error_msg;
  const auto kernel_level =
      VintfObject::GetInstance()->getKernelLevel(&error_msg);
  ASSERT_NE(Level::UNSPECIFIED, kernel_level) << error_msg;
  std::string boot_path;
  if (kernel_level >= Level::T) {
    if (std::stoi(android::base::GetProperty("ro.vendor.api_level", "0")) >=
        __ANDROID_API_T__) {
      boot_path = "/dev/block/by-name/init_boot" + slot_suffix;
    } else {
      // This is the case of a device launched before Android 13 that is
      // upgrading its kernel to android13+. These devices can't add an
      // init_boot partition and need to include the equivalent ramdisk
      // functionality somewhere outside of boot.img (most likely in the
      // vendor_boot image). Since we don't know where to look, or which files
      // will be present, we can skip the rest of this test case.
      GTEST_SKIP() << "Exempt generic ramdisk test on upgrading device that "
                   << "launched before Android 13 and is now using an Android "
                   << "13+ kernel.";
    }
  } else {
    boot_path = "/dev/block/by-name/boot" + slot_suffix;
  }
  if (0 != access(boot_path.c_str(), F_OK)) {
    int saved_errno = errno;
    FAIL() << "Can't access " << boot_path << ": " << strerror(saved_errno);
  }

  auto extracted_ramdisk = android::ExtractRamdiskToDirectory(boot_path);
  ASSERT_TRUE(extracted_ramdisk.ok())
      << "Failed to find the block device: " << boot_path;

  std::set<std::string> actual_files;
  std::filesystem::path extracted_ramdisk_path((*extracted_ramdisk)->path);
  for (auto& p : recursive_directory_iterator(extracted_ramdisk_path)) {
    if (p.is_directory()) continue;
    EXPECT_TRUE(p.is_regular_file())
        << "Unexpected non-regular file " << p.path();
    auto rel_path = p.path().lexically_relative(extracted_ramdisk_path);
    actual_files.insert(rel_path.string());
  }

  std::set<std::string> generic_ramdisk_allowlist{
      "init",
      "system/etc/ramdisk/build.prop",
  };
  if (GetBoolProperty("ro.debuggable", false)) {
    EXPECT_THAT(actual_files, IsSupersetOf(generic_ramdisk_allowlist))
        << "Missing files required by non-debuggable generic ramdisk.";
    std::set<std::string> debuggable_allowlist{
        "adb_debug.prop",
        "force_debuggable",
        "userdebug_plat_sepolicy.cil",
    };
    generic_ramdisk_allowlist.insert(debuggable_allowlist.begin(),
                                     debuggable_allowlist.end());
    EXPECT_THAT(generic_ramdisk_allowlist, IsSupersetOf(actual_files))
        << "Contains files disallowed by debuggable generic ramdisk";
  } else {
    EXPECT_EQ(actual_files, generic_ramdisk_allowlist);
  }
}
