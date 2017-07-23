#
# Copyright (C) 2016 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os

from vts.utils.python.os import path_utils

from vts.testcases.kernel.ltp import ltp_enums

VTS_LTP_OUTPUT = os.path.join('DATA', 'nativetest', 'ltp')
LTP_RUNTEST_DIR = os.path.join(VTS_LTP_OUTPUT, 'runtest')
LTP_DISABLED_BUILD_TESTS_CONFIG_PATH = os.path.join(VTS_LTP_OUTPUT, 'disabled_tests.txt')

# Environment paths for ltp test cases
# string, ltp build root directory on target
LTPDIR = '/data/local/tmp/ltp'
# Directory for environment variable 'TMP' needed by some test cases
TMP = path_utils.JoinTargetPath(LTPDIR, 'tmp')
# Directory for environment variable 'TMPBASE' needed by some test cases
TMPBASE = path_utils.JoinTargetPath(TMP, 'tmpbase')
# Directory for environment variable 'LTPTMP' needed by some test cases
LTPTMP = path_utils.JoinTargetPath(TMP, 'ltptemp')
# Directory for environment variable 'TMPDIR' needed by some test cases
TMPDIR = path_utils.JoinTargetPath(TMP, 'tmpdir')
# Path where ltp test binary exists
LTPBINPATH = path_utils.JoinTargetPath(LTPDIR, 'testcases', 'bin')
# Add LTP's binary path to PATH
PATH = '/system/bin:%s' % LTPBINPATH

# File system type for loop device
LTP_DEV_FS_TYPE = 'ext4'

# Binaries required by LTP test cases that should exist in PATH
INTERNAL_BINS = [
    'mktemp',
    'cp',
    'chmod',
    'chown',
    'ls',
    'mkfifo',
    'ldd',
]

# Internal shell command required by some LTP test cases
INTERNAL_SHELL_COMMANDS = [
    'export',
    'cd',
]

# Requirement to testcase dictionary.
REQUIREMENTS_TO_TESTCASE = {
    ltp_enums.Requirements.LOOP_DEVICE_SUPPORT: [
        'syscalls.mount01',
        'syscalls.fchmod06',
        'syscalls.ftruncate04',
        'syscalls.ftruncate04_64',
        'syscalls.inotify03',
        'syscalls.link08',
        'syscalls.linkat02',
        'syscalls.mkdir03',
        'syscalls.mkdirat02',
        'syscalls.mknod07',
        'syscalls.mknodat02',
        'syscalls.mmap16',
        'syscalls.mount01',
        'syscalls.mount02',
        'syscalls.mount03',
        'syscalls.mount04',
        'syscalls.mount06',
        'syscalls.rename11',
        'syscalls.renameat01',
        'syscalls.rmdir02',
        'syscalls.umount01',
        'syscalls.umount02',
        'syscalls.umount03',
        'syscalls.umount2_01',
        'syscalls.umount2_02',
        'syscalls.umount2_03',
        'syscalls.utime06',
        'syscalls.utimes01',
        'syscalls.mkfs01',
        'fs.quota_remount_test01',
    ],
    ltp_enums.Requirements.BIN_IN_PATH_LDD: ['commands.ldd'],
}

# Requirement for all test cases
REQUIREMENT_FOR_ALL = [ltp_enums.Requirements.LTP_TMP_DIR]

# Requirement to test suite dictionary
REQUIREMENT_TO_TESTSUITE = {}

# List of LTP test suites to run
TEST_SUITES = [
    'admin_tools',
    'can',
    'cap_bounds',
    'commands',
    'connectors',
    'containers',
#     'controllers',
    'cpuhotplug',
    'dio',
    'fcntl-locktests_android',
    'filecaps',
    'fs',
    'fs_bind',
    'fs_ext4',
    'fs_perms_simple',
    'fsx',
    'hugetlb',
    'hyperthreading',
    'input',
    'io',
    'ipc',
    'kernel_misc',
    'math',
    'mm',
    'modules',
    'nptl',
    'numa',
    'pipes',
    'power_management_tests',
    'pty',
    'sched',
    'syscalls',
    'timers',
    # The following are not included in default LTP scenario group
    'securebits',
    'tracing',
]

# List of LTP test suites that will not run in multi-thread mode
TEST_SUITES_REQUIRE_SINGLE_THREAD_MODE = [
    'dio',
    'io',
    'mm',
]

# Staging tests are for debugging and verifying fixed tests
# Test specified here can be in format: testsuite.testname,
# or testsuite.testname_**bit, or just testname. Using just testname
# is not recommended
STAGING_TESTS = [
    # flakey due to b/62575538
    'syscalls.epoll_ctl01_32bit',
    'syscalls.epoll_ctl01_64bit',
    'syscalls.epoll_wait01_32bit',
    'syscalls.epoll_wait01_64bit',
    # b/38393835 failing for kernel 4.4, 4.9
    'syscalls.writev01',
    'syscalls.writev03',
    'syscalls.writev04',
    # b/37861231
    'modules.delete_module02',
    # Flaky on pixel
    # b/32417988
    'syscalls.waitpid02_64bit',
    # Tests currently only failing on pixels,
    # these will be inspected soon
    'syscalls.open14',
    'syscalls.openat03',
    # Fail on local device but pass on lab devices
    'fs.proc01',
    # Failing for missing libcap
    'containers.userns01_64bit',
    'securebits.check_keepcaps03_64bit',
    'securebits.check_keepcaps02_64bit',
    'containers.userns05_64bit',
    'containers.userns07_64bit',
    'containers.userns06_64bit',
    'containers.userns03_64bit',
    'securebits.check_keepcaps01_64bit',
    'containers.userns02_64bit',

    # Skipped tests on pixels are put in staging
    'admin_tools.acl_test01_32bit',
    'admin_tools.acl_test01_64bit',
    'admin_tools.at_allow01_32bit',
    'admin_tools.at_allow01_64bit',
    'admin_tools.at_deny01_32bit',
    'admin_tools.at_deny01_64bit',
    'can.can_filter_32bit',
    'can.can_filter_64bit',
    'can.can_rcv_own_msgs_32bit',
    'can.can_rcv_own_msgs_64bit',
    'commands.df01_exfat_32bit',
    'commands.df01_exfat_64bit',
    'commands.df01_ext2_32bit',
    'commands.df01_ext2_64bit',
    'commands.df01_ext3_32bit',
    'commands.df01_ext3_64bit',
    'commands.df01_ext4_32bit',
    'commands.df01_ext4_64bit',
    'commands.df01_ntfs_32bit',
    'commands.df01_ntfs_64bit',
    'commands.df01_vfat_32bit',
    'commands.df01_vfat_64bit',
    'commands.df01_xfs_32bit',
    'commands.df01_xfs_64bit',
    'commands.insmod01_32bit',
    'commands.insmod01_64bit',
    'commands.mkfs01_btrfs_32bit',
    'commands.mkfs01_btrfs_64bit',
    'commands.mkfs01_ext2_32bit',
    'commands.mkfs01_ext2_64bit',
    'commands.mkfs01_ext3_32bit',
    'commands.mkfs01_ext3_64bit',
    'commands.mkfs01_ext4_32bit',
    'commands.mkfs01_ext4_64bit',
    'commands.mkfs01_minix_32bit',
    'commands.mkfs01_minix_64bit',
    'commands.mkfs01_msdos_32bit',
    'commands.mkfs01_msdos_64bit',
    'commands.mkfs01_ntfs_32bit',
    'commands.mkfs01_ntfs_64bit',
    'commands.mkfs01_vfat_32bit',
    'commands.mkfs01_vfat_64bit',
    'commands.mkfs01_xfs_32bit',
    'commands.mkfs01_xfs_64bit',
    'commands.mkswap01_32bit',
    'commands.mkswap01_64bit',
    'connectors.Connectors_32bit',
    'connectors.Connectors_64bit',
    'containers.pidns01_32bit',
    'containers.pidns01_64bit',
    'containers.pidns02_32bit',
    'containers.pidns02_64bit',
    'containers.pidns03_32bit',
    'containers.pidns03_64bit',
    'containers.pidns04_32bit',
    'containers.pidns04_64bit',
    'containers.pidns05_32bit',
    'containers.pidns05_64bit',
    'containers.pidns06_32bit',
    'containers.pidns06_64bit',
    'containers.pidns13_32bit',
    'containers.pidns13_64bit',
    'containers.pidns16_32bit',
    'containers.pidns16_64bit',
    'containers.pidns32_32bit',
    'containers.pidns32_64bit',
    'containers.userns01_32bit',
    'containers.userns02_32bit',
    'containers.userns03_32bit',
    'containers.userns04_32bit',
    'containers.userns04_64bit',
    'containers.userns05_32bit',
    'containers.userns06_32bit',
    'containers.userns07_32bit',
    'containers.utstest_clone_1_32bit',
    'containers.utstest_clone_1_64bit',
    'containers.utstest_clone_2_32bit',
    'containers.utstest_clone_2_64bit',
    'containers.utstest_clone_3_32bit',
    'containers.utstest_clone_3_64bit',
    'containers.utstest_clone_4_32bit',
    'containers.utstest_clone_4_64bit',
    'containers.utstest_clone_5_32bit',
    'containers.utstest_clone_5_64bit',
    'containers.utstest_unshare_1_32bit',
    'containers.utstest_unshare_1_64bit',
    'containers.utstest_unshare_2_32bit',
    'containers.utstest_unshare_2_64bit',
    'containers.utstest_unshare_3_32bit',
    'containers.utstest_unshare_3_64bit',
    'containers.utstest_unshare_4_32bit',
    'containers.utstest_unshare_4_64bit',
    'containers.utstest_unshare_5_32bit',
    'containers.utstest_unshare_5_64bit',
    'cpuhotplug.cpuhotplug05_32bit',
    'cpuhotplug.cpuhotplug05_64bit',
    'cpuhotplug.cpuhotplug07_32bit',
    'cpuhotplug.cpuhotplug07_64bit',
    'fs_ext4.ext4-nsec-timestamps_32bit',
    'fs_ext4.ext4-nsec-timestamps_64bit',
    'fs_ext4.ext4-subdir-limit_32bit',
    'fs_ext4.ext4-subdir-limit_64bit',
    'hugetlb.hugemmap01_32bit',
    'hugetlb.hugemmap01_64bit',
    'hugetlb.hugemmap02_32bit',
    'hugetlb.hugemmap02_64bit',
    'hugetlb.hugemmap04_32bit',
    'hugetlb.hugemmap04_64bit',
    'hugetlb.hugemmap06_32bit',
    'hugetlb.hugemmap06_64bit',
    'hyperthreading.ht_interrupt_32bit',
    'hyperthreading.ht_interrupt_64bit',
    'kernel_misc.block_dev_32bit',
    'kernel_misc.block_dev_64bit',
    'kernel_misc.cpufreq_boost_32bit',
    'kernel_misc.cpufreq_boost_64bit',
    'kernel_misc.fw_load_32bit',
    'kernel_misc.fw_load_64bit',
    'kernel_misc.lock_torture_32bit',
    'kernel_misc.lock_torture_64bit',
    'kernel_misc.ltp_acpi_32bit',
    'kernel_misc.ltp_acpi_64bit',
    'kernel_misc.rcu_torture_32bit',
    'kernel_misc.rcu_torture_64bit',
    'kernel_misc.rtc01_32bit',
    'kernel_misc.rtc01_64bit',
    'kernel_misc.tbio_32bit',
    'kernel_misc.tbio_64bit',
    'kernel_misc.tpci_32bit',
    'kernel_misc.tpci_64bit',
    'kernel_misc.uaccess_32bit',
    'kernel_misc.uaccess_64bit',
    'kernel_misc.zram01_32bit',
    'kernel_misc.zram01_64bit',
    'kernel_misc.zram02_32bit',
    'kernel_misc.zram02_64bit',
    'mm.ksm01_1_32bit',
    'mm.ksm01_1_64bit',
    'mm.ksm01_32bit',
    'mm.ksm01_64bit',
    'mm.ksm02_1_32bit',
    'mm.ksm02_1_64bit',
    'mm.ksm02_32bit',
    'mm.ksm02_64bit',
    'mm.ksm03_1_32bit',
    'mm.ksm03_1_64bit',
    'mm.ksm03_32bit',
    'mm.ksm03_64bit',
    'mm.ksm04_1_32bit',
    'mm.ksm04_1_64bit',
    'mm.ksm04_32bit',
    'mm.ksm04_64bit',
    'mm.ksm06_1_32bit',
    'mm.ksm06_1_64bit',
    'mm.ksm06_2_32bit',
    'mm.ksm06_2_64bit',
    'mm.ksm06_32bit',
    'mm.ksm06_64bit',
    'mm.mmap10_2_32bit',
    'mm.mmap10_2_64bit',
    'mm.mmap10_3_32bit',
    'mm.mmap10_3_64bit',
    'mm.mmap10_4_32bit',
    'mm.mmap10_4_64bit',
    'mm.mmapstress08_32bit',
    'mm.mmapstress08_64bit',
    'mm.oom01_32bit',
    'mm.oom02_32bit',
    'mm.oom03_32bit',
    'mm.oom04_32bit',
    'mm.oom05_32bit',
    'mm.overcommit_memory01_32bit',
    'mm.overcommit_memory02_32bit',
    'mm.overcommit_memory03_32bit',
    'mm.overcommit_memory04_32bit',
    'mm.overcommit_memory05_32bit',
    'mm.overcommit_memory06_32bit',
    'mm.swapping01_32bit',
    'mm.thp02_32bit',
    'mm.thp03_32bit',
    'mm.vma02_32bit',
    'mm.vma02_64bit',
    'mm.vma04_32bit',
    'mm.vma04_64bit',
    'modules.delete_module01_32bit',
    'modules.delete_module01_64bit',
    'modules.delete_module03_32bit',
    'modules.delete_module03_64bit',
    'numa.move_pages01_32bit',
    'numa.move_pages01_64bit',
    'numa.move_pages02_32bit',
    'numa.move_pages02_64bit',
    'numa.move_pages04_32bit',
    'numa.move_pages04_64bit',
    'numa.move_pages05_32bit',
    'numa.move_pages05_64bit',
    'numa.move_pages06_32bit',
    'numa.move_pages06_64bit',
    'numa.move_pages07_32bit',
    'numa.move_pages07_64bit',
    'numa.move_pages08_32bit',
    'numa.move_pages08_64bit',
    'numa.move_pages09_32bit',
    'numa.move_pages09_64bit',
    'numa.move_pages10_32bit',
    'numa.move_pages10_64bit',
    'power_management_tests.runpwtests01_32bit',
    'power_management_tests.runpwtests01_64bit',
    'power_management_tests.runpwtests02_32bit',
    'power_management_tests.runpwtests02_64bit',
    'power_management_tests.runpwtests03_32bit',
    'power_management_tests.runpwtests03_64bit',
    'power_management_tests.runpwtests04_32bit',
    'power_management_tests.runpwtests04_64bit',
    'power_management_tests.runpwtests06_32bit',
    'power_management_tests.runpwtests06_64bit',
    'syscalls.acct01_32bit',
    'syscalls.acct01_64bit',
    'syscalls.cacheflush01_32bit',
    'syscalls.cacheflush01_64bit',
    'syscalls.fanotify01_32bit',
    'syscalls.fanotify01_64bit',
    'syscalls.fanotify02_32bit',
    'syscalls.fanotify02_64bit',
    'syscalls.fanotify03_32bit',
    'syscalls.fanotify03_64bit',
    'syscalls.fanotify04_32bit',
    'syscalls.fanotify04_64bit',
    'syscalls.fanotify05_32bit',
    'syscalls.fanotify05_64bit',
    'syscalls.fanotify06_32bit',
    'syscalls.fanotify06_64bit',
    'syscalls.fcntl06_32bit',
    'syscalls.fcntl06_64_32bit',
    'syscalls.fcntl06_64_64bit',
    'syscalls.fcntl06_64bit',
    'syscalls.fork14_32bit',
    'syscalls.fork14_64bit',
    'syscalls.futex_wake04_32bit',
    'syscalls.futex_wake04_64bit',
    'syscalls.get_mempolicy01_32bit',
    'syscalls.get_mempolicy01_64bit',
    'syscalls.getcpu01_32bit',
    'syscalls.getcpu01_64bit',
    'syscalls.getxattr01_32bit',
    'syscalls.getxattr01_64bit',
    'syscalls.getxattr02_32bit',
    'syscalls.getxattr02_64bit',
    'syscalls.getxattr03_32bit',
    'syscalls.getxattr03_64bit',
    'syscalls.kcmp01_32bit',
    'syscalls.kcmp01_64bit',
    'syscalls.kcmp02_32bit',
    'syscalls.kcmp02_64bit',
    'syscalls.keyctl01_32bit',
    'syscalls.keyctl01_64bit',
    'syscalls.mbind01_32bit',
    'syscalls.mbind01_64bit',
    'syscalls.migrate_pages01_32bit',
    'syscalls.migrate_pages01_64bit',
    'syscalls.migrate_pages02_32bit',
    'syscalls.migrate_pages02_64bit',
    'syscalls.mmap15_32bit',
    'syscalls.mmap15_64bit',
    'syscalls.move_pages01_32bit',
    'syscalls.move_pages01_64bit',
    'syscalls.move_pages02_32bit',
    'syscalls.move_pages02_64bit',
    'syscalls.move_pages04_32bit',
    'syscalls.move_pages04_64bit',
    'syscalls.move_pages05_32bit',
    'syscalls.move_pages05_64bit',
    'syscalls.move_pages06_32bit',
    'syscalls.move_pages06_64bit',
    'syscalls.move_pages07_32bit',
    'syscalls.move_pages07_64bit',
    'syscalls.move_pages08_32bit',
    'syscalls.move_pages08_64bit',
    'syscalls.move_pages09_32bit',
    'syscalls.move_pages09_64bit',
    'syscalls.move_pages10_32bit',
    'syscalls.move_pages10_64bit',
    'syscalls.munlockall02_32bit',
    'syscalls.munlockall02_64bit',
    'syscalls.ptrace04_32bit',
    'syscalls.ptrace04_64bit',
    'syscalls.quotactl02_32bit',
    'syscalls.quotactl02_64bit',
    'syscalls.readdir21_32bit',
    'syscalls.readdir21_64bit',
    'syscalls.removexattr01_32bit',
    'syscalls.removexattr01_64bit',
    'syscalls.removexattr02_32bit',
    'syscalls.removexattr02_64bit',
    'syscalls.sendfile09_32bit',
    'syscalls.sendfile09_64_32bit',
    'syscalls.sendfile09_64_64bit',
    'syscalls.sendfile09_64bit',
    'syscalls.setxattr01_32bit',
    'syscalls.setxattr01_64bit',
    'syscalls.setxattr02_32bit',
    'syscalls.setxattr02_64bit',
    'syscalls.setxattr03_32bit',
    'syscalls.setxattr03_64bit',
    'syscalls.sgetmask01_32bit',
    'syscalls.sgetmask01_64bit',
    'syscalls.signal06_32bit',
    'syscalls.signal06_64bit',
    'syscalls.sockioctl01_32bit',
    'syscalls.sockioctl01_64bit',
    'syscalls.ssetmask01_32bit',
    'syscalls.ssetmask01_64bit',
    'syscalls.switch01_32bit',
    'syscalls.switch01_64bit',
    'syscalls.sysctl01_32bit',
    'syscalls.sysctl01_64bit',
    'syscalls.sysctl03_32bit',
    'syscalls.sysctl03_64bit',
    'syscalls.sysctl04_32bit',
    'syscalls.sysctl04_64bit',
    'syscalls.sysctl05_32bit',
    'syscalls.sysctl05_64bit',
    'syscalls.sysfs01_32bit',
    'syscalls.sysfs01_64bit',
    'syscalls.sysfs02_32bit',
    'syscalls.sysfs02_64bit',
    'syscalls.sysfs03_32bit',
    'syscalls.sysfs03_64bit',
    'syscalls.sysfs04_32bit',
    'syscalls.sysfs04_64bit',
    'syscalls.sysfs05_32bit',
    'syscalls.sysfs05_64bit',
    'syscalls.sysfs06_32bit',
    'syscalls.sysfs06_64bit',
    'tracing.ftrace_regression01_32bit',
    'tracing.ftrace_regression01_64bit',
]

# Tests disabled
# Based on external/ltp commit 5f01077afe994f4107b147222f3956716d4a8fde
DISABLED_TESTS = [
    # b/63928505
    'syscalls.add_key02',
    # gunzip newly added on 4/12/17 and test is failing because -r option is not yet implemented.
    'commands.gzip01',
    # b/32386191 getrusage04 result is flaky
    'syscalls.getrusage04',
    # b/31154962
    'cpuhotplug.cpuhotplug02',
    # b/32385889
    'syscalls.creat08',
    # The following test cases are uncategorized
    'syscalls.fcntl34',
    'syscalls.fcntl34_64',
    'syscalls.inotify06',
    'syscalls.abort01',
    'syscalls.chmod05',
    'syscalls.chmod07',
    'syscalls.chown01_16',
    'syscalls.chown02_16',
    'syscalls.chown03_16',
    'syscalls.chown05_16',
    'syscalls.fchmod01',
    'syscalls.fchmod02',
    'syscalls.fchmod05',
    'syscalls.fchmod06',
    'syscalls.fchown01_16',
    'syscalls.fchown02_16',
    'syscalls.fchown03_16',
    'syscalls.fchown04_16',
    'syscalls.fchown05_16',
    'syscalls.fsync01',
    'syscalls.ftruncate04',
    'syscalls.ftruncate04_64',
    'syscalls.getcwd02',
    'syscalls.getcwd03',
    'syscalls.getegid01_16',
    'syscalls.getegid02_16',
    'syscalls.geteuid01_16',
    'syscalls.geteuid02_16',
    'syscalls.getgid01_16',
    'syscalls.getgid03_16',
    'syscalls.getgroups01_16',
    'syscalls.gethostbyname_r01',
    'syscalls.getuid01_16',
    'syscalls.getuid03_16',
    'syscalls.ioctl03',
    'syscalls.inotify03',
    'syscalls.kill11',
    'syscalls.lchown01_16',
    'syscalls.lchown02_16',
    'syscalls.lchown03_16',
    'syscalls.link08',
    'syscalls.linkat02',
    'syscalls.mkdir03',
    'syscalls.rmdir02',
    'syscalls.mkdirat02',
    'syscalls.mknod07',
    'syscalls.mknodat02',
    'syscalls.mmap16',
    'syscalls.mount01',
    'syscalls.mount02',
    'syscalls.mount03',
    'syscalls.mount04',
    'syscalls.mount06',
    'syscalls.move_pages03',
    'syscalls.move_pages11',
    'syscalls.mprotect01',
    'syscalls.nftw01',
    'syscalls.nftw6401',
    'syscalls.nice04',
    'syscalls.open01',
    'syscalls.open08',
    'syscalls.open10',
    'syscalls.open11',
    'syscalls.madvise01',
    'syscalls.madvise02',
    'syscalls.madvise06',
    'syscalls.pathconf01',
    'syscalls.preadv02',
    'syscalls.process_vm_readv01',
    'syscalls.process_vm_writev01',
    'syscalls.pwritev01_64',
    'syscalls.pwritev02',
    'syscalls.quotactl01',
    'syscalls.readlink04',
    'syscalls.rename11',
    'syscalls.renameat01',
    'syscalls.request_key01',
    'syscalls.request_key02',
    'syscalls.rt_sigprocmask01',
    'syscalls.sbrk03',
    'syscalls.setfsgid01_16',
    'syscalls.setfsgid02_16',
    'syscalls.setfsgid03_16',
    'syscalls.setfsuid01_16',
    'syscalls.setfsuid02_16',
    'syscalls.setfsuid03_16',
    'syscalls.setfsuid04_16',
    'syscalls.setgid01_16',
    'syscalls.setgid02_16',
    'syscalls.setgid03_16',
    'syscalls.setgroups01_16',
    'syscalls.setgroups02_16',
    'syscalls.setgroups03_16',
    'syscalls.setgroups04_16',
    'syscalls.setregid01_16',
    'syscalls.setregid02_16',
    'syscalls.setregid03_16',
    'syscalls.setregid04_16',
    'syscalls.setresgid01_16',
    'syscalls.setresgid02_16',
    'syscalls.setresgid03_16',
    'syscalls.setresgid04_16',
    'syscalls.setresuid01_16',
    'syscalls.setresuid02_16',
    'syscalls.setresuid03_16',
    'syscalls.setresuid04_16',
    'syscalls.setresuid05_16',
    'syscalls.setreuid01_16',
    'syscalls.setreuid02_16',
    'syscalls.setreuid03_16',
    'syscalls.setreuid04_16',
    'syscalls.setreuid05_16',
    'syscalls.setreuid06_16',
    'syscalls.setreuid07_16',
    'syscalls.setuid01_16',
    'syscalls.setuid02_16',
    'syscalls.setuid03_16',
    'syscalls.setuid04_16',
    'syscalls.splice02',
    'syscalls.sysconf01',
    'syscalls.syslog01',
    'syscalls.syslog02',
    'syscalls.syslog03',
    'syscalls.syslog04',
    'syscalls.syslog05',
    'syscalls.syslog06',
    'syscalls.syslog07',
    'syscalls.syslog08',
    'syscalls.syslog09',
    'syscalls.syslog10',
    'syscalls.umask02',
    'syscalls.umask03',
    'syscalls.umount01',
    'syscalls.umount02',
    'syscalls.umount03',
    'syscalls.umount2_01',
    'syscalls.umount2_02',
    'syscalls.umount2_03',
    'syscalls.utime06',
    'syscalls.utimes01',
    'syscalls.utimensat01',
    'syscalls.waitpid05',
    'fs.gf01',
    'fs.gf02',
    'fs.gf03',
    'fs.gf04',
    'fs.gf05',
    'fs.gf06',
    'fs.gf07',
    'fs.gf08',
    'fs.gf09',
    'fs.gf10',
    'fs.gf11',
    'fs.gf14',
    'fs.gf15',
    'fs.gf16',
    'fs.gf17',
    'fs.gf18',
    'fs.gf19',
    'fs.gf20',
    'fs.gf21',
    'fs.gf22',
    'fs.gf23',
    'fs.gf24',
    'fs.gf25',
    'fs.gf26',
    'fs.gf27',
    'fs.gf28',
    'fs.gf29',
    'fs.gf30',
    'fs.rwtest01',
    'fs.rwtest02',
    'fs.rwtest03',
    'fs.rwtest04',
    'fs.rwtest05',
    'fs.iogen01',
    'fs.fs_inod01',
    'fs.ftest06',
    'fs.isofs',
    'fsx.fsx-linux',
    'io.aio01',
    'io.aio02',
    'mm.mtest06',
    'mm.shm_test01',
    'mm.mallocstress01',
    'mm.mmapstress04',
    'mm.mmapstress07',
    'mm.vma03',
    'mm.min_free_kbytes',
    'pipes.pipeio_1',
    'pipes.pipeio_3',
    'pipes.pipeio_4',
    'pipes.pipeio_5',
    'pipes.pipeio_6',
    'pipes.pipeio_8',
    'sched.trace_sched01',
    'math.float_bessel',
    'math.float_exp_log',
    'math.float_iperb',
    'math.float_power',
    'math.float_trigo',
    'pty.pty01',
    'containers.mqns_01_clone',
    'containers.mqns_02_clone',
    'containers.mqns_03_clone',
    'containers.mqns_04_clone',
    'containers.netns_netlink',
    'containers.netns_breakns_ns_exec_ipv4_netlink',
    'containers.netns_breakns_ns_exec_ipv6_netlink',
    'containers.netns_breakns_ns_exec_ipv4_ioctl',
    'containers.netns_breakns_ns_exec_ipv6_ioctl',
    'containers.netns_breakns_ip_ipv4_netlink',
    'containers.netns_breakns_ip_ipv6_netlink',
    'containers.netns_breakns_ip_ipv4_ioctl',
    'containers.netns_breakns_ip_ipv6_ioctl',
    'containers.netns_comm_ns_exec_ipv4_netlink',
    'containers.netns_comm_ns_exec_ipv6_netlink',
    'containers.netns_comm_ns_exec_ipv4_ioctl',
    'containers.netns_comm_ns_exec_ipv6_ioctl',
    'containers.netns_comm_ip_ipv4_netlink',
    'containers.netns_comm_ip_ipv6_netlink',
    'containers.netns_comm_ip_ipv4_ioctl',
    'containers.netns_comm_ip_ipv6_ioctl',
    'containers.netns_sysfs',
    'containers.shmnstest_none',
    'containers.shmnstest_clone',
    'containers.shmnstest_unshare',
    'containers.shmem_2nstest_none',
    'containers.shmem_2nstest_clone',
    'containers.shmem_2nstest_unshare',
    'containers.mesgq_nstest_none',
    'containers.mesgq_nstest_clone',
    'containers.mesgq_nstest_unshare',
    'containers.sem_nstest_none',
    'containers.sem_nstest_clone',
    'containers.sem_nstest_unshare',
    'containers.semtest_2ns_none',
    'containers.semtest_2ns_clone',
    'containers.semtest_2ns_unshare',
    'fs_bind.BindMounts',
    'filecaps.Filecaps',
    'cap_bounds.Cap_bounds',
    'fcntl-locktests_android.FCNTL_LOCKTESTS',
    'admin_tools.su01',
    'admin_tools.cron02',
    'admin_tools.cron_deny01',
    'admin_tools.cron_allow01',
    'admin_tools.cron_dirs_checks01',
    'numa.move_pages03',
    'numa.move_pages11',
    'hugetlb.hugemmap05_1',
    'hugetlb.hugemmap05_2',
    'hugetlb.hugemmap05_3',
    'commands.ar',
    'commands.ld',
    'commands.nm',
    'commands.objdump',
    'commands.file',
    'commands.tar',
    'commands.cron',
    'commands.logrotate',
    'commands.mail',
    'commands.cpio',
    'commands.unzip01',
    'commands.cp_tests01',
    'commands.ln_tests01',
    'commands.mkdir_tests01',
    'commands.mv_tests01',
    'commands.size01',
    'commands.sssd01',
    'commands.sssd02',
    'commands.sssd03',
    'commands.du01',
    'commands.mkfs01',
    'commands.lsmod01',
    'commands.wc01',
    'hyperthreading.smt_smp_enabled',
    'hyperthreading.smt_smp_affinity',
    'kernel_misc.zram03',
    'fs_ext4.ext4-uninit-groups',
    'fs_ext4.ext4-persist-prealloc',
    'cpuhotplug.cpuhotplug03',
    'cpuhotplug.cpuhotplug06',
    'input.input06',
    'dio.dio10',
    'fsx.fsx-linux',
    'dio.dio04',
    'numa.Numa-testcases',
    'syscalls.connect01',
    'syscalls.prot_hsymlinks',
    'fs.ftest01',
    'fs.ftest03',
    'fs.ftest04',
    'fs.ftest05',
    'fs.ftest07',
    'fs.ftest08',
    'fs.inode02',
    'ipc.signal_test_01',
    'mm.data_space',
    'mm.mmapstress01',
    'mm.mmapstress03',
    'mm.mmapstress09',
    'mm.mmapstress10',
    'syscalls.clock_nanosleep01',
    'syscalls.clone04',
    'syscalls.fcntl14',
    'syscalls.fcntl14',
    'syscalls.fcntl14_64',
    'syscalls.fcntl17',
    'syscalls.fcntl17_64',
    'syscalls.getdomainname01',
    'syscalls.kill12',
    'syscalls.setdomainname01',
    'syscalls.setdomainname02',
    'syscalls.setdomainname03',
    'syscalls.sighold02',
    'syscalls.sigpending02',
    'syscalls.sigrelse01',
    'syscalls.vfork02',
    # The following tests are not stable on 64bit version
    'input.input01_64bit',
    'input.input02_64bit',
    'input.input03_64bit',
    'input.input04_64bit',
    'input.input05_64bit',
    'input.input06_64bit',
    # The following tests are failing on 64bit version
    'mm.overcommit_memory01_64bit',
    'mm.overcommit_memory02_64bit',
    'mm.overcommit_memory03_64bit',
    'mm.overcommit_memory04_64bit',
    'mm.overcommit_memory05_64bit',
    'mm.overcommit_memory06_64bit',
    # 'which' in Android does not accept the tested options b/31152668
    'commands.which01',
    # tests that are currently killing some lab devices 64bit on (pixel and bullhead)
    # b/31181781
    'mm.oom01_64bit',
    'mm.oom02_64bit',
    'mm.oom03_64bit',
    'mm.oom04_64bit',
    'mm.oom05_64bit',
    'mm.swapping01_64bit',
    'mm.thp01_64bit',
    'mm.thp02_64bit',
    'mm.thp03_64bit',
    'mm.vma01_64bit',
    # kmsg01 would pass but it occasionally causes socket timeout and misalignment
    # of request and response
    # b/32343072
    'kernel_misc.kmsg01',
    # alarm02 tests for a boundary condition which is impractical to implement
    # correctly on 32-bit Linux.  bionic deliberately breaks with POSIX by reporting
    # that it failed to set up the alarm.  (Other libc implementations fail to
    # set up the alarm too, but then return 0 anyway.)
    'syscalls.alarm02',
    # readdir02 calls opendir() -> closedir() -> readdir() and checks if readdir()
    # returns EBADF.  POSIX doesn't require this, and bionic is likely to instead
    # deadlock trying to acquire a destroyed mutex.
    'syscalls.readdir02',
    # Android sets RLIMIT_NICE to 40, so setpriority02 succeeds unexpectedly
    'syscalls.setpriority02',
    # fork13 takes ~45 minutes to run
    'syscalls.fork13',
    # open13 tests that fchmod() fails on fds opened with O_PATH.  bionic
    # deliberately masks the EBADF returned by the kernel.
    #
    # https://android-review.googlesource.com/#/c/127908/
    'syscalls.open13',
    # Bug#30675453
    'syscalls.perf_event_open02',
    # Bug#30688551
    'syscalls.lstat03_64',
    'syscalls.lstat03',
    # Bug#30688061
    'input.input03',
    # Bug#30688056
    'cpuhotplug.cpuhotplug04',
    # Bug#30699880
    'mm.mtest01w',
    'mm.mtest01',
    # Bug#30688574
    'syscalls.accept4_01',
    # Bug#30689411
    'mm.mmapstress03',
    # Bug #32100169
    'dma_thread_diotest.dma_thread_diotest1',
    'dma_thread_diotest.dma_thread_diotest2',
    'dma_thread_diotest.dma_thread_diotest3',
    'dma_thread_diotest.dma_thread_diotest4',
    'dma_thread_diotest.dma_thread_diotest5',
    'dma_thread_diotest.dma_thread_diotest6',
    'dma_thread_diotest.dma_thread_diotest7',
    # b/33008689 (closed) requires mkfs.ext4 and loop device support.
    'fs.quota_remount_test01',
]
