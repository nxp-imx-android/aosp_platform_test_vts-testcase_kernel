#
# Copyright (C) 2017 The Android Open Source Project
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from vts.testcases.kernel.api.proc import KernelProcFileTestBase

from vts.utils.python.file import target_file_utils

# Test for /proc/sys/kernel/*.

class ProcCorePipeLimit(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/core_pipe_limit defines how many concurrent crashing
    processes may be piped to user space applications in parallel.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def get_path(self):
        return "/proc/sys/kernel/core_pipe_limit"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcDmesgRestrict(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/dmesg_restrict indicates whether unprivileged users are
    prevented from using dmesg.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result in [0, 1]

    def get_path(self):
        return "/proc/sys/kernel/dmesg_restrict"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcKptrRestrictTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/kptr_restrict determines whether kernel pointers are printed
    in proc files.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result >= 0 and result <= 4

    def get_path(self):
        return "/proc/sys/kernel/kptr_restrict"

    def get_permission_checker(self):
        """Get r/w file permission checker.
        """
        return target_file_utils.IsReadWrite


class ProcModulesDisabled(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/modules_disabled indicates if modules are allowed to be
    loaded.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result in [0, 1]

    def get_path(self):
        return "/proc/sys/kernel/modules_disabled"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcPanicOnOops(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/panic_on_oops controls kernel's behaviour on oops.'''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result in [0, 1]

    def get_path(self):
        return "/proc/sys/kernel/panic_on_oops"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcPerfEventMaxSampleRate(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/perf_event_max_sample_rate sets the maximum sample rate
    of performance events.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def get_path(self):
        return "/proc/sys/kernel/perf_event_max_sample_rate"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcPerfEventParanoid(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/perf_event_paranoid controls use of the performance
    events system by unprivileged users.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def get_path(self):
        return "/proc/sys/kernel/perf_event_paranoid"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcPidMax(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/pid_max is the pid allocation wrap value.'''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def get_path(self):
        return "/proc/sys/kernel/pid_max"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcRandomizeVaSpaceTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/kernel/randomize_va_space determines the address layout randomization
    policy for the system.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result >= 0 and result <= 2

    def get_path(self):
        return "/proc/sys/kernel/randomize_va_space"

    def get_permission_checker(self):
        """Get r/w file permission checker.
        """
        return target_file_utils.IsReadWrite


# Tests for /proc/sys/vm/*.

class ProcOverCommitMemoryTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/vm/overcommit_memory determines the kernel virtual memory accounting mode.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result >= 0 and result <= 2

    def get_path(self):
        return "/proc/sys/vm/overcommit_memory"

    def get_permission_checker(self):
        """Get r/w file permission checker.
        """
        return target_file_utils.IsReadWrite


class ProcMmapMinAddrTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/vm/mmap_min_addr specifies the minimum address that can be mmap'd.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def get_path(self):
        return "/proc/sys/vm/mmap_min_addr"

    def get_permission_checker(self):
        """Get r/w file permission checker.
        """
        return target_file_utils.IsReadWrite


class ProcMmapRndBitsTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/vm/mmap_rnd_(compat_)bits specifies the amount of randomness in mmap'd
    addresses. Must be >= 8.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result >= 8

    def get_path(self):
        return "/proc/sys/vm/mmap_rnd_bits"

    def get_permission_checker(self):
        """Get r/w file permission checker.
        """
        return target_file_utils.IsReadWrite


class ProcMmapRndCompatBitsTest(ProcMmapRndBitsTest):
    def get_path(self):
        return "/proc/sys/vm/mmap_rnd_compat_bits"


# Tests for /proc/sys/fs/*.

class ProcPipeMaxSize(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/fs/pipe-max-size reports the maximum size (in bytes) of
    individual pipes.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def get_path(self):
        return "/proc/sys/fs/pipe-max-size"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcProtectedHardlinks(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/fs/protected_hardlinks reports hardlink creation behavior.'''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result in [0, 1]

    def get_path(self):
        return "/proc/sys/fs/protected_hardlinks"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcProtectedSymlinks(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/fs/protected_symlinks reports symlink following behavior.'''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result in [0, 1]

    def get_path(self):
        return "/proc/sys/fs/protected_symlinks"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcSuidDumpable(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/sys/fs/suid_dumpable value can be used to query and set the core
    dump mode for setuid or otherwise protected/tainted binaries.
    '''

    def parse_contents(self, contents):
        return self.parse_line("{:d}\n", contents)[0]

    def result_correct(self, result):
        return result in [0, 1, 2]

    def get_path(self):
        return "/proc/sys/fs/suid_dumpable"

    def get_permission_checker(self):
        return target_file_utils.IsReadWrite


class ProcUptime(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/uptime tells how long the system has been running.'''

    def parse_contents(self, contents):
        return self.parse_line("{:f} {:f}\n", contents)[0]

    def get_path(self):
        return "/proc/uptime"
