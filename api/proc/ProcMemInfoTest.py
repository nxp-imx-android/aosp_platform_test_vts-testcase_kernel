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

import KernelProcFileTestBase
from KernelProcFileTestBase import repeat_rule, literal_token


class ProcMemInfoTest(KernelProcFileTestBase.KernelProcFileTestBase):
    """
    /proc/meminfo reports statistics about memory usage on the system.

    No new fields should be added to the upstream implementation.
    """

    ALLOWED_FIELDS = {
        "MemTotal",
        "MemFree",
        "MemAvailable",
        "Buffers",
        "Cached",
        "SwapCached",
        "Active",
        "Inactive",
        "Active(anon)",
        "Inactive(anon)",
        "Active(file)",
        "Inactive(file)",
        "Unevictable",
        "Mlocked",
        "SwapTotal",
        "SwapFree",
        "Dirty",
        "Writeback",
        "AnonPages",
        "Mapped",
        "Shmem",
        "Slab",
        "SReclaimable",
        "SUnreclaim",
        "KernelStack",
        "PageTables",
        "NFS_Unstable",
        "Bounce",
        "WritebackTmp",
        "CommitLimit",
        "Committed_AS",
        "VmallocTotal",
        "VmallocUsed",
        "VmallocChunk",
    }

    t_KB = literal_token(r'kB')

    start = 'lines'
    p_lines = repeat_rule('line')

    def p_line(self, p):
        'line : STRING COLON SPACEs NUMBER SPACE KB NEWLINE'
        p[0] = [p[1], p[4]]

    def result_correct(self, parse_result):
        for line in parse_result:
            if line[0] not in self.ALLOWED_FIELDS:
                print "'%s' is an illegal field" % line[0]
                return False
        return True

    def get_path(self):
        return "/proc/meminfo"
