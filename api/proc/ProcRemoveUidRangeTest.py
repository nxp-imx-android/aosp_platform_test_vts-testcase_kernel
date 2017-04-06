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

import ProcShowUidStatTest
from vts.runners.host import const
from vts.utils.python.file import file_utils


class ProcRemoveUidRangeTest(ProcShowUidStatTest.ProcShowUidStatTest):
    '''
    /proc/uid_cputime/remove_uid_range can be written in order to remove uids
    from being shown when reading show_uid_stat.

    Format is '[start uid]-[end uid]'

    This is an Android specific file.

    Attributes:
        uid_remove: int, the uid that the test attempts to remove from show_uid_range
    '''

    def prepare_test(self, shell):
        # Remove the last uid
        results = shell.Execute('cat %s' % self.get_path())
        if results[const.EXIT_CODE][0] != 0:
            return False
        parsed = self.parse_contents(results[const.STDOUT][0])
        self.uid_remove = parsed[-1][0]

        results = shell.Execute('echo "%d-%d" > /proc/uid_cputime/remove_uid_range' % \
                (self.uid_remove, self.uid_remove))
        if results[const.EXIT_CODE][0] != 0:
            print "Failed to remove uid %d" % self.uid_remove
            return False
        return True

    def result_correct(self, results):
        for line in results:
            if self.uid_remove == line[0]:
                print line
                return False
        return True

    def get_path(self):
        return "/proc/uid_cputime/remove_uid_range"

    def get_permission_checker(self):
        """Get write-only file permission checker.
        """
        return file_utils.IsWriteOnly
