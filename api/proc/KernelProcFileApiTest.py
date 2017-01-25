#!/usr/bin/env python
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

import logging

from vts.runners.host import asserts
from vts.runners.host import base_test_with_webdb
from vts.runners.host import const
from vts.runners.host import test_runner
from vts.utils.python.controllers import android_device


class KernelProcFileApiTest(base_test_with_webdb.BaseTestWithWebDbClass):
    """Test cases which check content of proc files."""

    def setUpClass(self):
        self.dut = self.registerController(android_device)[0]
        self.dut.shell.InvokeTerminal(
            "KernelApiTest")  # creates a remote shell instance.
        self.shell = self.dut.shell.KernelApiTest

    def ReadFileContent(self, filepath):
        """Read the content of a file and perform assertions.

        Args:
            filepath: string, path to file

        Returns:
            string, content of file"""
        cmd = "cat %s" % filepath
        results = self.shell.Execute(cmd)
        logging.info("%s: Shell command '%s' results: %s", filepath, cmd,
                     results)

        # checks the exit code
        asserts.assertEqual(results[const.EXIT_CODE][0], 0,
                            "%s: Error happened while reading the file." %
                            filepath)

        return results[const.STDOUT][0]

    def ConvertToInteger(self, text):
        """Check whether a given text is interger.

        Args:
            text, string

        Returns:
            bool, True if is integer
        """
        try:
            return int(text)
        except:
            asserts.fail("Content '%s' is not integer" % text)

    def testMmapRndBitsAndMmapRndBits(self):
        """Check the value of /proc/sys/vm/mmap_rnd_bits."""
        filepath = "/proc/sys/vm/mmap_rnd_bits"
        content = self.ReadFileContent(filepath)
        value = self.ConvertToInteger(content)
        asserts.assertTrue(
            value >= 8, "%s: bits of mmap_rnd_bits '%s' should be higher than 8"
            % (filepath, value))

    def testMmapRndBitsAndMmapRndCompatBits(self):
        """Check the value of /proc/sys/vm/mmap_rnd_bits."""
        filepath = "/proc/sys/vm/mmap_rnd_compat_bits"
        content = self.ReadFileContent(filepath)
        value = self.ConvertToInteger(content)
        asserts.assertTrue(
            value >= 8,
            "%s: bits of mmap_rnd_compat_bits '%s' should be higher than 8" %
            (filepath, value))


if __name__ == "__main__":
    test_runner.main()
