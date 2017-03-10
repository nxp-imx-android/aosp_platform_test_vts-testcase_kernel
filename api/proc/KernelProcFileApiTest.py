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

import gzip
import logging
import os
import shutil
import tempfile

from vts.runners.host import asserts
from vts.runners.host import base_test
from vts.runners.host import const
from vts.runners.host import test_runner
from vts.testcases.kernel.api.proc import required_kernel_configs as configs
from vts.utils.python.controllers import android_device


class KernelProcFileApiTest(base_test.BaseTestClass):
    """Test cases which check content of proc files.

    Attributes:
        _temp_dir: The temporary directory to which /proc/config.gz is copied.
    """

    PROC_FILE_PATH = "/proc/config.gz"

    def setUpClass(self):
        self.dut = self.registerController(android_device)[0]
        self.dut.shell.InvokeTerminal(
            "KernelApiTest")  # creates a remote shell instance.
        self.shell = self.dut.shell.KernelApiTest
        self._temp_dir = tempfile.mkdtemp()

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

    def testCheckConfigs(self):
        """Ensures all options from android-base.cfg are enabled."""
        self.dut.adb.pull("%s %s" % (self.PROC_FILE_PATH, self._temp_dir))
        logging.info("Adb pull %s to %s", self.PROC_FILE_PATH, self._temp_dir)

        localpath = os.path.join(self._temp_dir, "config.gz")
        with gzip.open(localpath, 'rb') as f:
            device_config_lines = [line.rstrip("\n") for line in f.readlines()]

        device_configs = dict()
        for line in device_config_lines:
            if line == "" or line.startswith("#"):
                continue
            config_name, config_state = line.split("=", 1)
            device_configs[config_name] = config_state

        should_be_enabled = []
        should_not_be_set = []
        for config_name, config_state in configs.CONFIGS.iteritems():
            if (config_state == "y" and (config_name not in device_configs or
                device_configs[config_name] not in ("y", "m"))):
                should_be_enabled.append(config_name)
            elif config_state == "n" and config_name in device_configs:
                should_not_be_set.append(
                    config_name + "=" + device_configs[config_name])

        asserts.assertTrue(
            len(should_be_enabled) == 0 and len(should_not_be_set) == 0,
            ("The following kernel configs should be enabled: [%s].\n"
             "The following kernel configs should not be set: [%s]") %
            (", ".join(should_be_enabled), ", ".join(should_not_be_set))
        )

    def tearDownClass(self):
        """Deletes the temporary directory."""
        logging.info("Delete %s", self._temp_dir)
        shutil.rmtree(self._temp_dir)


if __name__ == "__main__":
    test_runner.main()
