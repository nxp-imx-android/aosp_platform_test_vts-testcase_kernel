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
from vts.utils.python.file import file_utils

from ProcMemInfoTest import ProcMemInfoTest
from ProcZoneInfoTest import ProcZoneInfoTest
from ProcShowUidStatTest import ProcShowUidStatTest
from ProcCpuInfoTest import ProcCpuInfoTest
from ProcStatTest import ProcStatTest
from ProcVmallocInfoTest import ProcVmallocInfoTest
from ProcRemoveUidRangeTest import ProcRemoveUidRangeTest
from ProcQtaguidCtrlTest import ProcQtaguidCtrlTest
from ProcMapsTest import ProcMapsTest
from ProcSimpleFileTests import ProcKptrRestrictTest
from ProcSimpleFileTests import ProcMmapMinAddrTest
from ProcSimpleFileTests import ProcMmapRndBitsTest
from ProcSimpleFileTests import ProcMmapRndCompatBitsTest
from ProcSimpleFileTests import ProcOverCommitMemoryTest
from ProcSimpleFileTests import ProcRandomizeVaSpaceTest

TEST_OBJECTS = {
    ProcMemInfoTest(),
    ProcZoneInfoTest(),
    ProcShowUidStatTest(),
    ProcCpuInfoTest(),
    ProcStatTest(),
    ProcVmallocInfoTest(),
    ProcKptrRestrictTest(),
    ProcRandomizeVaSpaceTest(),
    ProcMmapMinAddrTest(),
    ProcMmapRndBitsTest(),
    ProcMmapRndCompatBitsTest(),
    ProcOverCommitMemoryTest(),
    ProcRemoveUidRangeTest(),
    ProcQtaguidCtrlTest(),
    ProcMapsTest(),
}

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

    def checkPermissionsAndExistence(self, path, check_permission):
        """Asserts that the specified path exists and has the correct permission.

        Args:
            path: string, path to validate existence and permissions
            check_permission: function which takes unix permissions in octal
                              format and returns True if the permissions are
                              correct, False otherwise.
        """
        asserts.assertTrue(
            file_utils.Exists(path, self.shell),
            "%s: File does not exist." % path)
        try:
            permission = file_utils.GetPermission(path, self.shell)
            asserts.assertTrue(
                check_permission(permission),
                "%s: File has invalid permissions (%s)" %
                (path, permission))
        except (ValueError, IOError) as e:
            asserts.fail("Failed to assert permissions: %s" % str(e))


    def runProcFileTest(self, test_object):
        """Reads from the file and checks that it parses and the content is valid.

        Args:
            test_object: inherits KernelProcFileTestBase, contains the test functions
        """
        self.checkPermissionsAndExistence(
            test_object.get_path(), test_object.get_permission_checker())

        logging.info("Testing format of %s" % (test_object.get_path()))
        asserts.assertTrue(
            test_object.prepare_test(self.shell), "Setup failed!")

        file_content = self.ReadFileContent(test_object.get_path())
        try:
            parse_result = test_object.parse_contents(file_content)
        except SyntaxError as e:
            asserts.fail("Failed to parse! " + str(e))
        asserts.assertTrue(
            test_object.result_correct(parse_result), "Results not valid!")

    def generateProcFileTests(self):
        """Run all proc file tests."""
        self.runGeneratedTests(test_func=self.runProcFileTest,
                settings=TEST_OBJECTS,
                name_func=lambda test_obj: "test" + test_obj.__class__.__name__)

    def ReadFileContent(self, filepath):
        """Read the content of a file and perform assertions.

        Args:
            filepath: string, path to file

        Returns:
            string, content of file
        """
        cmd = "cat %s" % filepath
        results = self.shell.Execute(cmd)
        logging.info("%s: Shell command '%s' results: %s", filepath, cmd,
                     results)

        # checks the exit code
        asserts.assertEqual(
            results[const.EXIT_CODE][0], 0,
            "%s: Error happened while reading the file." % filepath)

        return results[const.STDOUT][0]

    def testCheckConfigs(self):
        """Ensures all options from android-base.cfg are enabled."""

        logging.info("Testing existence of %s" % self.PROC_FILE_PATH)
        self.checkPermissionsAndExistence(
            self.PROC_FILE_PATH, file_utils.IsReadOnly)

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
            if (config_state == "y" and
                (config_name not in device_configs or
                 device_configs[config_name] not in ("y", "m"))):
                should_be_enabled.append(config_name)
            elif config_state == "n" and config_name in device_configs:
                should_not_be_set.append(config_name + "=" +
                                         device_configs[config_name])

        asserts.assertTrue(
            len(should_be_enabled) == 0 and len(should_not_be_set) == 0,
            ("The following kernel configs should be enabled: [%s].\n"
             "The following kernel configs should not be set: [%s]") %
            (", ".join(should_be_enabled), ", ".join(should_not_be_set)))

    def tearDownClass(self):
        """Deletes the temporary directory."""
        logging.info("Delete %s", self._temp_dir)
        shutil.rmtree(self._temp_dir)


if __name__ == "__main__":
    test_runner.main()
