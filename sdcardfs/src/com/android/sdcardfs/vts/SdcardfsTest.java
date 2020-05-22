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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import com.android.tradefed.log.LogUtil.CLog;
import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
import org.junit.Test;
import org.junit.runner.RunWith;

@RunWith(DeviceJUnit4ClassRunner.class)
public final class SdcardfsTest extends BaseHostJUnit4Test {
    public static final String TAG = SdcardfsTest.class.getSimpleName();

    @Test
    public void testSdcardfsNotPresent() throws Exception {
        String cmd = "mount | grep \"type sdcardfs\"";
        CLog.i("Invoke shell command [" + cmd + "]");
        try {
            String output = getDevice().executeShellCommand(cmd);
            assertEquals("Found sdcardfs entries:" + output, output, "");
        } catch (Exception e) {
            fail("Could not run command [" + cmd + "] (" + e.getMessage() + ")");
        }
    }
}
