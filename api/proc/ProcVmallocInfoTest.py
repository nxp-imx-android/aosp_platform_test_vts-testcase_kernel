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


class ProcVmallocInfoTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''
    /proc/vmallocinfo provides info on vmalloc'd ranges.
    '''

    start = 'lines'

    t_PLUS = literal_token(r'\+')
    t_SLASH = literal_token(r'/')
    t_STRING = r'[a-zA-Z\(\)_0-9\-@\.]+'
    t_ignore = ' '

    p_lines = repeat_rule('line')

    def p_line(self, p):
        '''line : addr_range NUMBER STRING NEWLINE
                | addr_range NUMBER STRING PLUS HEX_LITERAL SLASH HEX_LITERAL STRING NEWLINE
                | addr_range NUMBER STRING PLUS HEX_LITERAL SLASH HEX_LITERAL NEWLINE
                | addr_range NUMBER STRING PLUS HEX_LITERAL SLASH HEX_LITERAL \
                        STRING EQUALS NUMBER STRING NEWLINE
                | addr_range NUMBER STRING PLUS HEX_LITERAL SLASH HEX_LITERAL \
                        STRING EQUALS NUMBER STRING STRING NEWLINE'''
        p[0] = p[1:]

    def p_addr_range(self, p):
        'addr_range : HEX_LITERAL DASH HEX_LITERAL'
        p[0] = [p[1], p[3]]

    def get_path(self):
        return "/proc/vmallocinfo"
