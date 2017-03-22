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


class ProcMapsTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''/proc/self/maps provides currently mapped memory regions and permissions.'''

    start = 'lines'

    t_STRING = literal_token(r'[a-zA-Z\(\)_\-0-9@]+')
    t_PATH = r'/[^\0^\n]*'
    t_BRACKET_ITEM = r'\[[^\0^\n]*\]'
    t_DASH = r'-'

    t_ignore = r' '

    p_lines = repeat_rule('line')

    def p_line(self, p):
        'line : STRING STRING STRING STRING COLON STRING STRING source NEWLINE'
        rng = p[1].split('-')
        try:
            if len(rng) != 2:
                print 'Invalid address range format!'
                raise SyntaxError
            p[0] = [int(rng[0], 16), int(rng[1], 16), p[2], int(p[3], 16), int(p[4], 16),\
                    int(p[6], 16), int(p[7]), p[8]]
        except ValueError:
            print 'Invalid number!'
            raise SyntaxError

    def p_source(self, p):
        '''source : PATH
                  | BRACKET_ITEM
                  | empty'''
        if p[1] is None:
            p[0] = []
        else:
            p[0] = p[1]

    def get_path(self):
        return "/proc/self/maps"
