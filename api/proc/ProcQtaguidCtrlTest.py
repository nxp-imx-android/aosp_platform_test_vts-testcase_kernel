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


class ProcQtaguidCtrlTest(KernelProcFileTestBase.KernelProcFileTestBase):
    '''
    /proc/net/xt_qtaguid/ctrl provides information about tagged sockets.
    '''

    start = 'content'

    t_EVENTS = literal_token(r'events')
    t_TAG = literal_token(r'tag')
    t_UID = literal_token(r'uid')
    t_PID = literal_token(r'pid')
    t_FCOUNT = literal_token(r'f_count')
    t_LPAREN = literal_token(r'\(')
    t_RPAREN = literal_token(r'\)')

    p_lines = repeat_rule('line', zero_ok=True)
    p_attrs = repeat_rule('attr')

    def p_content(self, p):
        'content : lines EVENTS COLON attrs NEWLINE'
        p[0] = p[1:]

    def p_line(self, p):
        'line : STRING EQUALS NUMBER SPACE TAG EQUALS HEX_LITERAL SPACE \
                LPAREN UID EQUALS NUMBER RPAREN SPACE PID EQUALS NUMBER SPACE \
                FCOUNT EQUALS NUMBER NEWLINE'
        p[0] = p[1:]

    def p_attr(self, p):
        'attr : SPACE STRING EQUALS NUMBER'
        p[0] = [p[2], p[4]]

    def get_path(self):
        return "/proc/net/xt_qtaguid/ctrl"
