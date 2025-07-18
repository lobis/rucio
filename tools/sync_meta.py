#!/usr/bin/env python
# Copyright European Organization for Nuclear Research (CERN) since 2012
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os.path
import sys

base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_path)
os.chdir(base_path)

import sys  # noqa: E402
import traceback  # noqa: E402

from rucio.client import Client  # noqa: E402
from rucio.common.exception import Duplicate  # noqa: E402

UNKNOWN = 3
CRITICAL = 2
WARNING = 1
OK = 0

if __name__ == '__main__':

    meta_keys = [('project', 'ALL', None, ['data13_hip', 'NoProjectDefined']),
                 ('run_number', 'ALL', None, ['NoRunNumberDefined']),
                 ('stream_name', 'ALL', None, ['NoStreamNameDefined']),
                 ('prod_step', 'ALL', None, ['merge', 'recon', 'simul', 'evgen', 'NoProdstepDefined', 'user']),
                 ('datatype', 'ALL', None, ['HITS', 'AOD', 'EVNT', 'NTUP_TRIG', 'NTUP_SMWZ', 'NoDatatypeDefined', 'DPD']),
                 ('version', 'ALL', None, []),
                 ('campaign', 'ALL', None, []),
                 ('guid', 'FILE', r'^(\{){0,1}[0-9a-fA-F]{8}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{4}-?[0-9a-fA-F]{12}(\}){0,1}$', []),
                 ('events', 'DERIVED', r'^\d+$', [])]

    c = Client()
    for key, key_type, value_regexp, values in meta_keys:
        try:
            try:
                c.add_key(key=key, key_type=key_type, value_regexp=value_regexp)
            except Duplicate:
                print(f'{key} already added')

            for value in values:

                try:
                    c.add_value(key=key, value=value)
                except Duplicate:
                    print(f'{key}:{value} already added')

                if key == 'project':
                    try:
                        c.add_scope('root', value)
                    except Duplicate:
                        print(f'Scope {value} already added')
        except Exception:
            errno, errstr = sys.exc_info()[:2]
            trcbck = traceback.format_exc()
            print('Interrupted processing with %s %s %s.' % (errno, errstr, trcbck))

    sys.exit(OK)
