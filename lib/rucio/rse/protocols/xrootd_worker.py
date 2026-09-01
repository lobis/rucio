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

"""Minimal credential-isolated worker for the native XRootD protocol.

This file is executed directly with Python's isolated mode.  It intentionally
does not import Rucio, so a worker cannot repeat server-side import effects such
as starting the Prometheus listener.
"""

from __future__ import annotations

import json
import sys
from importlib import import_module
from typing import Any, cast

WORKER_RESULT_PREFIX = 'RUCIO_XROOTD_RESULT='

if __name__ == '__main__' and len(sys.argv) > 1:
    # The parent passes the distribution root which it already imported and
    # version-checked. Isolated mode otherwise omits user-site installations.
    sys.path.insert(0, sys.argv[1])


def _client() -> Any:
    client = import_module('XRootD.client')
    version = getattr(client, '__version__', None)
    if version is not None:
        try:
            major, minor = (int(part) for part in str(version).lstrip('v').split('.')[:2])
        except (TypeError, ValueError):
            raise RuntimeError('Unsupported XRootD version: {}'.format(version))
        if (major, minor) < (6, 0):
            raise RuntimeError('XRootD 6.0.0 or newer is required')
    return client


def _flags() -> Any:
    return import_module('XRootD.client.flags')


def _serialize_status(status: Any) -> dict[str, Any]:
    def _json_scalar(value: Any) -> Any:
        if value is None or isinstance(value, (bool, int, float, str)):
            return value
        try:
            return int(value)
        except (TypeError, ValueError):
            return str(value)

    return {
        'ok': bool(getattr(status, 'ok', False)),
        'message': str(getattr(status, 'message', status)),
        'code': _json_scalar(getattr(status, 'code', None)),
        'errNotFound': _json_scalar(getattr(status, 'errNotFound', None)),
        'shellcode': _json_scalar(getattr(status, 'shellcode', None)),
        'errno': _json_scalar(getattr(status, 'errno', None)),
    }


def execute_request(request: dict[str, Any]) -> dict[str, Any]:
    xrootd_client = cast('Any', _client())
    action = request['action']

    if action == 'copy':
        copy_process = xrootd_client.CopyProcess()
        copy_process.add_job(
            request['source'],
            request['target'],
            force=True,
            mkdir=True,
            cptimeout=request['cptimeout'],
            inittimeout=request['inittimeout'],
        )
        prepare_status = copy_process.prepare()
        if getattr(prepare_status, 'ok', False):
            copy_status, copy_results = copy_process.run()
        else:
            copy_status, copy_results = prepare_status, []
        return {
            'prepare_status': _serialize_status(prepare_status),
            'copy_status': _serialize_status(copy_status),
            'copy_results': [
                {'status': _serialize_status(result['status'])}
                for result in copy_results or []
                if 'status' in result
            ],
        }

    filesystem = xrootd_client.FileSystem(request['endpoint'])
    if action == 'exists':
        status, _ = filesystem.stat(request['path'])
        return {'status': _serialize_status(status)}

    if action == 'stat':
        status, stat_info = filesystem.stat(request['path'])
        result: dict[str, Any] = {
            'status': _serialize_status(status),
            'stat_info': {'size': getattr(stat_info, 'size', None)},
        }
        if request['verify_checksum'] and getattr(status, 'ok', False):
            flags = cast('Any', _flags())
            checksum_status, checksum = filesystem.query(flags.QueryCode.CHECKSUM, request['path'])
            result['checksum_status'] = _serialize_status(checksum_status)
            result['checksum'] = checksum.decode() if isinstance(checksum, bytes) else checksum
        return result

    if action == 'connect':
        flags = cast('Any', _flags())
        status, _ = filesystem.query(
            flags.QueryCode.CONFIG,
            '{}:{}'.format(request['hostname'], request['port']),
            timeout=10,
        )
        return {'status': _serialize_status(status)}

    if action == 'delete':
        status, _ = filesystem.rm(request['path'])
        return {'status': _serialize_status(status)}

    if action == 'rename':
        flags = cast('Any', _flags())
        mkdir_status, _ = filesystem.mkdir(request['new_dir'], flags.MkDirFlags.MAKEPATH)
        mkdir_ok = (
            getattr(mkdir_status, 'ok', False)
            or 'file exists' in str(getattr(mkdir_status, 'message', '')).lower()
        )
        move_status = mkdir_status
        if mkdir_ok:
            move_status, _ = filesystem.mv(request['path'], request['new_path'])
        return {
            'mkdir_status': _serialize_status(mkdir_status),
            'move_status': _serialize_status(move_status),
        }

    raise ValueError('Unsupported isolated XRootD action: {}'.format(action))


def worker_main() -> None:
    for request_line in sys.stdin:
        try:
            request = json.loads(request_line)
            response = {'result': execute_request(request)}
        except Exception as error:
            response = {'error': '{}: {}'.format(type(error).__name__, error)}
        print('{}{}'.format(WORKER_RESULT_PREFIX, json.dumps(response)), flush=True)


if __name__ == '__main__':
    worker_main()
