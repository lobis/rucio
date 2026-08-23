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

import json
import os
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock
from urllib.parse import parse_qs, urlsplit

import pytest

from rucio.common import exception
from rucio.common.utils import execute
from rucio.rse import rsemanager
from rucio.rse.protocols import posix, xrootd, xrootd_worker
from rucio.tests.common import load_test_conf_file, skip_rse_tests_with_accounts

from .rsemgr_api_test import MgrTestCases


class _Status:
    def __init__(self, ok=True, message=''):
        self.ok = ok
        self.message = message


class _StatInfo:
    size = 1234


class _QueryCode:
    CHECKSUM = 'checksum'


class _MkDirFlags:
    MAKEPATH = 'makepath'


class _Flags:
    QueryCode = _QueryCode
    MkDirFlags = _MkDirFlags


class _FileSystem:
    def __init__(self):
        self.renamed = False

    def stat(self, path):
        return _Status(), _StatInfo()

    def query(self, query_code, path):
        return _Status(), b'adler32 deadbeef\n\0'

    def mkdir(self, path, flags):
        return _Status(ok=False, message='[ERROR] Unable to mkdir {}; file exists'.format(path)), None

    def mv(self, path, new_path):
        self.renamed = True
        return _Status(), None


class _XRootDClient:
    def __init__(self, version='6.0.0'):
        self.__version__ = version
        self.copy_process = None
        self.filesystem_url = None

    def CopyProcess(self):  # noqa: N802 - match XRootD client API
        self.copy_process = _CopyProcess()
        return self.copy_process

    def FileSystem(self, url):  # noqa: N802 - match XRootD client API
        self.filesystem_url = url
        return _FileSystem()


class _CopyProcess:
    def __init__(self):
        self.job = None
        self.run_token = None

    def add_job(self, source, target, **kwargs):
        self.job = (source, target, kwargs)

    def prepare(self):
        return _Status()

    def run(self):
        source = self.job[0]
        token_path = parse_qs(urlsplit(source).query)['xrd.ztn'][0]
        with open(token_path) as token_file:
            self.run_token = token_file.read()
        return _Status(), []


def _protocol(auth_token=None, x509_proxy=None, credential_id='credential-id'):
    protocol = object.__new__(xrootd.Default)
    protocol.auth_token = auth_token
    protocol.scheme = 'root'
    protocol.hostname = 'example.com'
    protocol.port = '1094'
    protocol._Default__auth_mode = 'ztn' if auth_token else 'gsi'
    protocol._Default__token_file = None
    protocol._Default__proxy_file = None
    protocol._Default__worker = None
    protocol._Default__worker_lock = threading.Lock()
    protocol._Default__x509_proxy = x509_proxy
    protocol._Default__credential_id = credential_id
    return protocol


def test_native_xrootd_requires_version_6_or_newer():
    assert not xrootd._is_supported_xrootd_version(_XRootDClient('5.8.4'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.0.0'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.0.3'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.1.0'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('v6.1.0'))


def test_rsemanager_falls_back_from_missing_optional_binding(monkeypatch):
    native_impl = 'rucio.rse.protocols.xrootd.Default'
    fallback_impl = 'rucio.rse.protocols.posix.Default'
    protocol_template = {
        'scheme': 'root',
        'hostname': 'example.com',
        'port': 1094,
        'prefix': '/',
        'extended_attributes': None,
    }
    rse_settings = {
        'rse': 'MOCK',
        'deterministic': False,
        'protocols': [
            {
                **protocol_template,
                'impl': native_impl,
                'domains': {'wan': {'read': 1}},
            },
            {
                **protocol_template,
                'impl': fallback_impl,
                'domains': {'wan': {'read': 2}},
            },
        ],
    }
    monkeypatch.setattr(xrootd, '_xrootd_client', None)

    result = rsemanager.create_protocol(
        rse_settings,
        'read',
        scheme='root',
        auth_token='transfer-token',
    )

    assert isinstance(result, posix.Default)
    assert all('auth_token' not in protocol for protocol in rse_settings['protocols'])
    with pytest.raises(exception.MissingDependency):
        rsemanager.create_protocol(rse_settings, 'read', scheme='root', impl=native_impl)


def test_xrootd_url_operations_do_not_require_optional_binding(monkeypatch):
    protocol = {
        'scheme': 'root',
        'hostname': 'example.com',
        'port': 1094,
        'prefix': '/rucio/',
        'impl': 'rucio.rse.protocols.xrootd.Default',
        'domains': {'wan': {'read': 1, 'write': 1, 'delete': 1}},
    }
    rse_settings = {
        'rse': 'MOCK',
        # Keep this URL-only test independent of server-side VO policy
        # lookups, which require a persisted RSE id.
        'deterministic': False,
        'protocols': [protocol],
    }
    pfn = 'root://example.com:1094/rucio/mock/file'

    monkeypatch.setattr(xrootd, '_xrootd_client', None)

    assert rsemanager.lfns2pfns(
        rse_settings,
        {'scope': 'mock', 'name': 'file', 'path': 'mock/file'},
        scheme='root',
    ) == {'mock:file': pfn}
    assert rsemanager.parse_pfns(rse_settings, [pfn])[pfn]['name'] == 'file'


@pytest.mark.parametrize('operation_error', [None, exception.ServiceUnavailable('stat failed')])
def test_rsemanager_exists_always_closes_protocol(monkeypatch, operation_error):
    protocol = MagicMock()
    protocol.exists.side_effect = operation_error
    if operation_error is None:
        protocol.exists.return_value = False

    monkeypatch.setattr(rsemanager, 'create_protocol', lambda *_args, **_kwargs: protocol)
    monkeypatch.setattr(rsemanager.utils, 'is_method_overridden', lambda *_args, **_kwargs: True)

    if operation_error is None:
        assert not rsemanager.exists({}, '/tmp/file')
    else:
        with pytest.raises(exception.ServiceUnavailable):
            rsemanager.exists({}, '/tmp/file')

    protocol.close.assert_called_once()


def test_native_xrootd_copy_keeps_token_out_of_parent_environment(monkeypatch):
    protocol = _protocol(auth_token='transfer-token')
    captured = {'requests': [], 'processes': []}

    monkeypatch.setenv('XrdSecPROTOCOL', 'gsi')
    monkeypatch.setenv('BEARER_TOKEN', 'old-token')
    monkeypatch.setenv('PYTHONHOME', '/unsafe/python-home')
    monkeypatch.setenv('PYTHONPATH', '/unsafe/python-path')

    class FakeWorkerProcess:
        def __init__(self, command, env):
            self.command = command
            self.env = env
            self.returncode = None
            self.responses = []
            self.stdin = MagicMock()
            self.stdout = MagicMock()
            self.stdin.write.side_effect = self.write
            self.stdout.readline.side_effect = self.readline

        def write(self, request_line):
            request = json.loads(request_line)
            captured['requests'].append(request)
            if request['action'] == 'copy':
                result = {
                    'prepare_status': {'ok': True, 'message': '', 'code': 0, 'errNotFound': None},
                    'copy_status': {'ok': True, 'message': '', 'code': 0, 'errNotFound': None},
                    'copy_results': [],
                }
            else:
                result = {'status': {'ok': True, 'message': '', 'code': 0, 'errNotFound': None}}
            self.responses.append('{}{}\n'.format(
                xrootd._WORKER_RESULT_PREFIX,
                json.dumps({'result': result}),
            ))

        def readline(self):
            return self.responses.pop(0)

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    def start_worker(command, *, env, **_kwargs):
        captured['command'] = command
        captured['env'] = env
        process = FakeWorkerProcess(command, env)
        captured['processes'].append(process)
        return process

    monkeypatch.setattr(xrootd, '_xrootd_client', object())
    monkeypatch.setattr(xrootd, '_xrootd_module_path', lambda: '/trusted/site-packages')
    monkeypatch.setattr(xrootd.subprocess, 'Popen', start_worker)

    protocol._copy('root://example.com//source', '/tmp/destination')
    protocol._run_isolated({'action': 'exists'})

    source = captured['requests'][0]['source']
    query = parse_qs(urlsplit(source).query)
    token_path = query['xrd.ztn'][0]
    assert query['xrd.wantprot'] == ['ztn']
    assert query['xrdcl.intent'] == ['rucio']
    assert os.stat(token_path).st_mode & 0o777 == 0o600
    assert captured['env']['BEARER_TOKEN_FILE'] == token_path
    assert captured['env']['XrdSecPROTOCOL'] == 'ztn'
    assert 'BEARER_TOKEN' not in captured['env']
    assert 'PYTHONHOME' not in captured['env']
    assert 'PYTHONPATH' not in captured['env']
    assert captured['command'][:2] == [sys.executable, '-I']
    assert Path(captured['command'][2]).is_absolute()
    assert Path(captured['command'][2]).name == 'xrootd_worker.py'
    assert captured['command'][3] == '/trusted/site-packages'
    assert len(captured['processes']) == 1
    assert os.environ['XrdSecPROTOCOL'] == 'gsi'
    assert os.environ['BEARER_TOKEN'] == 'old-token'

    protocol.close()
    captured['processes'][0].stdin.close.assert_called_once()
    captured['processes'][0].stdout.close.assert_called_once()
    assert not os.path.exists(token_path)


def test_native_xrootd_gsi_worker_removes_ambient_credentials(monkeypatch, tmp_path):
    proxy = tmp_path / 'proxy'
    proxy.write_text('selected identity')
    protocol = _protocol(x509_proxy=str(proxy), credential_id='proxy-identity')
    captured = {}

    monkeypatch.setenv('HOME', str(tmp_path / 'ambient-home'))
    monkeypatch.setenv('XDG_RUNTIME_DIR', str(tmp_path / 'ambient-runtime'))
    monkeypatch.setenv('X509_USER_CERT', '/tmp/other-cert')
    monkeypatch.setenv('X509_USER_KEY', '/tmp/other-key')
    monkeypatch.setenv('X509_USER_PROXY', '/tmp/other-proxy')
    monkeypatch.setenv('XrdSecCREDS', 'other-credentials')
    monkeypatch.setenv('XrdSecGSIUSERPROXY', '/tmp/other-gsi-proxy')
    monkeypatch.setenv('XrdSecPROXYCREDS', 'other-proxy-credentials')
    monkeypatch.setenv('XrdSecUSER', 'other-user')

    class FakeWorkerProcess:
        def __init__(self):
            self.returncode = None
            self.responses = []
            self.stdin = MagicMock()
            self.stdout = MagicMock()
            self.stdin.write.side_effect = self.write
            self.stdout.readline.side_effect = self.readline

        def write(self, _request_line):
            result = {'status': {'ok': True, 'message': '', 'code': 0, 'errNotFound': None}}
            self.responses.append('{}{}\n'.format(
                xrootd._WORKER_RESULT_PREFIX,
                json.dumps({'result': result}),
            ))

        def readline(self):
            return self.responses.pop(0)

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def kill(self):
            self.returncode = -9

    def start_worker(_command, *, env, **_kwargs):
        captured['env'] = env
        captured['process'] = FakeWorkerProcess()
        return captured['process']

    monkeypatch.setattr(xrootd, '_xrootd_client', object())
    monkeypatch.setattr(xrootd, '_xrootd_module_path', lambda: '/trusted/site-packages')
    monkeypatch.setattr(xrootd.subprocess, 'Popen', start_worker)

    protocol._run_isolated({'action': 'exists'})

    worker_env = captured['env']
    assert worker_env['XrdSecPROTOCOL'] == 'gsi'
    assert worker_env['X509_USER_PROXY'] == str(proxy)
    assert worker_env['HOME'] != os.environ['HOME']
    assert worker_env['XDG_RUNTIME_DIR'] == worker_env['HOME']
    assert os.path.isdir(worker_env['HOME'])
    for key in (
        'BEARER_TOKEN',
        'BEARER_TOKEN_FILE',
        'X509_USER_CERT',
        'X509_USER_KEY',
        'XrdSecCREDS',
        'XrdSecGSIUSERPROXY',
        'XrdSecPROXYCREDS',
        'XrdSecUSER',
    ):
        assert key not in worker_env

    query = parse_qs(urlsplit(protocol._authenticated_url('root://example.com:1094')).query)
    assert query['xrd.gsiusrpxy'] == [str(proxy)]
    assert query['xrd.gsiusrcrt'] == [os.devnull]
    assert query['xrd.gsiusrkey'] == [os.devnull]

    worker_home = worker_env['HOME']
    protocol.close()
    assert not os.path.exists(worker_home)


def test_native_xrootd_gsi_worker_preserves_explicit_cert_key(monkeypatch, tmp_path):
    cert = tmp_path / 'cert.pem'
    key = tmp_path / 'key.pem'
    cert.write_text('certificate identity')
    key.write_text('private key identity')
    monkeypatch.setenv('X509_USER_CERT', str(cert))
    monkeypatch.setenv('X509_USER_KEY', str(key))
    captured = {}
    process = MagicMock()
    process.poll.return_value = None
    process.wait.return_value = 0

    def start_worker(_command, *, env, **_kwargs):
        captured['env'] = env
        return process

    monkeypatch.setattr(xrootd.subprocess, 'Popen', start_worker)
    worker = xrootd._CredentialWorker('/trusted/site-packages', 'gsi')
    try:
        worker._start()
        assert Path(captured['env']['X509_USER_CERT']).read_text() == cert.read_text()
        assert Path(captured['env']['X509_USER_KEY']).read_text() == key.read_text()
        assert 'X509_USER_PROXY' not in captured['env']
    finally:
        worker.close()


def test_native_xrootd_pins_explicit_cert_key(monkeypatch, tmp_path):
    cert = tmp_path / 'cert.pem'
    key = tmp_path / 'key.pem'
    cert.write_text('certificate identity')
    key.write_text('private key identity')
    monkeypatch.setenv('X509_USER_CERT', str(cert))
    monkeypatch.setenv('X509_USER_KEY', str(key))
    monkeypatch.delenv('RUCIO_CLIENT_PROXY', raising=False)
    monkeypatch.delenv('X509_USER_PROXY', raising=False)
    protocol = _protocol()
    protocol._configured_x509_proxy = lambda: None
    protocol._default_x509_proxy = lambda: None

    selected_cert, selected_key = protocol._valid_x509_cert_key()
    pinned_cert = protocol._snapshot_x509_cert(selected_cert)
    pinned_key = protocol._snapshot_x509_key(selected_key)
    protocol._Default__x509_proxy = None
    protocol._Default__x509_cert = pinned_cert
    protocol._Default__x509_key = pinned_key
    protocol._Default__credential_id = protocol._gsi_credential_id(None, pinned_cert, pinned_key)

    query = parse_qs(urlsplit(protocol._authenticated_url('root://example.com:1094')).query)
    assert Path(query['xrd.gsiusrcrt'][0]).read_text() == cert.read_text()
    assert Path(query['xrd.gsiusrkey'][0]).read_text() == key.read_text()
    assert 'xrd.gsiusrpxy' not in query

    protocol.close()
    assert not Path(pinned_cert).exists()
    assert not Path(pinned_key).exists()


def test_native_xrootd_scopes_workers_to_protocol_credentials(monkeypatch):
    workers = []

    class FakeWorker:
        def __init__(
                self, module_path, auth_mode, token_path=None, proxy_path=None,
                cert_path=None, key_path=None,
        ):
            self.module_path = module_path
            self.auth_mode = auth_mode
            self.token_path = token_path
            self.proxy_path = proxy_path
            self.cert_path = cert_path
            self.key_path = key_path
            workers.append(self)

        def request(self, _request):
            return {'status': {'ok': True}}

        def close(self):
            pass

    monkeypatch.setattr(xrootd, '_xrootd_client', object())
    monkeypatch.setattr(xrootd, '_xrootd_module_path', lambda: '/trusted/site-packages')
    monkeypatch.setattr(xrootd, '_CredentialWorker', FakeWorker)

    first = _protocol(x509_proxy='/tmp/first-proxy', credential_id='first')
    second = _protocol(x509_proxy='/tmp/second-proxy', credential_id='second')
    first._run_isolated({'action': 'exists'})
    second._run_isolated({'action': 'exists'})

    assert len(workers) == 2
    assert [worker.proxy_path for worker in workers] == ['/tmp/first-proxy', '/tmp/second-proxy']
    assert all(worker.auth_mode == 'gsi' for worker in workers)


def test_native_xrootd_worker_runs_copy_with_url_token(monkeypatch):
    client = _XRootDClient()
    protocol = _protocol(auth_token='transfer-token')
    source = protocol._authenticated_url('root://example.com//source')

    monkeypatch.setattr(xrootd_worker, '_client', lambda: client)

    result = xrootd_worker.execute_request({
        'action': 'copy',
        'source': source,
        'target': '/tmp/destination',
        'cptimeout': 0,
        'inittimeout': 600,
    })

    assert result['prepare_status']['ok']
    assert result['copy_status']['ok']
    assert client.copy_process.run_token == 'transfer-token'
    protocol.close()


def test_native_xrootd_pins_proxy_and_channel_identity_in_url():
    protocol = _protocol(x509_proxy='/tmp/proxy', credential_id='proxy-identity')

    query = parse_qs(urlsplit(protocol._authenticated_url('root://example.com:1094')).query)
    assert query == {
        'xrd.gsiusrcrt': [os.devnull],
        'xrd.gsiusrkey': [os.devnull],
        'xrd.gsiusrpxy': ['/tmp/proxy'],
        'xrd.wantprot': ['gsi'],
        'xrdcl.intent': ['rucio-proxy-identity'],
    }


def test_native_xrootd_reuses_only_unchanged_proxy_credentials(tmp_path):
    proxy = tmp_path / 'proxy'
    proxy.write_text('first credential')

    first_id = xrootd.Default._gsi_credential_id(str(proxy))
    second_id = xrootd.Default._gsi_credential_id(str(proxy))
    proxy.write_text('renewed credential')
    renewed_id = xrootd.Default._gsi_credential_id(str(proxy))

    assert first_id == second_id
    assert renewed_id != first_id


def test_native_xrootd_pins_proxy_contents_for_protocol_lifetime(tmp_path):
    proxy = tmp_path / 'proxy'
    proxy.write_text('first credential')
    protocol = _protocol()

    pinned_proxy = protocol._snapshot_x509_proxy(str(proxy))
    proxy.write_text('renewed credential')

    assert pinned_proxy is not None
    assert Path(pinned_proxy).read_text() == 'first credential'
    protocol.close()
    assert not Path(pinned_proxy).exists()


def test_native_xrootd_invalid_explicit_proxy_does_not_fall_through(monkeypatch, tmp_path):
    ambient_proxy = tmp_path / 'ambient-proxy'
    ambient_proxy.write_text('another identity')
    protocol = _protocol()
    protocol._configured_x509_proxy = lambda: None
    protocol._default_x509_proxy = lambda: None

    monkeypatch.setenv('RUCIO_CLIENT_PROXY', str(tmp_path / 'missing-proxy'))
    monkeypatch.setenv('X509_USER_PROXY', str(ambient_proxy))

    assert protocol._valid_x509_proxy() is None


@pytest.mark.parametrize('variable', ['RUCIO_CLIENT_PROXY', 'X509_USER_PROXY'])
def test_native_xrootd_empty_explicit_proxy_does_not_fall_through(monkeypatch, tmp_path, variable):
    fallback_proxy = tmp_path / 'fallback-proxy'
    fallback_proxy.write_text('different identity')
    protocol = _protocol()
    protocol._configured_x509_proxy = lambda: str(fallback_proxy) if variable == 'RUCIO_CLIENT_PROXY' else None
    protocol._default_x509_proxy = lambda: str(fallback_proxy)

    monkeypatch.delenv('RUCIO_CLIENT_PROXY', raising=False)
    monkeypatch.delenv('X509_USER_PROXY', raising=False)
    monkeypatch.setenv(variable, '')

    assert protocol._valid_x509_proxy() is None


def test_native_xrootd_unset_config_proxy_uses_default_proxy(monkeypatch, tmp_path):
    default_proxy = tmp_path / 'default-proxy'
    default_proxy.write_text('default identity')
    protocol = _protocol()
    protocol._default_x509_proxy = lambda: str(default_proxy)

    monkeypatch.delenv('RUCIO_CLIENT_PROXY', raising=False)
    monkeypatch.delenv('X509_USER_PROXY', raising=False)
    monkeypatch.setattr(xrootd, 'config_get', lambda *_args, **_kwargs: '$X509_USER_PROXY')

    assert protocol._valid_x509_proxy() == str(default_proxy)


def test_native_xrootd_close_cleans_credentials_after_worker_failure():
    protocol = _protocol()
    worker = MagicMock()
    worker.close.side_effect = RuntimeError('worker shutdown failed')
    token_file = MagicMock()
    proxy_file = MagicMock()
    cert_file = MagicMock()
    key_file = MagicMock()
    protocol._Default__worker = worker
    protocol._Default__token_file = token_file
    protocol._Default__proxy_file = proxy_file
    protocol._Default__cert_file = cert_file
    protocol._Default__key_file = key_file

    with pytest.raises(RuntimeError, match='worker shutdown failed'):
        protocol.close()

    token_file.close.assert_called_once()
    proxy_file.close.assert_called_once()
    cert_file.close.assert_called_once()
    key_file.close.assert_called_once()


def test_native_xrootd_status_failures_use_public_exception_contract():
    protocol = _protocol()

    with pytest.raises(exception.ServiceUnavailable):
        protocol._ensure_ok(_Status(ok=False, message='temporary failure'))

    with pytest.raises(exception.SourceNotFound):
        protocol._ensure_ok(_Status(ok=False, message='no such file'), source_not_found=True)


def test_native_xrootd_connect_normalizes_worker_errors():
    protocol = _protocol(auth_token='transfer-token')
    protocol.logger = MagicMock()
    protocol.hostname = 'example.com'
    protocol.port = '1094'
    protocol.scheme = 'root'
    protocol._run_isolated = MagicMock(side_effect=exception.ServiceUnavailable('worker failed'))

    with pytest.raises(exception.RSEAccessDenied):
        protocol.connect()


def test_native_xrootd_worker_serializes_not_found_details():
    status = _Status(ok=False, message='server error')
    status.shellcode = 54
    status.errno = 2

    serialized = xrootd_worker._serialize_status(status)

    assert serialized['shellcode'] == 54
    assert serialized['errno'] == 2
    assert _protocol()._is_not_found(serialized)

    serialized['errno'] = 3011
    assert _protocol()._is_not_found(serialized)

    serialized['errno'] = 3008
    assert not _protocol()._is_not_found(serialized)


def test_native_xrootd_stat_accepts_worker_checksum():
    protocol = _protocol()
    protocol.logger = lambda *args, **kwargs: None
    protocol.rse = {'verify_checksum': True}
    protocol._run_isolated = lambda _request: {
        'status': {'ok': True, 'message': ''},
        'stat_info': {'size': 1234},
        'checksum_status': {'ok': True, 'message': ''},
        'checksum': 'adler32 deadbeef\n\0',
    }

    assert protocol.stat('/tmp/file') == {'filesize': '1234', 'adler32': 'deadbeef'}


def test_native_xrootd_worker_decodes_bytes_checksum(monkeypatch):
    client = _XRootDClient()

    monkeypatch.setattr(xrootd_worker, '_client', lambda: client)
    monkeypatch.setattr(xrootd_worker, '_flags', lambda: _Flags)

    result = xrootd_worker.execute_request({
        'action': 'stat',
        'endpoint': 'root://example.com:1094',
        'path': '/tmp/file',
        'verify_checksum': True,
    })

    assert result['checksum'] == 'adler32 deadbeef\n\0'


def test_native_xrootd_rename_ignores_existing_directory():
    protocol = _protocol()
    protocol.logger = lambda *args, **kwargs: None
    protocol.pfn2path = lambda pfn: pfn
    protocol._run_isolated = MagicMock(return_value={
        'mkdir_status': {'ok': False, 'message': 'file exists'},
        'move_status': {'ok': True, 'message': ''},
    })

    protocol.rename('/tmp/file.rucio.upload', '/tmp/file')

    assert protocol._run_isolated.call_args.args[0]['action'] == 'rename'


def test_rsemanager_upload_normalizes_filesize_for_renaming(monkeypatch):
    write_protocol = MagicMock(renaming=True, overwrite=True)
    delete_protocol = MagicMock()
    pfn = 'root://example.com//file'
    write_protocol.lfns2pfns.return_value = {'mock:file': pfn}
    write_protocol.exists.return_value = False
    write_protocol.stat.return_value = {'filesize': '4'}

    def create_protocol(_rse_settings, operation, **_kwargs):
        return write_protocol if operation == 'write' else delete_protocol

    monkeypatch.setattr(rsemanager, 'create_protocol', create_protocol)

    result = rsemanager.upload(
        rse_settings={'rse': 'MOCK', 'verify_checksum': False},
        lfns={'scope': 'mock', 'name': 'file', 'filesize': 4, 'adler32': 'deadbeef'},
        source_dir='/tmp',
    )

    assert result['success'] is True
    write_protocol.rename.assert_called_once_with('%s.rucio.upload' % pfn, pfn)


@pytest.mark.noparallel(reason='creates and removes a test directory with a fixed name')
@skip_rse_tests_with_accounts
class TestRseXROOTD(MgrTestCases):

    @classmethod
    @pytest.fixture(scope='class')
    def setup_rse_and_files(cls, vo, tmp_path_factory):
        """XROOTD (RSE/PROTOCOLS): Creating necessary directories and files """

        cmd = "rucio list-rses --rses 'test_container_xrd=True'"
        print(cmd)
        exitcode, out, err = execute(cmd)
        print(out, err)
        rses = out.split()

        data = load_test_conf_file('rse_repository.json')
        prefix = data['WJ-XROOTD']['protocols']['supported']['xroot']['prefix']

        if len(rses) == 0:
            rse_name = 'WJ-XROOTD'
            hostname = data['WJ-XROOTD']['protocols']['supported']['xroot']['hostname']
        else:
            rse_name = 'XRD1'
            hostname = 'xrd1'
            prefix = '/rucio/'

        try:
            os.mkdir(prefix)
        except Exception as e:
            print(e)

        rse_settings, tmpdir, user = cls.setup_common_test_env(rse_name, vo, tmp_path_factory)

        protocol = rsemanager.create_protocol(rse_settings, 'write')
        protocol.connect()

        os.system('dd if=/dev/urandom of=%s/data.raw bs=1024 count=1024' % prefix)

        for f in cls.files_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'xrdcp %s/data.raw %s' % (prefix, path)
            execute(cmd)

        for f in MgrTestCases.files_local_and_remote:
            path = protocol.path2pfn(prefix + protocol._get_path('user.%s' % user, f))
            cmd = 'xrdcp %s/%s %s' % (tmpdir, f, path)
            execute(cmd)

        yield rse_settings, tmpdir, user

        clean_raw = '%s/data.raw' % prefix
        list_files_cmd_user = 'xrdfs %s ls %s/user.%s' % (hostname, prefix, user)
        clean_files = str(execute(list_files_cmd_user)[1]).split('\n')
        list_files_cmd_group = 'xrdfs %s ls %s/group.%s' % (hostname, prefix, user)
        clean_files += str(execute(list_files_cmd_group)[1]).split('\n')
        clean_files.append(clean_raw)
        for files in clean_files:
            clean_cmd = 'xrdfs %s rm %s' % (hostname, files)
            execute(clean_cmd)

        clean_prefix = '%s' % prefix
        list_directory = 'xrdfs %s ls %s' % (hostname, prefix)
        clean_directory = str(execute(list_directory)[1]).split('\n')
        clean_directory.append(clean_prefix)
        for directory in clean_directory:
            clean_cmd = 'xrdfs %s rmdir %s' % (hostname, directory)
            execute(clean_cmd)

    @pytest.fixture(autouse=True)
    def setup_obj(self, setup_rse_and_files, vo):
        rse_settings, tmpdir, user = setup_rse_and_files
        self.init(tmpdir=tmpdir, rse_settings=rse_settings, user=user, vo=vo)

    def test_delete_mgr_ok_dir(self):
        raise pytest.skip("Not implemented")
