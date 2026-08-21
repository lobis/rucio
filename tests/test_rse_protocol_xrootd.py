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
from urllib.parse import parse_qs, urlsplit

import pytest

from rucio.common.utils import execute
from rucio.rse import rsemanager
from rucio.rse.protocols import xrootd
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
    protocol = xrootd.Default.__new__(xrootd.Default)
    protocol.auth_token = auth_token
    protocol._Default__fs = None
    protocol._Default__token_file = None
    protocol._Default__x509_proxy = x509_proxy
    protocol._Default__credential_id = credential_id
    return protocol


def test_native_xrootd_requires_version_6_or_newer():
    assert not xrootd._is_supported_xrootd_version(_XRootDClient('5.8.4'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.0.0'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.0.3'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('6.1.0'))
    assert xrootd._is_supported_xrootd_version(_XRootDClient('v6.1.0'))


def test_native_xrootd_copy_keeps_token_out_of_parent_environment(monkeypatch):
    protocol = _protocol(auth_token='transfer-token')
    captured = {}

    monkeypatch.setenv('XrdSecPROTOCOL', 'gsi')
    monkeypatch.setenv('BEARER_TOKEN', 'old-token')

    def run_worker(command, *, input, env, **kwargs):
        captured['command'] = command
        captured['request'] = json.loads(input)
        captured['env'] = env
        response = {
            'result': {
                'prepare_status': {'ok': True, 'message': '', 'code': 0, 'errNotFound': None},
                'copy_status': {'ok': True, 'message': '', 'code': 0, 'errNotFound': None},
                'copy_results': [],
            },
        }
        return type('CompletedProcess', (), {
            'returncode': 0,
            'stdout': '{}{}'.format(xrootd._WORKER_RESULT_PREFIX, json.dumps(response)),
            'stderr': '',
        })()

    monkeypatch.setattr(xrootd.subprocess, 'run', run_worker)

    protocol._copy('root://example.com//source', '/tmp/destination')

    source = captured['request']['source']
    query = parse_qs(urlsplit(source).query)
    token_path = query['xrd.ztn'][0]
    assert query['xrd.wantprot'] == ['ztn']
    assert query['xrdcl.intent'] == ['rucio-credential-id']
    assert os.stat(token_path).st_mode & 0o777 == 0o600
    assert captured['env']['BEARER_TOKEN_FILE'] == token_path
    assert captured['env']['XrdSecPROTOCOL'] == 'ztn'
    assert 'BEARER_TOKEN' not in captured['env']
    assert os.environ['XrdSecPROTOCOL'] == 'gsi'
    assert os.environ['BEARER_TOKEN'] == 'old-token'

    protocol.close()
    assert not os.path.exists(token_path)


def test_native_xrootd_worker_runs_copy_with_url_token(monkeypatch):
    client = _XRootDClient()
    protocol = _protocol(auth_token='transfer-token')
    source = protocol._authenticated_url('root://example.com//source')

    monkeypatch.setattr(xrootd, '_xrootd_client', client)

    result = xrootd._execute_isolated_request({
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


def test_native_xrootd_pins_proxy_and_channel_identity_in_url(monkeypatch):
    client = _XRootDClient()
    protocol = _protocol(x509_proxy='/tmp/proxy', credential_id='proxy-identity')
    protocol.scheme = 'root'
    protocol.hostname = 'example.com'
    protocol.port = '1094'

    monkeypatch.setattr(xrootd, '_xrootd_client', client)

    protocol._filesystem()

    query = parse_qs(urlsplit(client.filesystem_url).query)
    assert query == {
        'xrd.gsiusrpxy': ['/tmp/proxy'],
        'xrd.wantprot': ['gsi'],
        'xrdcl.intent': ['rucio-proxy-identity'],
    }


def test_native_xrootd_stat_accepts_bytes_checksum(monkeypatch):
    protocol = _protocol()
    protocol.logger = lambda *args, **kwargs: None
    protocol.rse = {'verify_checksum': True}
    protocol._filesystem = lambda: _FileSystem()

    monkeypatch.setattr(xrootd, '_xrootd_flags', _Flags)

    assert protocol.stat('/tmp/file') == {'filesize': '1234', 'adler32': 'deadbeef'}


def test_native_xrootd_rename_ignores_existing_directory(monkeypatch):
    fs = _FileSystem()
    protocol = _protocol()
    protocol.logger = lambda *args, **kwargs: None
    protocol._filesystem = lambda: fs
    protocol.exists = lambda pfn: True
    protocol.pfn2path = lambda pfn: pfn

    monkeypatch.setattr(xrootd, '_xrootd_flags', _Flags)

    protocol.rename('/tmp/file.rucio.upload', '/tmp/file')

    assert fs.renamed


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
