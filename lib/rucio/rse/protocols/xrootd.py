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

from __future__ import annotations

import json
import logging
import os
import subprocess  # noqa: S404 - required to isolate native XRootD credentials
import sys
from importlib import import_module, metadata
from tempfile import NamedTemporaryFile
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from uuid import uuid4

from packaging.version import InvalidVersion, Version

from rucio.common import exception
from rucio.common.checksum import PREFERRED_CHECKSUM
from rucio.common.config import config_get
from rucio.rse.protocols import protocol

if TYPE_CHECKING:
    from types import ModuleType

    from rucio.common.types import LoggerFunction, RSESettingsDict

_MIN_XROOTD_VERSION = Version('6.0.0')
_WORKER_RESULT_PREFIX = 'RUCIO_XROOTD_RESULT='


def _is_supported_xrootd_version(xrootd_client: ModuleType) -> bool:
    version = getattr(xrootd_client, '__version__', None)
    if version is None:
        try:
            version = metadata.version('xrootd')
        except metadata.PackageNotFoundError:
            return False
    try:
        return Version(str(version).lstrip('v')) >= _MIN_XROOTD_VERSION
    except InvalidVersion:
        return False


try:
    _xrootd_client: ModuleType | None = import_module('XRootD.client')
    _xrootd_flags: ModuleType | None = import_module('XRootD.client.flags')

    if not _is_supported_xrootd_version(_xrootd_client):
        _xrootd_client = None
        _xrootd_flags = None
except Exception:
    _xrootd_client = None
    _xrootd_flags = None


def _client() -> ModuleType:
    if _xrootd_client is None:
        raise exception.MissingDependency('Missing dependency : xrootd')
    return _xrootd_client


def _flags() -> ModuleType:
    if _xrootd_flags is None:
        raise exception.MissingDependency('Missing dependency : xrootd')
    return _xrootd_flags


class Default(protocol.RSEProtocol):
    """Implement access to RSEs using the native XRootD Python bindings."""

    _COPY_DEFAULT_TIMEOUT = 0

    def __init__(self, protocol_attr: dict[str, Any], rse_settings: RSESettingsDict, logger: LoggerFunction = logging.log) -> None:
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)

        self.scheme = self.attributes['scheme']
        self.hostname = self.attributes['hostname']
        self.port = str(self.attributes['port'])
        self.logger = logger
        self.__fs: Any | None = None
        self.__token_file: Any | None = None
        self.__x509_proxy = None if self.auth_token else self._valid_x509_proxy()
        self.__credential_id = uuid4().hex

    @property
    def _endpoint(self) -> str:
        return '{}://{}:{}'.format(self.scheme, self.hostname, self.port)

    @staticmethod
    def _status_ok(status: Any) -> bool:
        if isinstance(status, dict):
            return bool(status.get('ok', False))
        return bool(getattr(status, 'ok', False))

    @staticmethod
    def _status_message(status: Any) -> Any:
        if isinstance(status, dict):
            return status.get('message', status)
        return getattr(status, 'message', status)

    @staticmethod
    def _response_text(response: Any) -> Any:
        if isinstance(response, bytes):
            return response.decode()
        return response

    def _valid_x509_proxy(self) -> str | None:
        for proxy in (
            os.environ.get('RUCIO_CLIENT_PROXY'),
            self._configured_x509_proxy(),
            os.environ.get('X509_USER_PROXY'),
            self._default_x509_proxy(),
        ):
            expanded_proxy = self._expand_x509_proxy(proxy)
            if expanded_proxy:
                return expanded_proxy
        return None

    def _configured_x509_proxy(self) -> str | None:
        try:
            return config_get('client', 'client_x509_proxy', default=None, raise_exception=False)
        except Exception:
            return None

    @staticmethod
    def _default_x509_proxy() -> str | None:
        if hasattr(os, 'geteuid'):
            return '/tmp/x509up_u%d' % os.geteuid()
        return None

    @staticmethod
    def _expand_x509_proxy(proxy: str | None) -> str | None:
        if not proxy:
            return None
        expanded_proxy = os.path.expanduser(os.path.expandvars(proxy))
        if '$' in expanded_proxy:
            return None
        if os.path.isfile(expanded_proxy):
            return expanded_proxy
        return None

    def _token_path(self) -> str:
        if self.__token_file is None:
            token_file = NamedTemporaryFile(mode='w', encoding='utf-8', prefix='rucio-xrootd-token-')
            token_file.write(cast('str', self.auth_token))
            token_file.flush()
            self.__token_file = token_file
        return self.__token_file.name

    def _authenticated_url(self, url: str) -> str:
        parsed = urlsplit(url)
        if parsed.scheme not in ('root', 'xroot'):
            return url

        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query['xrdcl.intent'] = 'rucio-{}'.format(self.__credential_id)
        if self.auth_token:
            query['xrd.wantprot'] = 'ztn'
            query['xrd.ztn'] = self._token_path()
        else:
            query['xrd.wantprot'] = 'gsi'
            # Pin the credential choice made when this protocol was created.
            # /dev/null prevents a later process-wide proxy from being picked up
            # for an operation which intentionally has no usable proxy.
            query['xrd.gsiusrpxy'] = self.__x509_proxy or os.devnull
        return urlunsplit(parsed._replace(path=parsed.path or '/', query=urlencode(query, safe='/')))

    def _run_isolated(self, request: dict[str, Any]) -> dict[str, Any]:
        env = os.environ.copy()
        for key in ('XrdSecPROTOCOL', 'BEARER_TOKEN', 'BEARER_TOKEN_FILE', 'X509_USER_PROXY'):
            env.pop(key, None)
        env['XrdSecPROTOCOL'] = 'ztn'
        env['BEARER_TOKEN_FILE'] = self._token_path()

        process = subprocess.run(
            [sys.executable, '-m', __name__],
            input=json.dumps(request),
            text=True,
            capture_output=True,
            env=env,
            check=False,
        )
        result_line = next(
            (line for line in reversed(process.stdout.splitlines()) if line.startswith(_WORKER_RESULT_PREFIX)),
            None,
        )
        if process.returncode or result_line is None:
            message = process.stderr.strip() or process.stdout.strip() or 'Native XRootD worker failed'
            raise exception.ServiceUnavailable(message)

        try:
            response = json.loads(result_line[len(_WORKER_RESULT_PREFIX):])
        except (TypeError, json.JSONDecodeError) as error:
            raise exception.ServiceUnavailable('Invalid response from native XRootD worker') from error
        if 'error' in response:
            raise exception.ServiceUnavailable(response['error'])
        return cast('dict[str, Any]', response['result'])

    def _filesystem(self) -> Any:
        xrootd_client = cast('Any', _client())
        if self.__fs is None:
            self.__fs = xrootd_client.FileSystem(self._authenticated_url(self._endpoint))
        return cast('Any', self.__fs)

    def _is_not_found(self, status: Any) -> bool:
        if status is None:
            return False
        if isinstance(status, dict):
            not_found_code = status.get('errNotFound')
            return (
                not_found_code is not None and status.get('code') == not_found_code
                or 'No such file' in status.get('message', '')
            )
        return (
            getattr(status, 'code', None) == getattr(status, 'errNotFound', None)
            or 'No such file' in getattr(status, 'message', '')
        )

    def _is_file_exists(self, status: Any) -> bool:
        if status is None:
            return False
        return 'file exists' in str(self._status_message(status)).lower()

    def _ensure_ok(self, status: Any, source_not_found: bool = False) -> None:
        if status is not None and self._status_ok(status):
            return
        if source_not_found and self._is_not_found(status):
            raise exception.SourceNotFound(self._status_message(status))
        raise exception.RucioException(self._status_message(status))

    def _copy(self, source: str, target: str, transfer_timeout: int | None = None) -> None:
        timeout = int(transfer_timeout or self._COPY_DEFAULT_TIMEOUT)
        cptimeout = min(timeout, 65535) if timeout > 0 else 0
        inittimeout = min(timeout or 600, 65535)
        source = self._authenticated_url(source)
        target = self._authenticated_url(target)
        if self.auth_token:
            result = self._run_isolated({
                'action': 'copy',
                'source': source,
                'target': target,
                'cptimeout': cptimeout,
                'inittimeout': inittimeout,
            })
            prepare_status = result['prepare_status']
            copy_status = result['copy_status']
            copy_results = result['copy_results']
        else:
            xrootd_client = cast('Any', _client())
            copy_process = xrootd_client.CopyProcess()
            copy_process.add_job(
                source,
                target,
                force=True,
                mkdir=True,
                cptimeout=cptimeout,
                inittimeout=inittimeout,
            )
            prepare_status = copy_process.prepare()
            self._ensure_ok(prepare_status)
            copy_status, copy_results = copy_process.run()
        self._ensure_ok(prepare_status)
        if not self._status_ok(copy_status) and copy_results:
            copy_status = copy_results[0].get('status', copy_status)
        self._ensure_ok(copy_status, source_not_found=True)

    def path2pfn(self, path):
        """
            Returns a fully qualified PFN for the file referred by path.

            :param path: The path to the file.

            :returns: Fully qualified PFN.

        """
        self.logger(logging.DEBUG, 'xrootd.path2pfn: path: {}'.format(path))
        if not path.startswith('xroot') and not path.startswith('root'):
            if path.startswith('/'):
                return '%s://%s:%s/%s' % (self.scheme, self.hostname, self.port, path)
            else:
                return '%s://%s:%s//%s' % (self.scheme, self.hostname, self.port, path)
        else:
            return path

    def exists(self, pfn):
        """ Checks if the requested file is known by the referred RSE.

            :param pfn: Physical file name

            :returns: True if the file exists, False if it doesn't

            :raise  ServiceUnavailable
        """
        self.logger(logging.DEBUG, 'xrootd.exists: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            if self.auth_token:
                status = self._run_isolated({
                    'action': 'exists',
                    'endpoint': self._authenticated_url(self._endpoint),
                    'path': path,
                })['status']
            else:
                status, _ = self._filesystem().stat(path)
            if not self._status_ok(status):
                return False
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)

        return True

    def stat(self, path):
        """
        Returns the stats of a file.

        :param path: path to file

        :raises ServiceUnavailable: if some generic error occurred in the library.

        :returns: a dict with two keys, filesize and an element of GLOBALLY_SUPPORTED_CHECKSUMS.
        """
        self.logger(logging.DEBUG, f'xrootd.stat: path: {path}')
        ret = {}
        chsum = None
        if path.startswith('root:'):
            path = self.pfn2path(path)

        try:
            if self.auth_token:
                result = self._run_isolated({
                    'action': 'stat',
                    'endpoint': self._authenticated_url(self._endpoint),
                    'path': path,
                    'verify_checksum': self.rse.get('verify_checksum', True),
                })
                status = result['status']
                stat_info = result['stat_info']
            else:
                status, stat_info = self._filesystem().stat(path)
            self._ensure_ok(status, source_not_found=True)
            ret['filesize'] = str(stat_info['size'] if isinstance(stat_info, dict) else getattr(stat_info, 'size'))

            if not self.rse.get('verify_checksum', True):
                return ret

            if self.auth_token:
                status = result['checksum_status']
                checksum = result['checksum']
            else:
                flags = cast('Any', _flags())
                status, checksum = self._filesystem().query(flags.QueryCode.CHECKSUM, path)
            if self._status_ok(status):
                checksum = self._response_text(checksum)
                chsum, value = checksum.strip('\n\0').split()
                ret[chsum] = value

        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)

        if 'filesize' not in ret:
            raise exception.ServiceUnavailable('Filesize could not be retrieved.')
        if PREFERRED_CHECKSUM != chsum or not chsum:
            msg = '{} does not match with {}'.format(chsum, PREFERRED_CHECKSUM)
            raise exception.RSEChecksumUnavailable(msg)

        return ret

    def pfn2path(self, pfn):
        """
        Returns the path of a file given the pfn, i.e. scheme and hostname are subtracted from the pfn.

        :param path: pfn of a file

        :returns: path.
        """
        self.logger(logging.DEBUG, 'xrootd.pfn2path: pfn: {}'.format(pfn))
        if pfn.startswith('//'):
            return pfn
        elif pfn.startswith('/'):
            return '/' + pfn
        else:
            prefix = self.attributes['prefix']
            path = pfn.partition(self.attributes['prefix'])[2]
            path = prefix + path
            return path

    def lfns2pfns(self, lfns):
        """
        Returns a fully qualified PFN for the file referred by path.

        :param path: The path to the file.

        :returns: Fully qualified PFN.
        """
        self.logger(logging.DEBUG, 'xrootd.lfns2pfns: lfns: {}'.format(lfns))
        pfns = {}
        prefix = self.attributes['prefix']

        if not prefix.startswith('/'):
            prefix = ''.join(['/', prefix])
        if not prefix.endswith('/'):
            prefix = ''.join([prefix, '/'])

        lfns = [lfns] if isinstance(lfns, dict) else lfns
        for lfn in lfns:
            scope, name = lfn['scope'], lfn['name']
            if 'path' in lfn and lfn['path'] is not None:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, lfn['path']])
            else:
                pfns['%s:%s' % (scope, name)] = ''.join([self.attributes['scheme'], '://', self.attributes['hostname'], ':', str(self.attributes['port']), prefix, self._get_path(scope=scope, name=name)])
        return pfns

    def connect(self):
        """ Establishes the actual connection to the referred RSE.

            :param credentials: Provides information to establish a connection
                to the referred storage system. For S3 connections these are
                access_key, secretkey, host_base, host_bucket, progress_meter
                and skip_existing.

            :raises RSEAccessDenied
        """
        self.logger(logging.DEBUG, 'xrootd.connect: port: {}, hostname {}'.format(self.port, self.hostname))
        try:
            if self.auth_token:
                status = self._run_isolated({
                    'action': 'connect',
                    'endpoint': self._authenticated_url(self._endpoint),
                    'hostname': self.hostname,
                    'port': self.port,
                })['status']
            else:
                flags = cast('Any', _flags())
                status, _ = self._filesystem().query(flags.QueryCode.CONFIG, '{}:{}'.format(self.hostname, self.port), timeout=10)
            if not self._status_ok(status):
                raise exception.RSEAccessDenied(self._status_message(status))
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        self.__fs = None
        if self.__token_file is not None:
            self.__token_file.close()
            self.__token_file = None

    def get(self, pfn, dest, transfer_timeout=None):
        """ Provides access to files stored inside connected the RSE.

            :param pfn: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible, ServiceUnavailable, SourceNotFound
        """
        self.logger(logging.DEBUG, 'xrootd.get: pfn: {}'.format(pfn))
        try:
            self._copy(pfn, dest, transfer_timeout=transfer_timeout)
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def put(self, filename, target, source_dir, transfer_timeout=None):
        """
            Allows to store files inside the referred RSE.

            :param source: path to the source file on the client file system
            :param target: path to the destination file on the storage
            :param source_dir: Path where the to be transferred files are stored in the local file system
            :param transfer_timeout: Transfer timeout (in seconds) - dummy

            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        self.logger(logging.DEBUG, 'xrootd.put: filename: {} target: {}'.format(filename, target))
        source_dir = source_dir or '.'
        source_url = '%s/%s' % (source_dir, filename)
        self.logger(logging.DEBUG, 'xrootd put: source url: {}'.format(source_url))
        path = self.path2pfn(target)
        if not os.path.exists(source_url):
            raise exception.SourceNotFound()
        try:
            self._copy(os.path.abspath(source_url), path, transfer_timeout=transfer_timeout)
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def delete(self, pfn):
        """
            Deletes a file from the connected RSE.

            :param pfn: Physical file name

            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        self.logger(logging.DEBUG, 'xrootd.delete: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            if self.auth_token:
                status = self._run_isolated({
                    'action': 'delete',
                    'endpoint': self._authenticated_url(self._endpoint),
                    'path': path,
                })['status']
            else:
                status, _ = self._filesystem().rm(path)
            self._ensure_ok(status, source_not_found=True)
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn:      Current physical file name
            :param new_pfn  New physical file name
            :raises DestinationNotAccessible: if the destination storage was not accessible.
            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        self.logger(logging.DEBUG, 'xrootd.rename: pfn: {}'.format(pfn))
        if not self.exists(pfn):
            raise exception.SourceNotFound()
        try:
            path = self.pfn2path(pfn)
            new_path = self.pfn2path(new_pfn)
            new_dir = new_path[:new_path.rindex('/') + 1]
            if self.auth_token:
                result = self._run_isolated({
                    'action': 'rename',
                    'endpoint': self._authenticated_url(self._endpoint),
                    'path': path,
                    'new_path': new_path,
                    'new_dir': new_dir,
                })
                status = result['mkdir_status']
            else:
                flags = cast('Any', _flags())
                status, _ = self._filesystem().mkdir(new_dir, flags.MkDirFlags.MAKEPATH)
            if not self._is_file_exists(status):
                self._ensure_ok(status)
            if self.auth_token:
                status = result['move_status']
            else:
                status, _ = self._filesystem().mv(path, new_path)
            self._ensure_ok(status, source_not_found=True)
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)


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
    }


def _execute_isolated_request(request: dict[str, Any]) -> dict[str, Any]:
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
        mkdir_ok = getattr(mkdir_status, 'ok', False) or 'file exists' in str(getattr(mkdir_status, 'message', '')).lower()
        move_status = mkdir_status
        if mkdir_ok:
            move_status, _ = filesystem.mv(request['path'], request['new_path'])
        return {
            'mkdir_status': _serialize_status(mkdir_status),
            'move_status': _serialize_status(move_status),
        }

    raise ValueError('Unsupported isolated XRootD action: {}'.format(action))


def _worker_main() -> None:
    try:
        request = json.loads(sys.stdin.read())
        response = {'result': _execute_isolated_request(request)}
    except Exception as error:
        response = {'error': '{}: {}'.format(type(error).__name__, error)}
    print('{}{}'.format(_WORKER_RESULT_PREFIX, json.dumps(response)))


if __name__ == '__main__':
    _worker_main()
