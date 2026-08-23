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

import hashlib
import json
import logging
import os
import subprocess  # noqa: S404 - required to isolate native XRootD credentials
import sys
import threading
from collections import deque
from importlib import import_module, metadata
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from packaging.version import InvalidVersion, Version

from rucio.common import exception
from rucio.common.checksum import PREFERRED_CHECKSUM
from rucio.common.config import config_get
from rucio.rse.protocols import protocol
from rucio.rse.protocols.xrootd_worker import WORKER_RESULT_PREFIX

if TYPE_CHECKING:
    from types import ModuleType

    from rucio.common.types import LoggerFunction, RSESettingsDict

_MIN_XROOTD_VERSION = Version('6.0.0')
_WORKER_RESULT_PREFIX = WORKER_RESULT_PREFIX


class _CredentialWorker:
    """A persistent XRootD process scoped to one immutable credential."""

    def __init__(
            self,
            module_path: str,
            auth_mode: str,
            token_path: str | None = None,
            proxy_path: str | None = None,
            cert_path: str | None = None,
            key_path: str | None = None,
    ) -> None:
        self._token_path = token_path
        self._proxy_path = proxy_path
        self._cert_path = cert_path
        self._key_path = key_path
        if auth_mode == 'gsi' and proxy_path is None and cert_path is None and key_path is None:
            # Direct worker users retain explicitly selected certificate/key
            # authentication. Protocol instances pass immutable snapshots here.
            selected_cert = os.environ.get('X509_USER_CERT')
            selected_key = os.environ.get('X509_USER_KEY')
            if selected_cert and selected_key and os.path.isfile(selected_cert) and os.path.isfile(selected_key):
                self._cert_path = selected_cert
                self._key_path = selected_key
        self._module_path = module_path
        self._auth_mode = auth_mode
        self._home = TemporaryDirectory(prefix='rucio-xrootd-home-')
        self._process: subprocess.Popen[str] | None = None
        self._lock = threading.Lock()
        self._closed = False

    def _stop_process(self, process: subprocess.Popen[str]) -> None:
        if self._process is process:
            self._process = None
        if process.stdin is not None:
            try:
                process.stdin.close()
            except OSError:
                pass
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            try:
                process.terminate()
            except OSError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    process.kill()
                except OSError:
                    pass
                process.wait()
        if process.stdout is not None:
            try:
                process.stdout.close()
            except OSError:
                pass

    def _start(self) -> subprocess.Popen[str]:
        if self._closed:
            raise exception.ServiceUnavailable('Native XRootD worker is closed')
        if self._process is not None:
            if self._process.poll() is None:
                return self._process
            self._stop_process(self._process)

        env = os.environ.copy()
        for key in (
            'BEARER_TOKEN',
            'BEARER_TOKEN_FILE',
            'PYTHONHOME',
            'PYTHONPATH',
            'RUCIO_CLIENT_PROXY',
            'XDG_RUNTIME_DIR',
            'X509_USER_CERT',
            'X509_USER_KEY',
            'X509_USER_PROXY',
            'XrdSecCREDS',
            'XrdSecGSICREATEPROXY',
            'XrdSecGSIUSERCERT',
            'XrdSecGSIUSERKEY',
            'XrdSecGSIUSERPROXY',
            'XrdSecPROTOCOL',
            'XrdSecPROXY',
            'XrdSecPROXYCREDS',
            'XrdSecUSER',
        ):
            env.pop(key, None)
        env['HOME'] = self._home.name
        env['XDG_RUNTIME_DIR'] = self._home.name
        env['XrdSecPROTOCOL'] = self._auth_mode
        if self._auth_mode == 'ztn':
            if self._token_path is None:
                raise exception.ServiceUnavailable('Native XRootD bearer worker has no token')
            env['BEARER_TOKEN_FILE'] = self._token_path
        elif self._proxy_path is not None:
            env['X509_USER_PROXY'] = self._proxy_path
        elif self._cert_path is not None and self._key_path is not None:
            env['X509_USER_CERT'] = self._cert_path
            env['X509_USER_KEY'] = self._key_path
        else:
            env['X509_USER_PROXY'] = os.devnull

        worker_path = str(Path(__file__).with_name('xrootd_worker.py').resolve())
        self._process = subprocess.Popen(  # noqa: S603 - fixed interpreter and trusted absolute script
            [sys.executable, '-I', worker_path, self._module_path],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding='utf-8',
            errors='replace',
            bufsize=1,
            env=env,
        )
        return self._process

    def request(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            process = self._start()
            if process.stdin is None or process.stdout is None:
                raise exception.ServiceUnavailable('Native XRootD worker has no communication pipes')

            try:
                process.stdin.write('{}\n'.format(json.dumps(request)))
                process.stdin.flush()
            except (BrokenPipeError, OSError) as error:
                self._stop_process(process)
                raise exception.ServiceUnavailable('Native XRootD worker stopped unexpectedly') from error

            diagnostics: deque[str] = deque(maxlen=20)
            while True:
                line = process.stdout.readline()
                if not line:
                    message = '\n'.join(diagnostics) or 'Native XRootD worker stopped unexpectedly'
                    self._stop_process(process)
                    raise exception.ServiceUnavailable(message)
                line = line.rstrip()
                if line.startswith(_WORKER_RESULT_PREFIX):
                    break
                diagnostics.append(line)

            try:
                response = json.loads(line[len(_WORKER_RESULT_PREFIX):])
            except (TypeError, json.JSONDecodeError) as error:
                self._stop_process(process)
                raise exception.ServiceUnavailable('Invalid response from native XRootD worker') from error
            if not isinstance(response, dict):
                self._stop_process(process)
                raise exception.ServiceUnavailable('Invalid response from native XRootD worker')
            if 'error' in response:
                raise exception.ServiceUnavailable(response['error'])
            result = response.get('result')
            if not isinstance(result, dict):
                self._stop_process(process)
                raise exception.ServiceUnavailable('Invalid response from native XRootD worker')
            return cast('dict[str, Any]', result)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            if self._process is not None:
                self._stop_process(self._process)
            self._home.cleanup()


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

    if not _is_supported_xrootd_version(_xrootd_client):
        _xrootd_client = None
except Exception:
    _xrootd_client = None


def _client() -> ModuleType:
    if _xrootd_client is None:
        raise exception.MissingDependency('Missing dependency : xrootd')
    return _xrootd_client


def _xrootd_module_path() -> str:
    """Return the validated distribution root for the isolated worker."""
    package_paths = list(getattr(import_module('XRootD'), '__path__', ()))
    if not package_paths:
        raise exception.MissingDependency('Cannot locate dependency : xrootd')
    return str(Path(package_paths[0]).resolve().parent)


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
        self.__token_file: Any | None = None
        self.__proxy_file: Any | None = None
        self.__cert_file: Any | None = None
        self.__key_file: Any | None = None
        self.__worker_lock = threading.Lock()
        self.__auth_mode = 'ztn' if self.auth_token else 'gsi'
        selected_proxy = None if self.__auth_mode == 'ztn' else self._valid_x509_proxy()
        self.__x509_proxy = self._snapshot_x509_proxy(selected_proxy)
        selected_cert, selected_key = (None, None)
        if self.__auth_mode == 'gsi' and selected_proxy is None:
            selected_cert, selected_key = self._valid_x509_cert_key()
        self.__x509_cert = self._snapshot_x509_cert(selected_cert)
        self.__x509_key = self._snapshot_x509_key(selected_key)
        self.__credential_id = self._gsi_credential_id(
            self.__x509_proxy,
            self.__x509_cert,
            self.__x509_key,
        )
        self.__worker: _CredentialWorker | None = None

    def check_dependencies(self) -> None:
        """Validate the optional native transport without affecting URL-only operations."""
        _client()

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
        # Presence is significant: an explicitly empty or unusable credential
        # must fail closed instead of selecting a lower-priority identity.
        if 'RUCIO_CLIENT_PROXY' in os.environ:
            return self._expand_x509_proxy(os.environ['RUCIO_CLIENT_PROXY'])

        configured_proxy = self._configured_x509_proxy()
        if configured_proxy is not None:
            return self._expand_x509_proxy(configured_proxy)

        if 'X509_USER_PROXY' in os.environ:
            return self._expand_x509_proxy(os.environ['X509_USER_PROXY'])

        if 'X509_USER_CERT' in os.environ or 'X509_USER_KEY' in os.environ:
            return None

        return self._expand_x509_proxy(self._default_x509_proxy())

    def _valid_x509_cert_key(self) -> tuple[str | None, str | None]:
        if 'RUCIO_CLIENT_PROXY' in os.environ or 'X509_USER_PROXY' in os.environ:
            return None, None
        if self._configured_x509_proxy() is not None:
            return None, None
        if 'X509_USER_CERT' not in os.environ and 'X509_USER_KEY' not in os.environ:
            return None, None
        cert = self._expand_x509_proxy(os.environ.get('X509_USER_CERT'))
        key = self._expand_x509_proxy(os.environ.get('X509_USER_KEY'))
        if cert is None or key is None:
            return None, None
        return cert, key

    def _configured_x509_proxy(self) -> str | None:
        try:
            configured_proxy = config_get('client', 'client_x509_proxy', default=None, raise_exception=False)
        except Exception:
            return None
        if configured_proxy in ('$X509_USER_PROXY', '${X509_USER_PROXY}'):
            # The standard client configuration commonly contains this alias
            # even when the variable is unset. Return the environment value
            # directly so an unset alias permits default-proxy lookup while an
            # explicitly invalid value still fails closed.
            return os.environ.get('X509_USER_PROXY')
        return configured_proxy

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

    @staticmethod
    def _gsi_credential_id(
            proxy: str | None,
            cert: str | None = None,
            key: str | None = None,
    ) -> str:
        digest = hashlib.sha256()
        selected_credentials = (
            ('proxy', proxy),
            ('cert', cert),
            ('key', key),
        )
        for label, credential_path in selected_credentials:
            if credential_path is None:
                continue
            digest.update(label.encode())
            try:
                with open(credential_path, 'rb') as credential_file:
                    for chunk in iter(lambda: credential_file.read(8192), b''):
                        digest.update(chunk)
            except OSError:
                digest.update(os.path.abspath(credential_path).encode())
        if all(path is None for _, path in selected_credentials):
            digest.update(b'no-gsi-credential')
        return digest.hexdigest()

    def _snapshot_x509_proxy(self, proxy: str | None) -> str | None:
        snapshot = self._snapshot_x509_credential(proxy, 'proxy')
        self.__proxy_file = snapshot
        return snapshot.name if snapshot is not None else None

    def _snapshot_x509_cert(self, cert: str | None) -> str | None:
        snapshot = self._snapshot_x509_credential(cert, 'cert')
        self.__cert_file = snapshot
        return snapshot.name if snapshot is not None else None

    def _snapshot_x509_key(self, key: str | None) -> str | None:
        snapshot = self._snapshot_x509_credential(key, 'key')
        self.__key_file = snapshot
        return snapshot.name if snapshot is not None else None

    @staticmethod
    def _snapshot_x509_credential(credential: str | None, kind: str) -> Any | None:
        if credential is None:
            return None
        credential_file = None
        try:
            credential_file = NamedTemporaryFile(mode='w+b', prefix='rucio-xrootd-{}-'.format(kind))
            with open(credential, 'rb') as source_credential:
                for chunk in iter(lambda: source_credential.read(8192), b''):
                    credential_file.write(chunk)
            credential_file.flush()
        except OSError:
            if credential_file is not None:
                credential_file.close()
            return None
        return credential_file

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
        auth_mode = getattr(self, '_Default__auth_mode', 'ztn' if self.auth_token else 'gsi')
        if auth_mode == 'ztn':
            # Each bearer credential has a dedicated process-local channel map.
            query['xrdcl.intent'] = 'rucio'
            query['xrd.wantprot'] = 'ztn'
            query['xrd.ztn'] = self._token_path()
        else:
            # Equal proxy contents use the same intent. Each protocol still has
            # its own process-local channel map and immutable proxy snapshot.
            query['xrdcl.intent'] = 'rucio-{}'.format(self.__credential_id)
            query['xrd.wantprot'] = 'gsi'
            x509_proxy = getattr(self, '_Default__x509_proxy', None)
            x509_cert = getattr(self, '_Default__x509_cert', None)
            x509_key = getattr(self, '_Default__x509_key', None)
            if x509_proxy is not None:
                query['xrd.gsiusrpxy'] = x509_proxy
                query['xrd.gsiusrcrt'] = os.devnull
                query['xrd.gsiusrkey'] = os.devnull
            elif x509_cert is not None and x509_key is not None:
                query['xrd.gsiusrcrt'] = x509_cert
                query['xrd.gsiusrkey'] = x509_key
            else:
                # Prevent XRootD from falling back to another identity in the
                # worker's isolated home directory.
                query['xrd.gsiusrpxy'] = os.devnull
                query['xrd.gsiusrcrt'] = os.devnull
                query['xrd.gsiusrkey'] = os.devnull
        return urlunsplit(parsed._replace(path=parsed.path or '/', query=urlencode(query, safe='/')))

    def _run_isolated(self, request: dict[str, Any]) -> dict[str, Any]:
        _client()
        worker_lock = getattr(self, '_Default__worker_lock', None)
        if worker_lock is None:
            worker_lock = threading.Lock()
            self.__worker_lock = worker_lock
        with worker_lock:
            worker = getattr(self, '_Default__worker', None)
            if worker is None:
                x509_proxy = getattr(self, '_Default__x509_proxy', None)
                x509_cert = getattr(self, '_Default__x509_cert', None)
                x509_key = getattr(self, '_Default__x509_key', None)
                auth_mode = getattr(self, '_Default__auth_mode', 'ztn' if self.auth_token else 'gsi')
                worker = _CredentialWorker(
                    _xrootd_module_path(),
                    auth_mode,
                    token_path=self._token_path() if auth_mode == 'ztn' else None,
                    proxy_path=x509_proxy,
                    cert_path=x509_cert,
                    key_path=x509_key,
                )
                self.__worker = worker
        return worker.request(request)

    def _is_not_found(self, status: Any) -> bool:
        if status is None:
            return False
        if isinstance(status, dict):
            not_found_code = status.get('errNotFound')
            return (
                not_found_code is not None and status.get('code') == not_found_code
                or status.get('errno') in (2, 3011, '2', '3011')
                or 'no such file' in str(status.get('message', '')).lower()
            )
        not_found_code = getattr(status, 'errNotFound', None)
        return (
            not_found_code is not None and getattr(status, 'code', None) == not_found_code
            or getattr(status, 'errno', None) in (2, 3011, '2', '3011')
            or 'no such file' in str(getattr(status, 'message', '')).lower()
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
        raise exception.ServiceUnavailable(self._status_message(status))

    def _copy(
            self,
            source: str,
            target: str,
            transfer_timeout: int | None = None,
            source_not_found: bool = False,
    ) -> None:
        timeout = int(transfer_timeout or self._COPY_DEFAULT_TIMEOUT)
        cptimeout = min(timeout, 65535) if timeout > 0 else 0
        inittimeout = min(timeout or 600, 65535)
        source = self._authenticated_url(source)
        target = self._authenticated_url(target)
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
        self._ensure_ok(prepare_status)
        if not self._status_ok(copy_status) and copy_results:
            copy_status = copy_results[0].get('status', copy_status)
        self._ensure_ok(copy_status, source_not_found=source_not_found)

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
            status = self._run_isolated({
                'action': 'exists',
                'endpoint': self._authenticated_url(self._endpoint),
                'path': path,
            })['status']
            if not self._status_ok(status):
                if self._is_not_found(status):
                    return False
                raise exception.ServiceUnavailable(self._status_message(status))
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
        :raises SourceNotFound: if the source file does not exist.
        :raises RSEChecksumUnavailable: if checksum verification is enabled but unavailable.

        :returns: a dict containing filesize and, when enabled, the preferred checksum.
        """
        self.logger(logging.DEBUG, f'xrootd.stat: path: {path}')
        ret = {}
        chsum = None
        if path.startswith('root:'):
            path = self.pfn2path(path)

        try:
            result = self._run_isolated({
                'action': 'stat',
                'endpoint': self._authenticated_url(self._endpoint),
                'path': path,
                'verify_checksum': self.rse.get('verify_checksum', True),
            })
            status = result['status']
            stat_info = result['stat_info']
            self._ensure_ok(status, source_not_found=True)
            ret['filesize'] = str(stat_info['size'] if isinstance(stat_info, dict) else getattr(stat_info, 'size'))

            if not self.rse.get('verify_checksum', True):
                return ret

            status = result['checksum_status']
            checksum = result['checksum']
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
            status = self._run_isolated({
                'action': 'connect',
                'endpoint': self._authenticated_url(self._endpoint),
                'hostname': self.hostname,
                'port': self.port,
            })['status']
            if not self._status_ok(status):
                raise exception.RSEAccessDenied(self._status_message(status))
        except exception.RSEAccessDenied:
            raise
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        worker_lock = getattr(self, '_Default__worker_lock', None)
        if worker_lock is None:
            self._close_resources()
        else:
            with worker_lock:
                self._close_resources()

    def _close_resources(self) -> None:
        close_error = None
        worker = getattr(self, '_Default__worker', None)
        self.__worker = None
        if worker is not None:
            try:
                worker.close()
            except Exception as error:
                close_error = error

        for attribute in (
            '_Default__token_file',
            '_Default__proxy_file',
            '_Default__cert_file',
            '_Default__key_file',
        ):
            credential_file = getattr(self, attribute, None)
            setattr(self, attribute, None)
            if credential_file is not None:
                try:
                    credential_file.close()
                except Exception as error:
                    if close_error is None:
                        close_error = error

        if close_error is not None:
            raise close_error

    def __del__(self) -> None:
        try:
            self.close()
        except Exception:
            pass

    def get(self, pfn, dest, transfer_timeout=None):
        """ Provides access to files stored inside connected the RSE.

            :param pfn: Physical file name of requested file
            :param dest: Name and path of the files when stored at the client
            :param transfer_timeout: Transfer timeout (in seconds)

            :raises ServiceUnavailable, SourceNotFound
        """
        self.logger(logging.DEBUG, 'xrootd.get: pfn: {}'.format(pfn))
        try:
            self._copy(pfn, dest, transfer_timeout=transfer_timeout, source_not_found=True)
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
            :param transfer_timeout: Transfer timeout (in seconds)

            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the local source file was not found.
        """
        self.logger(logging.DEBUG, 'xrootd.put: filename: {} target: {}'.format(filename, target))
        source_dir = source_dir or '.'
        source_url = '%s/%s' % (source_dir, filename)
        self.logger(logging.DEBUG, 'xrootd put: source url: {}'.format(source_url))
        path = self.path2pfn(target)
        if not os.path.exists(source_url):
            raise exception.SourceNotFound()
        try:
            self._copy(
                os.path.abspath(source_url),
                path,
                transfer_timeout=transfer_timeout,
                source_not_found=False,
            )
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
        try:
            path = self.pfn2path(pfn)
            status = self._run_isolated({
                'action': 'delete',
                'endpoint': self._authenticated_url(self._endpoint),
                'path': path,
            })['status']
            self._ensure_ok(status, source_not_found=True)
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)

    def rename(self, pfn, new_pfn):
        """ Allows to rename a file stored inside the connected RSE.

            :param pfn:      Current physical file name
            :param new_pfn  New physical file name
            :raises ServiceUnavailable: if some generic error occurred in the library.
            :raises SourceNotFound: if the source file was not found on the referred storage.
        """
        self.logger(logging.DEBUG, 'xrootd.rename: pfn: {}'.format(pfn))
        try:
            path = self.pfn2path(pfn)
            new_path = self.pfn2path(new_pfn)
            new_dir = new_path[:new_path.rindex('/') + 1]
            result = self._run_isolated({
                'action': 'rename',
                'endpoint': self._authenticated_url(self._endpoint),
                'path': path,
                'new_path': new_path,
                'new_dir': new_dir,
            })
            status = result['mkdir_status']
            if not self._is_file_exists(status):
                self._ensure_ok(status)
            status = result['move_status']
            self._ensure_ok(status, source_not_found=True)
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)
