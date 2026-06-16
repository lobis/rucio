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

import logging
import os
from typing import Any, Optional, cast

from rucio.common import exception
from rucio.common.checksum import PREFERRED_CHECKSUM
from rucio.common.config import config_get
from rucio.rse.protocols import protocol

try:
    from XRootD import client as _xrootd_client
    from XRootD.client import flags as _xrootd_flags
except Exception:
    _xrootd_client = None
    _xrootd_flags = None


def _client() -> Any:
    if _xrootd_client is None:
        raise exception.MissingDependency('Missing dependency : xrootd')
    return _xrootd_client


def _flags() -> Any:
    if _xrootd_flags is None:
        raise exception.MissingDependency('Missing dependency : xrootd')
    return _xrootd_flags


class Default(protocol.RSEProtocol):
    """Implement access to RSEs using the native XRootD Python bindings."""

    _COPY_DEFAULT_TIMEOUT = 0

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        """ Initializes the object with information about the referred RSE.

            :param props: Properties derived from the RSE Repository
        """
        super(Default, self).__init__(protocol_attr, rse_settings, logger=logger)

        self.scheme = self.attributes['scheme']
        self.hostname = self.attributes['hostname']
        self.port = str(self.attributes['port'])
        self.logger = logger
        self.__fs: Optional[Any] = None

    @property
    def _endpoint(self):
        return '{}://{}:{}'.format(self.scheme, self.hostname, self.port)

    @staticmethod
    def _status_ok(status):
        return bool(getattr(status, 'ok', False))

    @staticmethod
    def _status_message(status):
        return getattr(status, 'message', status)

    @staticmethod
    def _response_text(response):
        if isinstance(response, bytes):
            return response.decode()
        return response

    def _valid_x509_proxy(self):
        for proxy in (
            os.environ.get('RUCIO_CLIENT_PROXY'),
            os.environ.get('X509_USER_PROXY'),
            self._configured_x509_proxy(),
            self._default_x509_proxy(),
        ):
            expanded_proxy = self._expand_x509_proxy(proxy)
            if expanded_proxy:
                return expanded_proxy
        return None

    def _configured_x509_proxy(self):
        try:
            return config_get('client', 'client_x509_proxy', default=None, raise_exception=False)
        except Exception:
            return None

    @staticmethod
    def _default_x509_proxy():
        if hasattr(os, 'geteuid'):
            return '/tmp/x509up_u%d' % os.geteuid()
        return None

    @staticmethod
    def _expand_x509_proxy(proxy):
        if not proxy:
            return None
        expanded_proxy = os.path.expanduser(os.path.expandvars(proxy))
        if '$' in expanded_proxy:
            return None
        if os.path.isfile(expanded_proxy):
            return expanded_proxy
        return None

    def _clear_unexpanded_x509_proxy(self, xrootd_client):
        proxy = os.environ.get('X509_USER_PROXY')
        if proxy and '$' in os.path.expandvars(proxy):
            os.environ.pop('X509_USER_PROXY', None)
            env_del_string = getattr(xrootd_client, 'EnvDelString', None)
            if env_del_string:
                env_del_string('X509_USER_PROXY')

    def _configure_auth(self):
        xrootd_client = _client()
        if self.auth_token:
            os.environ['XrdSecPROTOCOL'] = 'ztn'
            os.environ['BEARER_TOKEN'] = self.auth_token
            xrootd_client.EnvPutString('XrdSecPROTOCOL', 'ztn')
            xrootd_client.EnvPutString('BEARER_TOKEN', self.auth_token)
            return

        os.environ['XrdSecPROTOCOL'] = 'gsi'
        xrootd_client.EnvPutString('XrdSecPROTOCOL', 'gsi')

        proxy = self._valid_x509_proxy()
        if proxy:
            os.environ['X509_USER_PROXY'] = proxy
            xrootd_client.EnvPutString('X509_USER_PROXY', proxy)
        else:
            self._clear_unexpanded_x509_proxy(xrootd_client)

    def _filesystem(self):
        xrootd_client = _client()
        if self.__fs is None:
            self._configure_auth()
            self.__fs = xrootd_client.FileSystem(self._endpoint)
        return cast('Any', self.__fs)

    def _is_not_found(self, status):
        if status is None:
            return False
        return (
            getattr(status, 'code', None) == getattr(status, 'errNotFound', None)
            or getattr(status, 'shellcode', None) == 54
            or 'No such file' in getattr(status, 'message', '')
        )

    def _is_file_exists(self, status):
        if status is None:
            return False
        return 'file exists' in str(self._status_message(status)).lower()

    def _ensure_ok(self, status, source_not_found=False):
        if status is not None and self._status_ok(status):
            return
        if source_not_found and self._is_not_found(status):
            raise exception.SourceNotFound(self._status_message(status))
        raise exception.RucioException(self._status_message(status))

    def _copy(self, source, target, transfer_timeout=None):
        xrootd_client = _client()
        self._configure_auth()
        timeout = int(transfer_timeout or self._COPY_DEFAULT_TIMEOUT)
        copy_process = xrootd_client.CopyProcess()
        copy_process.add_job(
            source,
            target,
            force=True,
            mkdir=True,
            cptimeout=timeout,
            inittimeout=timeout or 600,
        )
        prepare_status = copy_process.prepare()
        self._ensure_ok(prepare_status)
        copy_status, copy_results = copy_process.run()
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
            status, stat_info = self._filesystem().stat(path)
            self._ensure_ok(status, source_not_found=True)
            ret['filesize'] = str(getattr(stat_info, 'size'))

            if not self.rse.get('verify_checksum', True):
                return ret

            status, checksum = self._filesystem().query(_flags().QueryCode.CHECKSUM, path)
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
            status, _ = self._filesystem().query(_flags().QueryCode.CONFIG, '{}:{}'.format(self.hostname, self.port), timeout=10)
            if not self._status_ok(status):
                raise exception.RSEAccessDenied(self._status_message(status))
        except Exception as e:
            raise exception.RSEAccessDenied(e)

    def close(self):
        """ Closes the connection to RSE."""
        pass

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
            status, _ = self._filesystem().mkdir(new_dir, _flags().MkDirFlags.MAKEPATH)
            if not self._is_file_exists(status):
                self._ensure_ok(status)
            status, _ = self._filesystem().mv(path, new_path)
            self._ensure_ok(status, source_not_found=True)
        except exception.RucioException:
            raise
        except Exception as e:
            raise exception.ServiceUnavailable(e)
