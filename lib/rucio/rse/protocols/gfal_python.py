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

import contextlib
import errno
import json
import logging
import os
import posixpath
import re
from shutil import copyfileobj
from urllib.parse import urlparse, urlunsplit

from rucio.common import config, exception
from rucio.common.checksum import GLOBALLY_SUPPORTED_CHECKSUMS, PREFERRED_CHECKSUM
from rucio.common.constraints import STRING_TYPES
from rucio.rse.protocols import protocol

try:
    from gfal import GfalClient
except Exception:
    if "RUCIO_CLIENT_MODE" not in os.environ:
        if not config.config_has_section("database"):
            raise exception.MissingDependency("Missing dependency : gfal")
    else:
        if os.environ["RUCIO_CLIENT_MODE"]:
            raise exception.MissingDependency("Missing dependency : gfal")

TIMEOUT = config.config_get("deletion", "timeout", False, None)
COPY_BUFSIZE = 1024 * 1024


class Default(protocol.RSEProtocol):
    """RSE protocol implementation backed by the Python ``gfal`` library."""

    def lfns2pfns(self, lfns):
        """Return a fully qualified PFN for each LFN."""
        lfns = [lfns] if isinstance(lfns, dict) else lfns

        pfns = {}
        prefix = self.attributes["prefix"]
        if self.attributes["extended_attributes"] is not None and "web_service_path" in list(self.attributes["extended_attributes"].keys()):
            web_service_path = self.attributes["extended_attributes"]["web_service_path"]
        else:
            web_service_path = ""

        if not prefix.startswith("/"):
            prefix = "".join(["/", prefix])
        if not prefix.endswith("/"):
            prefix = "".join([prefix, "/"])

        hostname = self.attributes["hostname"]
        if "://" in hostname:
            hostname = hostname.split("://")[1]

        if self.attributes["port"] == 0:
            for lfn in lfns:
                scope, name = str(lfn["scope"]), lfn["name"]
                path = lfn["path"] if "path" in lfn and lfn["path"] else self._get_path(scope=scope, name=name)
                if self.attributes["scheme"] != "root" and path.startswith("/"):
                    path = path[1:]
                pfns["%s:%s" % (scope, name)] = "".join([self.attributes["scheme"], "://", hostname, web_service_path, prefix, path])
        else:
            for lfn in lfns:
                scope, name = str(lfn["scope"]), lfn["name"]
                path = lfn["path"] if "path" in lfn and lfn["path"] else self._get_path(scope=scope, name=name)
                if self.attributes["scheme"] != "root" and path.startswith("/"):
                    path = path[1:]
                if re.match(r"^\w+://", path):
                    pfns["%s:%s" % (scope, name)] = path
                else:
                    pfns["%s:%s" % (scope, name)] = "".join([self.attributes["scheme"], "://", hostname, ":", str(self.attributes["port"]), web_service_path, prefix, path])

        return pfns

    def parse_pfns(self, pfns):
        """Split a PFN into protocol parts and validate it against the RSE."""
        self.logger(logging.DEBUG, "parsing {} pfns".format(len(list(pfns))))
        ret = dict()
        pfns = [pfns] if isinstance(pfns, STRING_TYPES) else pfns
        for pfn in pfns:
            parsed = urlparse(pfn)
            if parsed.path.startswith("/srm/managerv2") or parsed.path.startswith("/srm/managerv1") or parsed.path.startswith("/srm/v2/server"):
                scheme, hostname, port, service_path, path = re.findall(r"([^:]+)://([^:/]+):?(\d+)?([^:]+=)?([^:]+)", pfn)[0]
            else:
                scheme = parsed.scheme
                hostname = parsed.netloc.partition(":")[0]
                port = parsed.netloc.partition(":")[2]
                path = parsed.path
                service_path = ""

            if self.attributes["hostname"] != hostname and self.attributes["hostname"] != scheme + "://" + hostname:
                raise exception.RSEFileNameNotSupported("Invalid hostname: provided '%s', expected '%s'" % (hostname, self.attributes["hostname"]))

            if port != "" and str(self.attributes["port"]) != str(port):
                raise exception.RSEFileNameNotSupported("Invalid port: provided '%s', expected '%s'" % (port, self.attributes["port"]))
            elif port == "":
                port = self.attributes["port"]

            if not path.startswith(self.attributes["prefix"]):
                raise exception.RSEFileNameNotSupported("Invalid prefix: provided '%s', expected '%s'" % ("/".join(path.split("/")[0 : len(self.attributes["prefix"].split("/")) - 1]), self.attributes["prefix"]))

            prefix = self.attributes["prefix"]
            path = path.partition(self.attributes["prefix"])[2]
            name = path.split("/")[-1]
            path = "/".join(path.split("/")[:-1])
            if not path.startswith("/"):
                path = "/" + path
            if path != "/" and not path.endswith("/"):
                path = path + "/"
            ret[pfn] = {"scheme": scheme, "port": port, "hostname": hostname, "path": path, "name": name, "prefix": prefix, "web_service_path": service_path}

        return ret

    def path2pfn(self, path):
        """Return a fully qualified PFN for ``path``."""
        self.logger(logging.DEBUG, "getting pfn for {}".format(path))

        if "://" in path:
            return path

        hostname = self.attributes["hostname"]
        if "://" in hostname:
            hostname = hostname.split("://")[1]

        if "extended_attributes" in list(self.attributes.keys()) and self.attributes["extended_attributes"] is not None and "web_service_path" in list(self.attributes["extended_attributes"].keys()):
            web_service_path = self.attributes["extended_attributes"]["web_service_path"]
        else:
            web_service_path = ""

        if not path.startswith("srm"):
            if self.attributes["port"] > 0:
                return "".join([self.attributes["scheme"], "://", hostname, ":", str(self.attributes["port"]), web_service_path, path])
            return "".join([self.attributes["scheme"], "://", hostname, web_service_path, path])
        return path

    def connect(self):
        """Prepare the Python ``gfal`` client configuration."""
        self.logger(logging.DEBUG, "connecting to storage via Python gfal")
        self._client_kwargs = {}

        if TIMEOUT:
            try:
                self._client_kwargs["timeout"] = int(TIMEOUT)
            except ValueError:
                self.logger(logging.ERROR, "wrong timeout value %s", TIMEOUT)

        proxy = config.config_get("client", "client_x509_proxy", default=None, raise_exception=False)
        if proxy:
            self.logger(logging.INFO, "Configuring authentication to use {}".format(proxy))
            self._client_kwargs["cert"] = proxy
            self._client_kwargs["key"] = proxy

    def close(self):
        """Close the protocol connection."""
        self.logger(logging.DEBUG, "closing protocol connection")
        self._client_kwargs = None

    @contextlib.contextmanager
    def _auth_environment(self):
        previous_token = os.environ.get("BEARER_TOKEN")
        if self.auth_token:
            os.environ["BEARER_TOKEN"] = self.auth_token
        try:
            yield
        finally:
            if self.auth_token:
                if previous_token is None:
                    os.environ.pop("BEARER_TOKEN", None)
                else:
                    os.environ["BEARER_TOKEN"] = previous_token

    def _make_client(self, timeout=None):
        kwargs = dict(getattr(self, "_client_kwargs", {}) or {})
        if timeout:
            kwargs["timeout"] = int(timeout)
        return GfalClient(**kwargs)

    @staticmethod
    def _local_path(path):
        if path.startswith("file://"):
            return urlparse(path).path
        return os.path.abspath(path)

    @staticmethod
    def _parent_url(url):
        parsed = urlparse(str(url))
        parent_path = posixpath.dirname(parsed.path.rstrip("/"))
        if not parent_path:
            parent_path = "/"
        return urlunsplit((parsed.scheme, parsed.netloc, parent_path, parsed.query, parsed.fragment))

    @staticmethod
    def _is_not_found(error):
        return isinstance(error, FileNotFoundError) or getattr(error, "errno", None) == errno.ENOENT or "No such file" in str(error)

    def exists(self, path):
        """Return ``True`` if the PFN exists, else ``False``."""
        self.logger(logging.DEBUG, "checking if file exists {}".format(path))
        if path is None:
            raise exception.RSEOperationNotSupported()

        try:
            with self._auth_environment():
                self._make_client().stat(str(path))
            return True
        except Exception as error:
            if self._is_not_found(error):
                return False
            raise exception.ServiceUnavailable(error)

    def get(self, path, dest, transfer_timeout=None):
        """Download a remote PFN to a local destination."""
        self.logger(logging.DEBUG, "downloading file from {} to {}".format(path, dest))
        local_dest = self._local_path(dest)
        client = self._make_client(timeout=transfer_timeout)
        try:
            with self._auth_environment():
                source_handle = client.open(str(path), "rb")
        except Exception as error:
            if self._is_not_found(error):
                raise exception.SourceNotFound(error)
            raise exception.ServiceUnavailable(error)

        try:
            with source_handle:
                with open(local_dest, "wb") as dest_handle:
                    copyfileobj(source_handle, dest_handle, COPY_BUFSIZE)
        except OSError as error:
            raise exception.DestinationNotAccessible(error)
        except Exception as error:
            raise exception.ServiceUnavailable(error)

    def put(self, source, target, source_dir, transfer_timeout=None):
        """Upload a local file to a remote PFN."""
        self.logger(logging.DEBUG, "uploading file from {} to {}".format(source, target))
        source_path = "%s/%s" % (source_dir, source) if source_dir else source
        local_source = self._local_path(source_path)
        if not os.path.exists(local_source):
            raise exception.SourceNotFound()

        client = self._make_client(timeout=transfer_timeout)
        try:
            with self._auth_environment():
                client.mkdir(self._parent_url(target), parents=True)
                with open(local_source, "rb") as source_handle:
                    with client.open(str(target), "wb") as dest_handle:
                        copyfileobj(source_handle, dest_handle, COPY_BUFSIZE)
        except OSError as error:
            if self._is_not_found(error):
                raise exception.SourceNotFound(error)
            raise exception.DestinationNotAccessible(error)
        except Exception as error:
            if self._is_not_found(error):
                raise exception.SourceNotFound(error)
            raise exception.ServiceUnavailable(error)

    def delete(self, path):
        """Delete one or more PFNs from the connected RSE."""
        self.logger(logging.DEBUG, "deleting file {}".format(path))
        pfns = [path] if isinstance(path, STRING_TYPES) else path
        client = self._make_client()
        try:
            with self._auth_environment():
                for pfn in pfns:
                    client.rm(str(pfn))
        except Exception as error:
            if self._is_not_found(error):
                raise exception.SourceNotFound(error)
            raise exception.ServiceUnavailable(error)

    def rename(self, path, new_path):
        """Rename a PFN on the connected RSE."""
        self.logger(logging.DEBUG, "renaming file from {} to {}".format(path, new_path))
        client = self._make_client()
        try:
            with self._auth_environment():
                with contextlib.suppress(Exception):
                    client.mkdir(self._parent_url(new_path), parents=True)
                client.rename(str(path), str(new_path))
        except Exception as error:
            if self._is_not_found(error):
                raise exception.SourceNotFound(error)
            raise exception.ServiceUnavailable(error)

    def stat(self, path):
        """Return file size and checksum metadata for a PFN."""
        self.logger(logging.DEBUG, "getting stats of file {}".format(path))
        ret = {}
        client = self._make_client()
        try:
            with self._auth_environment():
                stat_result = client.stat(str(path))
        except Exception as error:
            raise exception.ServiceUnavailable("Error while processing gfal stat call. Error: %s" % str(error))

        ret["filesize"] = int(stat_result.st_size)
        if not self.rse.get("verify_checksum", True):
            return ret

        message = "\n"
        try:
            with self._auth_environment():
                ret[PREFERRED_CHECKSUM] = client.checksum(str(path), str(PREFERRED_CHECKSUM.upper()))
            return ret
        except Exception as error:
            message += "Error while processing gfal checksum call (%s). Error: %s \n" % (PREFERRED_CHECKSUM, str(error))

        for checksum_name in GLOBALLY_SUPPORTED_CHECKSUMS:
            if checksum_name == PREFERRED_CHECKSUM:
                continue
            try:
                with self._auth_environment():
                    ret[checksum_name] = client.checksum(str(path), str(checksum_name.upper()))
                return ret
            except Exception as error:
                message += "Error while processing gfal checksum call (%s). Error: %s \n" % (checksum_name, str(error))

        raise exception.RSEChecksumUnavailable(message)

    def get_space_usage(self):
        """Return ``(totalsize, unusedsize)`` from the space-token xattr."""
        endpoint_basepath = self.path2pfn(self.attributes["prefix"])
        self.logger(logging.DEBUG, "getting space usage from {}".format(endpoint_basepath))

        space_token = None
        if self.attributes["extended_attributes"] is not None and "space_token" in list(self.attributes["extended_attributes"].keys()):
            space_token = self.attributes["extended_attributes"]["space_token"]

        if space_token is None or space_token == "":
            raise exception.RucioException("Space token is not defined for protocol: %s" % (self.attributes["scheme"]))

        client = self._make_client()
        try:
            with self._auth_environment():
                ret_usage = client.getxattr(str(endpoint_basepath), str("spacetoken.description?" + space_token))
            usage = json.loads(ret_usage)
            totalsize = usage[0]["totalsize"]
            unusedsize = usage[0]["unusedsize"]
            return totalsize, unusedsize
        except Exception as error:
            raise exception.ServiceUnavailable(error)


class NoRename(Default):
    """Same as ``Default`` but without the upload temp-file rename step."""

    def __init__(self, protocol_attr, rse_settings, logger=logging.log):
        super(NoRename, self).__init__(protocol_attr, rse_settings, logger=logger)
        self.renaming = False
        self.attributes.pop("determinism_type", None)
        self.files = []

    def rename(self, pfn, new_pfn):
        raise NotImplementedError
