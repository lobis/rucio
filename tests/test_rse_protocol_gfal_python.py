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

import importlib
import io
import os
import sys
import types


def _load_module(monkeypatch, client_cls):
    fake_gfal = types.ModuleType("gfal")
    fake_gfal.GfalClient = client_cls
    monkeypatch.setitem(sys.modules, "gfal", fake_gfal)
    sys.modules.pop("rucio.rse.protocols.gfal_python", None)
    module = importlib.import_module("rucio.rse.protocols.gfal_python")
    return importlib.reload(module)


def _make_protocol(module, protocol_class_name="Default"):
    protocol_attr = {
        "scheme": "https",
        "hostname": "storage.example",
        "port": 443,
        "prefix": "/rucio",
        "impl": "rucio.rse.protocols.gfal_python.%s" % protocol_class_name,
        "domains": {"wan": {"read": 1, "write": 1, "delete": 1}},
        "extended_attributes": {"space_token": "TOKEN"},
        "auth_token": "secret-token",
    }
    rse_settings = {
        "rse": "TEST_RSE",
        "id": "test-rse-id",
        "verify_checksum": True,
        "deterministic": False,
        "protocols": [dict(protocol_attr)],
    }
    protocol_cls = getattr(module, protocol_class_name)
    protocol = protocol_cls(dict(protocol_attr), rse_settings, logger=lambda *args, **kwargs: None)
    protocol.connect()
    return protocol


class FakeStat:
    def __init__(self, size):
        self.st_size = size


class FakeClient:
    instances = []
    files = {}
    checksums = {}
    xattrs = {}
    stats = {}
    mkdir_calls = []
    rename_calls = []
    rm_calls = []
    last_kwargs = None

    def __init__(self, **kwargs):
        FakeClient.last_kwargs = kwargs
        FakeClient.instances.append(self)

    @classmethod
    def reset(cls):
        cls.instances = []
        cls.files = {}
        cls.checksums = {}
        cls.xattrs = {}
        cls.stats = {}
        cls.mkdir_calls = []
        cls.rename_calls = []
        cls.rm_calls = []
        cls.last_kwargs = None

    def stat(self, path):
        if path not in self.stats:
            raise FileNotFoundError(path)
        return self.stats[path]

    def checksum(self, path, algorithm):
        return self.checksums[(path, algorithm)]

    def getxattr(self, path, name):
        return self.xattrs[(path, name)]

    def mkdir(self, path, parents=False):
        self.mkdir_calls.append((path, parents))

    def rename(self, source, dest):
        self.rename_calls.append((source, dest))

    def rm(self, path):
        self.rm_calls.append(path)

    def open(self, path, mode="rb"):
        if "r" in mode:
            if path not in self.files:
                raise FileNotFoundError(path)
            return io.BytesIO(self.files[path])

        buffer = io.BytesIO()
        original_close = buffer.close

        def _close():
            self.files[path] = buffer.getvalue()
            original_close()

        buffer.close = _close
        return buffer


def test_stat_prefers_adler32(monkeypatch):
    FakeClient.reset()
    module = _load_module(monkeypatch, FakeClient)
    protocol = _make_protocol(module)

    FakeClient.stats["https://storage.example:443/rucio/file1"] = FakeStat(123)
    FakeClient.checksums[("https://storage.example:443/rucio/file1", "ADLER32")] = "deadbeef"

    result = protocol.stat("https://storage.example:443/rucio/file1")

    assert result == {"filesize": 123, "adler32": "deadbeef"}


def test_put_creates_parent_and_uploads(monkeypatch, tmp_path):
    FakeClient.reset()
    module = _load_module(monkeypatch, FakeClient)
    protocol = _make_protocol(module)
    local_file = tmp_path / "payload.bin"
    local_file.write_bytes(b"payload-data")

    protocol.put(str(local_file), "https://storage.example:443/rucio/dir/file.bin", source_dir=None, transfer_timeout=42)

    assert FakeClient.mkdir_calls == [("https://storage.example:443/rucio/dir", True)]
    assert FakeClient.files["https://storage.example:443/rucio/dir/file.bin"] == b"payload-data"
    assert FakeClient.last_kwargs["timeout"] == 42
    assert "BEARER_TOKEN" not in os.environ


def test_get_downloads_to_local_path(monkeypatch, tmp_path):
    FakeClient.reset()
    module = _load_module(monkeypatch, FakeClient)
    protocol = _make_protocol(module)
    FakeClient.files["https://storage.example:443/rucio/data.bin"] = b"remote-data"

    destination = tmp_path / "download.bin"
    protocol.get("https://storage.example:443/rucio/data.bin", str(destination), transfer_timeout=15)

    assert destination.read_bytes() == b"remote-data"
    assert FakeClient.last_kwargs["timeout"] == 15


def test_exists_false_for_missing_file(monkeypatch):
    FakeClient.reset()
    module = _load_module(monkeypatch, FakeClient)
    protocol = _make_protocol(module)

    assert protocol.exists("https://storage.example:443/rucio/missing.bin") is False


def test_rename_creates_parent_before_rename(monkeypatch):
    FakeClient.reset()
    module = _load_module(monkeypatch, FakeClient)
    protocol = _make_protocol(module)

    protocol.rename("https://storage.example:443/rucio/source.bin", "https://storage.example:443/rucio/new/path/target.bin")

    assert FakeClient.mkdir_calls == [("https://storage.example:443/rucio/new/path", True)]
    assert FakeClient.rename_calls == [("https://storage.example:443/rucio/source.bin", "https://storage.example:443/rucio/new/path/target.bin")]


def test_delete_handles_multiple_pfns(monkeypatch):
    FakeClient.reset()
    module = _load_module(monkeypatch, FakeClient)
    protocol = _make_protocol(module)

    protocol.delete(["https://storage.example:443/rucio/a.bin", "https://storage.example:443/rucio/b.bin"])

    assert FakeClient.rm_calls == ["https://storage.example:443/rucio/a.bin", "https://storage.example:443/rucio/b.bin"]


def test_get_space_usage_reads_xattr(monkeypatch):
    FakeClient.reset()
    module = _load_module(monkeypatch, FakeClient)
    protocol = _make_protocol(module)
    FakeClient.xattrs[("https://storage.example:443/rucio", "spacetoken.description?TOKEN")] = '[{"totalsize": 1000, "unusedsize": 400}]'

    totalsize, unusedsize = protocol.get_space_usage()

    assert (totalsize, unusedsize) == (1000, 400)
