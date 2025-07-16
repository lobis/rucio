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
from typing import TYPE_CHECKING, Any, Optional

from rucio.common.types import InternalScope
from rucio.common.utils import gateway_update_return_dict
from rucio.core import opendata
from rucio.core.opendata import check_valid_opendata_did_state, opendata_state_str_to_enum
from rucio.db.sqla.session import read_session, transactional_session

if TYPE_CHECKING:
    from sqlalchemy.orm import Session


def list_opendata_dids(
        *,
        limit: Optional[int] = None,
        offset: Optional[int] = None,
        state: Optional[str] = None,
) -> dict[str, list[dict[str, Any]]]:
    state_enum = None
    if state:
        check_valid_opendata_did_state(state)
        state_enum = opendata_state_str_to_enum(state)
    result = opendata.list_opendata_dids(limit=limit, offset=offset, state=state_enum)
    return result


@read_session
def get_opendata_did(
        *,
        scope: str,
        name: str,
        state: Optional[str] = None,
        files: bool = True,
        meta: bool = False,
        doi: bool = True,
        vo: str = "def",
        session: "Session"
) -> dict[str, Any]:
    internal_scope = InternalScope(scope, vo=vo)
    state_enum = None
    if state:
        check_valid_opendata_did_state(state)
        state_enum = opendata_state_str_to_enum(state)
    result = opendata.get_opendata_did(scope=internal_scope, name=name,
                                       state=state_enum, files=files, meta=meta, doi=doi,
                                       session=session)
    return gateway_update_return_dict(result, session=session)


@transactional_session
def add_opendata_did(
        *,
        scope: str,
        name: str,
        vo: str = "def",
        session: "Session"
) -> None:
    internal_scope = InternalScope(scope, vo=vo)
    return opendata.add_opendata_did(scope=internal_scope, name=name, session=session)


@transactional_session
def delete_opendata_did(
        *,
        scope: str,
        name: str,
        vo: str = "def",
        session: "Session"
) -> None:
    internal_scope = InternalScope(scope, vo=vo)
    return opendata.delete_opendata_did(scope=internal_scope, name=name, session=session)


@transactional_session
def update_opendata_did(
        *,
        scope: str,
        name: str,
        state: Optional[str] = None,
        meta: Optional[dict] = None,
        doi: Optional[str] = None,
        vo: str = "def",
        session: "Session"
) -> None:
    internal_scope = InternalScope(scope, vo=vo)
    state_enum = None
    if state:
        check_valid_opendata_did_state(state)
        state_enum = opendata_state_str_to_enum(state)
    if isinstance(meta, str):
        try:
            meta = json.loads(meta)
        except ValueError as error:
            raise ValueError(f"Invalid JSON: {error}")

    return opendata.update_opendata_did(scope=internal_scope,
                                        name=name,
                                        state=state_enum,
                                        meta=meta,
                                        doi=doi,
                                        session=session)


@read_session
def get_opendata_did_files(
        *,
        scope: str,
        name: str,
        vo: str = "def",
        session: "Session"
) -> dict[str, Any]:
    internal_scope = InternalScope(scope, vo=vo)
    result = opendata.get_opendata_did_files(scope=internal_scope, name=name, session=session)
    return gateway_update_return_dict(result, session=session)
