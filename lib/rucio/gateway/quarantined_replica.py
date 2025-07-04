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

from typing import TYPE_CHECKING, Any, Optional

from rucio.common import exception
from rucio.common.constants import DEFAULT_VO
from rucio.common.types import InternalScope
from rucio.core.quarantined_replica import add_quarantined_replicas
from rucio.core.rse import get_rse_id
from rucio.db.sqla.constants import DatabaseOperationType
from rucio.db.sqla.session import db_session
from rucio.gateway import permission

if TYPE_CHECKING:
    from collections.abc import Iterable


def quarantine_file_replicas(
    replicas: "Iterable[dict[str, Any]]",
    issuer: str,
    rse: Optional[str] = None,
    rse_id: Optional[str] = None,
    vo: str = DEFAULT_VO,
) -> None:
    """
    Quarantine replicas.

    :param replicas: List of replica infos: {'scope': <scope> (optional), 'name': <name> (optional), 'path':<path> (required)}
    :param issuer: The issuer account.
    :param vo: The VO to act on.
    :param rse: RSE name
    :param rse_id: RSE id - either RSE name or RSE id must be specified
    """

    if not replicas:
        return

    if (rse is None) == (rse_id is None):
        raise exception.InputValidationError("Either RSE name or RSE id must be specified, but not both")

    with db_session(DatabaseOperationType.WRITE) as session:

        if rse_id is None:
            rse_id = get_rse_id(rse, vo=vo, session=session)

        auth_result = permission.has_permission(issuer, 'quarantine_file_replicas', {}, vo=vo, session=session)
        if not auth_result.allowed:
            raise exception.AccessDenied('Account %s can not quarantine replicas. %s' % (issuer, auth_result.message))

        replica_infos = []
        for r in replicas:
            if "path" not in r:
                raise exception.InputValidationError("Replica info must include path")
            scope = r.get("scope")
            if scope and isinstance(scope, str):
                scope = InternalScope(scope, vo=vo)
            replica_infos.append(
                {
                    "scope": scope or None,
                    "name": r.get("name"),
                    "path": r["path"]
                }
            )

        add_quarantined_replicas(rse_id, replica_infos, session=session)
