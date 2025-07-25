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

from json import dumps
from typing import Optional

from requests import post

from rucio.client.baseclient import BaseClient, choice
from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import RucioException, UnsupportedDIDType


class TouchClient(BaseClient):

    """
    Touch client class to send a trace that can be used to
    update accessed_at for file or dataset DIDs
    """

    DIDS_BASEURL = 'dids'
    TRACES_BASEURL = 'traces'

    def touch(
            self,
            scope: str,
            name: str,
            rse: Optional[str] = None
    ) -> None:
        """
        Sends a touch trace for a given file or dataset.

        Parameters
        ----------
        scope : The scope of the file/dataset to update.
        name : The name of file/dataset to update.
        rse : Optional parameter if a specific replica should be touched.

        Raises
        ------
        DataIdentifierNotFound
            If given DIDs does not exist.
        RSENotFound
            If rse is not None and given rse does not exist.
        UnsupportedDIDType
            If type of the given DID is not FILE or DATASET.
        RucioException
            If trace could not be sent successfully.
        """

        trace = {}

        trace['eventType'] = 'touch'
        trace['clientState'] = 'DONE'
        trace['account'] = self.account
        if self.vo != DEFAULT_VO:
            trace['vo'] = self.vo

        if rse:
            self.get_rse(rse)  # pylint: disable=no-member

            trace['localSite'] = trace['remoteSite'] = rse

        info = self.get_did(scope, name)  # pylint: disable=no-member

        if info['type'] == 'CONTAINER':
            raise UnsupportedDIDType("%s:%s is a container." % (scope, name))

        if info['type'] == 'FILE':
            trace['scope'] = scope
            trace['filename'] = name
        elif info['type'] == 'DATASET':
            trace['datasetScope'] = scope
            trace['dataset'] = name

        url = '%s/%s/' % (choice(self.list_hosts), self.TRACES_BASEURL)

        try:
            post(url, verify=False, data=dumps(trace))
        except Exception as error:
            raise RucioException("Could not send trace. " + str(error))
