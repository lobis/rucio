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
from typing import TYPE_CHECKING

from flask import Flask, Response, request

from rucio.common.constants import DEFAULT_VO
from rucio.gateway.did import list_archive_content
from rucio.web.rest.flaskapi.authenticated_bp import AuthenticatedBlueprint
from rucio.web.rest.flaskapi.v1.common import ErrorHandlingMethodView, check_accept_header_wrapper_flask, generate_http_error_flask, parse_scope_name, response_headers, try_stream

if TYPE_CHECKING:
    from collections.abc import Iterator


class Archive(ErrorHandlingMethodView):
    """ REST APIs for archive. """

    @check_accept_header_wrapper_flask(['application/x-json-stream'])
    def get(self, scope_name: str) -> Response:
        """
        ---
        summary: List
        description: "List archive contents."
        tags:
          - Archive
        parameters:
        - name: scope_name
          in: path
          description: "The data identifier of the scope."
          schema:
            type: string
          style: simple
        responses:
          201:
            description: "OK"
            content:
              application/x-json-stream:
                schema:
                  type: array
                  items:
                    type: object
                    properties:
                      scope:
                        description: "The scope of the DID."
                        type: string
                      name:
                        description: "The name of the DID."
                        type: string
                      bytes:
                        description: "The number of bytes."
                        type: integer
                      adler32:
                        description: "The adler32 checksum."
                        type: string
                      md5:
                        description: "The md5 checksum."
                        type: string
          400:
            description: "Invalid value"
          406:
            description: "Not acceptable"
        """
        try:
            scope, name = parse_scope_name(scope_name, request.environ.get('vo'))

            def generate(vo: str) -> 'Iterator[str]':
                for file in list_archive_content(scope=scope, name=name, vo=vo):
                    yield dumps(file) + '\n'

            return try_stream(generate(vo=request.environ.get('vo', DEFAULT_VO)))
        except ValueError as error:
            return generate_http_error_flask(400, error)


def blueprint() -> AuthenticatedBlueprint:
    bp = AuthenticatedBlueprint('archives', __name__, url_prefix='/archives')

    archive_view = Archive.as_view('archive')
    bp.add_url_rule('/<path:scope_name>/files', view_func=archive_view, methods=['get', ])

    bp.after_request(response_headers)
    return bp


def make_doc() -> Flask:
    """ Only used for sphinx documentation """
    doc_app = Flask(__name__)
    doc_app.register_blueprint(blueprint())
    return doc_app
