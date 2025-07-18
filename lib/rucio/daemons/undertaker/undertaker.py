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

'''
Undertaker is a daemon to manage expired DID.
'''

import functools
import logging
import threading
import traceback
from copy import deepcopy
from datetime import datetime, timedelta
from random import randint
from re import match
from typing import TYPE_CHECKING

from sqlalchemy.exc import DatabaseError

import rucio.db.sqla.util
from rucio.common.constants import DEFAULT_VO
from rucio.common.exception import DatabaseException, RuleNotFound, UnsupportedOperation
from rucio.common.logging import setup_logging
from rucio.common.types import InternalAccount
from rucio.common.utils import chunks
from rucio.core.did import delete_dids, list_expired_dids
from rucio.core.monitor import MetricManager
from rucio.daemons.common import HeartbeatHandler, run_daemon
from rucio.db.sqla.constants import MYSQL_LOCK_NOWAIT_REGEX, ORACLE_RESOURCE_BUSY_REGEX, PSQL_LOCK_NOT_AVAILABLE_REGEX, PSQL_PSYCOPG_LOCK_NOT_AVAILABLE_REGEX

if TYPE_CHECKING:
    from types import FrameType
    from typing import Optional

logging.getLogger("requests").setLevel(logging.CRITICAL)

METRICS = MetricManager(module=__name__)
graceful_stop = threading.Event()
DAEMON_NAME = 'undertaker'


def undertaker(once: bool = False, sleep_time: int = 60, chunk_size: int = 10) -> None:
    """
    Main loop to select and delete DIDs.
    """
    paused_dids = {}  # {(scope, name): datetime}
    run_daemon(
        once=once,
        graceful_stop=graceful_stop,
        executable=DAEMON_NAME,
        partition_wait_time=1,
        sleep_time=sleep_time,
        run_once_fnc=functools.partial(
            run_once,
            paused_dids=paused_dids,
            chunk_size=chunk_size,
        )
    )


def run_once(paused_dids: dict[tuple, datetime], chunk_size: int, heartbeat_handler: HeartbeatHandler, **_kwargs) -> None:
    worker_number, total_workers, logger = heartbeat_handler.live()

    try:
        # Refresh paused DIDs
        iter_paused_dids = deepcopy(paused_dids)
        for key in iter_paused_dids:
            if datetime.utcnow() > paused_dids[key]:
                del paused_dids[key]

        dids = list_expired_dids(worker_number=worker_number, total_workers=total_workers, limit=10000)

        dids = [did for did in dids if (did['scope'], did['name']) not in paused_dids]

        if not dids:
            logger(logging.INFO, 'did not get any work')
            return

        for chunk in chunks(dids, chunk_size):
            _, _, logger = heartbeat_handler.live()
            try:
                logger(logging.INFO, 'Receive %s dids to delete', len(chunk))
                delete_dids(dids=chunk, account=InternalAccount('root', vo=DEFAULT_VO), expire_rules=True)
                logger(logging.INFO, 'Delete %s dids', len(chunk))
                METRICS.counter(name='undertaker.delete_dids').inc(len(chunk))
            except RuleNotFound as error:
                logger(logging.ERROR, error)
            except (DatabaseException, DatabaseError, UnsupportedOperation) as e:
                if match(ORACLE_RESOURCE_BUSY_REGEX, str(e.args[0])) or match(PSQL_LOCK_NOT_AVAILABLE_REGEX, str(e.args[0])) or match(PSQL_PSYCOPG_LOCK_NOT_AVAILABLE_REGEX, str(e.args[0])) or match(MYSQL_LOCK_NOWAIT_REGEX, str(e.args[0])):
                    for did in chunk:
                        paused_dids[(did['scope'], did['name'])] = datetime.utcnow() + timedelta(seconds=randint(600, 2400))  # noqa: S311
                    METRICS.counter('delete_dids.exceptions.{exception}').labels(exception='LocksDetected').inc()
                    logger(logging.WARNING, 'Locks detected for chunk')
                else:
                    logger(logging.ERROR, 'Got database error %s.', str(e))
    except Exception:
        logging.critical(traceback.format_exc())


def stop(signum: "Optional[int]" = None, frame: "Optional[FrameType]" = None) -> None:
    """
    Graceful exit.
    """
    graceful_stop.set()


def run(once: bool = False, total_workers: int = 1, chunk_size: int = 10, sleep_time: int = 60) -> None:
    """
    Starts up the undertaker threads.
    """
    setup_logging(process_name=DAEMON_NAME)

    if rucio.db.sqla.util.is_old_db():
        raise DatabaseException("Database was not updated, daemon won't start")

    if once:
        undertaker(once)
    else:
        logging.info('main: starting threads')
        threads = [threading.Thread(target=undertaker, kwargs={'once': once, 'chunk_size': chunk_size,
                                                               'sleep_time': sleep_time}) for i in range(0, total_workers)]
        [t.start() for t in threads]
        logging.info('main: waiting for interrupts')

        # Interruptible joins require a timeout.
        while threads[0].is_alive():
            [t.join(timeout=3.14) for t in threads]
