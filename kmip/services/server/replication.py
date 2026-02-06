# Copyright (c) 2026 The Johns Hopkins University/Applied Physics Laboratory
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Simple leader/follower replication helpers for the KMIP server."""

from __future__ import annotations

import datetime
import logging
import os
import tempfile
import threading
import time
from typing import Optional
from urllib.parse import urlparse

import requests


class ReplicationManager:
    """Coordinate leader/follower replication using database snapshots."""

    def __init__(
        self,
        engine,
        role: Optional[str] = None,
        leader_url: Optional[str] = None,
        token: Optional[str] = None,
        poll_interval: float = 10.0,
        timeout: float = 5.0,
        logger: Optional[logging.Logger] = None,
    ) -> None:
        self._engine = engine
        self._logger = logger or logging.getLogger("kmip.server.replication")

        self._role = (role or "").strip().lower() or None
        self._leader_url = self._normalize_leader_url(leader_url)
        self._token = token or None
        self._poll_interval = max(float(poll_interval), 1.0)
        self._timeout = max(float(timeout), 1.0)

        self._last_success = None
        self._last_error = None
        self._last_error_at = None
        self._last_sync_size = None

        self._poller = None

    @property
    def role(self) -> Optional[str]:
        return self._role

    @property
    def leader_url(self) -> Optional[str]:
        return self._leader_url

    @property
    def is_leader(self) -> bool:
        return self._role == "leader"

    @property
    def is_follower(self) -> bool:
        return self._role == "follower"

    def start(self) -> None:
        if self.is_follower:
            if not self._leader_url:
                self._logger.warning(
                    "Replication follower enabled without leader URL."
                )
                return
            self._poller = _ReplicationPoller(self)
            self._poller.start()

    def stop(self) -> None:
        if self._poller:
            self._poller.stop()
            self._poller.join(timeout=self._poll_interval + 1.0)
            self._poller = None

    def authorize(self, headers) -> bool:
        if not self._token:
            return True

        auth = headers.get("Authorization")
        if auth and auth.startswith("Bearer "):
            return auth.split(" ", 1)[1] == self._token

        token = headers.get("X-Replication-Token")
        return token == self._token

    def create_backup(self) -> str:
        return self._engine.create_storage_backup()

    def pull_once(self) -> None:
        if not self._leader_url:
            raise ValueError("Replication leader URL not configured.")

        headers = {}
        if self._token:
            headers["Authorization"] = "Bearer {0}".format(self._token)

        response = requests.get(
            self._leader_url,
            headers=headers,
            stream=True,
            timeout=self._timeout,
        )
        try:
            response.raise_for_status()
            tmp_fd, tmp_path = tempfile.mkstemp(
                prefix="pykmip-replication-",
                suffix=".db",
            )
            size = 0
            with os.fdopen(tmp_fd, "wb") as handle:
                for chunk in response.iter_content(chunk_size=1024 * 1024):
                    if chunk:
                        handle.write(chunk)
                        size += len(chunk)

            try:
                self._engine.restore_storage_backup(tmp_path)
            finally:
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)
        finally:
            response.close()

        self._last_success = self._utc_timestamp()
        self._last_error = None
        self._last_error_at = None
        self._last_sync_size = size

    def record_error(self, exc: Exception) -> None:
        self._last_error = str(exc)
        self._last_error_at = self._utc_timestamp()
        self._logger.warning("Replication error: %s", exc)

    def get_status(self) -> dict:
        return {
            "role": self._role or "standalone",
            "leader_url": self._leader_url,
            "poll_interval": self._poll_interval,
            "timeout": self._timeout,
            "last_success": self._last_success,
            "last_error": self._last_error,
            "last_error_at": self._last_error_at,
            "last_sync_size": self._last_sync_size,
        }

    @staticmethod
    def _utc_timestamp() -> str:
        return datetime.datetime.utcnow().isoformat() + "Z"

    @staticmethod
    def _normalize_leader_url(leader_url: Optional[str]) -> Optional[str]:
        if not leader_url:
            return None

        parsed = urlparse(leader_url)
        if parsed.path in ("", "/"):
            return leader_url.rstrip("/") + "/replication/backup"
        return leader_url


class _ReplicationPoller(threading.Thread):
    def __init__(self, manager: ReplicationManager) -> None:
        super(_ReplicationPoller, self).__init__(daemon=True)
        self._manager = manager
        self._stop_event = threading.Event()

    def stop(self) -> None:
        self._stop_event.set()

    def run(self) -> None:
        while not self._stop_event.is_set():
            start = time.time()
            try:
                self._manager.pull_once()
            except Exception as exc:  # pragma: no cover - defensive logging
                self._manager.record_error(exc)
            elapsed = time.time() - start
            wait_time = max(self._manager._poll_interval - elapsed, 0.0)
            self._stop_event.wait(wait_time)
