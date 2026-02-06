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

"""SQLite storage backend implementation."""

from __future__ import annotations

import logging
import os
import shutil
import sqlite3
import tempfile
from typing import Any
from typing import Mapping

import sqlalchemy
from sqlalchemy import text
from sqlalchemy.engine import Engine
from sqlalchemy.engine.url import make_url

from kmip.pie import sqltypes
from kmip.services.server.storage.base import StorageBackend
from kmip.services.server.storage.base import StorageBackendError


class SQLiteBackend(StorageBackend):
    """SQLite storage backend for the KMIP server."""

    def __init__(
        self,
        config: Mapping[str, Any] | None = None,
        database_path: str | None = None,
    ) -> None:
        """Initialize the SQLite backend.

        Args:
            config (Mapping[str, Any] | None): Backend configuration values.
            database_path (str | None): Optional SQLite path override.
        """
        super().__init__(config)
        if database_path is not None:
            self._config["database_path"] = database_path

        self._logger = logging.getLogger("kmip.server.storage.sqlite")
        self._engine: Engine | None = None
        self._session_factory: sqlalchemy.orm.sessionmaker | None = None
        self._database_uri: str | None = None

    @property
    def database_uri(self) -> str | None:
        """str | None: The SQLAlchemy database URI, if initialized."""
        return self._database_uri

    def initialize(self) -> None:
        """Initialize the SQLite engine and schema."""
        if self._engine is not None and self._session_factory is not None:
            return

        self._ensure_database_uri()

        connect_args = {
            "check_same_thread": self._config.get("check_same_thread", False)
        }
        self._engine = sqlalchemy.create_engine(
            self._database_uri,
            echo=bool(self._config.get("echo", False)),
            connect_args=connect_args,
        )
        sqltypes.Base.metadata.create_all(self._engine)
        self._session_factory = sqlalchemy.orm.sessionmaker(bind=self._engine)

        self._logger.info(
            "Initialized SQLite storage backend: %s",
            self._database_uri,
        )

    def get_engine(self) -> Engine:
        """Return the SQLAlchemy engine for this backend."""
        self._ensure_initialized()
        return self._engine

    def get_session(self) -> sqlalchemy.orm.Session:
        """Return a SQLAlchemy session bound to the backend."""
        self._ensure_initialized()
        return self._session_factory()

    def health_check(self) -> bool:
        """Check backend connectivity and return True if healthy."""
        self._ensure_initialized()
        try:
            with self._engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            return True
        except sqlalchemy.exc.SQLAlchemyError:
            self._logger.exception("SQLite health check failed.")
            return False

    def backup(self, destination: str | None = None) -> str | None:
        """Create a file-based backup of the SQLite database.

        Args:
            destination (str | None): Optional backup destination path.

        Returns:
            str | None: Path to the created backup file.
        """
        self._ensure_database_uri()
        database_path = self._get_database_path()
        if database_path is None:
            raise StorageBackendError(
                "SQLite in-memory databases cannot be backed up."
            )
        if not os.path.exists(database_path):
            raise StorageBackendError(
                "SQLite database file does not exist: {0}".format(
                    database_path
                )
            )

        destination = destination or "{0}.bak".format(database_path)
        destination = os.path.abspath(destination)
        destination_dir = os.path.dirname(destination)
        if destination_dir:
            os.makedirs(destination_dir, exist_ok=True)

        try:
            source_conn = sqlite3.connect(database_path)
            dest_conn = sqlite3.connect(destination)
            try:
                source_conn.backup(dest_conn)
            finally:
                dest_conn.close()
                source_conn.close()
        except sqlite3.Error:
            self._logger.exception(
                "SQLite backup failed, falling back to file copy."
            )
            shutil.copy2(database_path, destination)

        self._logger.info("SQLite backup created at %s", destination)
        return destination

    def restore(self, source: str) -> None:
        """Restore the SQLite database from a backup source.

        Args:
            source (str): Backup source path.
        """
        self._ensure_database_uri()
        database_path = self._get_database_path()
        if database_path is None:
            raise StorageBackendError(
                "SQLite in-memory databases cannot be restored."
            )
        if not os.path.exists(source):
            raise StorageBackendError(
                "SQLite backup source does not exist: {0}".format(source)
            )

        self.close()
        database_dir = os.path.dirname(database_path)
        if database_dir:
            os.makedirs(database_dir, exist_ok=True)
        shutil.copy2(source, database_path)
        self.initialize()
        self._logger.info("SQLite database restored from %s", source)

    def get_connection_info(self) -> dict[str, Any]:
        """Return diagnostic connection information for this backend."""
        return {
            "backend": "sqlite",
            "database_uri": self._database_uri,
            "database_path": self._get_database_path(),
            "initialized": self._engine is not None,
        }

    def close(self) -> None:
        """Close any open connections and release backend resources."""
        if self._engine is not None:
            self._engine.dispose()
        self._engine = None
        self._session_factory = None

    def _ensure_initialized(self) -> None:
        if self._engine is None or self._session_factory is None:
            self.initialize()

    def _ensure_database_uri(self) -> None:
        if self._database_uri is None:
            self._database_uri = self._build_database_uri(
                self._config.get("database_path")
            )

    def _build_database_uri(self, database_path: str | None) -> str:
        if database_path:
            if database_path.startswith("sqlite:"):
                return database_path
            if database_path == ":memory:":
                return "sqlite:///:memory:"

            db_path = os.path.abspath(database_path)
            db_dir = os.path.dirname(db_path)
            if db_dir:
                os.makedirs(db_dir, exist_ok=True)
            return "sqlite:///{}".format(db_path.replace("\\", "/"))

        db_path = os.path.join(tempfile.gettempdir(), "pykmip.database")
        db_dir = os.path.dirname(db_path)
        if db_dir:
            os.makedirs(db_dir, exist_ok=True)
        return "sqlite:///{}".format(db_path.replace("\\", "/"))

    def _get_database_path(self) -> str | None:
        if not self._database_uri:
            return None
        url = make_url(self._database_uri)
        if url.database in (None, "", ":memory:"):
            return None
        return url.database
