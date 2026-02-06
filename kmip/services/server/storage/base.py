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

"""Abstract storage backend interface for KMIP server persistence."""

from abc import ABC
from abc import abstractmethod
from typing import Any
from typing import Mapping

from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session


class StorageBackendError(Exception):
    """Base exception for storage backend errors."""


class ConnectionError(StorageBackendError):
    """Raised when a storage backend cannot be reached."""


class ConfigurationError(StorageBackendError):
    """Raised when a storage backend is misconfigured."""


class StorageBackend(ABC):
    """Abstract base class for pluggable storage backends."""

    def __init__(self, config: Mapping[str, Any] | None = None) -> None:
        """Initialize the backend with its configuration.

        Args:
            config (Mapping[str, Any] | None): Backend configuration values.
        """
        self._config = dict(config or {})

    @property
    def config(self) -> Mapping[str, Any]:
        """Mapping[str, Any]: The configuration for this backend."""
        return self._config

    @abstractmethod
    def initialize(self) -> None:
        """Initialize backend connections and create schema if needed."""

    @abstractmethod
    def get_session(self) -> Session:
        """Return a SQLAlchemy session bound to the backend."""

    @abstractmethod
    def get_engine(self) -> Engine:
        """Return the SQLAlchemy engine for this backend."""

    @abstractmethod
    def health_check(self) -> bool:
        """Check backend connectivity and return True if healthy."""

    @abstractmethod
    def backup(self, destination: str | None = None) -> str | None:
        """Create a backend-specific backup if supported.

        Args:
            destination (str | None): Optional backup destination path/URI.

        Returns:
            str | None: Identifier for the created backup, if any.
        """

    @abstractmethod
    def restore(self, source: str) -> None:
        """Restore backend state from a backup source if supported.

        Args:
            source (str): Backup source path/URI.
        """

    @abstractmethod
    def get_connection_info(self) -> dict[str, Any]:
        """Return diagnostic connection information for this backend."""

    @abstractmethod
    def close(self) -> None:
        """Close any open connections and release backend resources."""
