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

import os
import shutil
import tempfile

import testtools

from kmip.services.server.storage.base import StorageBackendError
from kmip.services.server.storage.sqlite_backend import SQLiteBackend


class TestSQLiteBackend(testtools.TestCase):
    """Unit tests for the SQLite storage backend."""

    def setUp(self):
        super(TestSQLiteBackend, self).setUp()
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)

    def tearDown(self):
        super(TestSQLiteBackend, self).tearDown()

    def test_initialize_in_memory(self):
        """Test initializing an in-memory SQLite backend."""
        backend = SQLiteBackend(database_path=":memory:")
        backend.initialize()

        self.assertEqual("sqlite:///:memory:", backend.database_uri)
        self.assertTrue(backend.health_check())

        with backend.get_session() as session:
            self.assertIsNotNone(session.bind)

        backend.close()

    def test_backup_in_memory_not_supported(self):
        """Test that backups are not supported for in-memory SQLite."""
        backend = SQLiteBackend(database_path=":memory:")
        backend.initialize()

        self.assertRaises(StorageBackendError, backend.backup)
        backend.close()

    def test_backup_and_restore_file_database(self):
        """Test backup and restore for a file-based SQLite database."""
        database_path = os.path.join(self.temp_dir, "pykmip.db")
        backend = SQLiteBackend(database_path=database_path)
        backend.initialize()

        backup_path = backend.backup()
        self.assertTrue(os.path.exists(backup_path))

        backend.close()
        os.remove(database_path)
        backend.restore(backup_path)

        self.assertTrue(os.path.exists(database_path))
        backend.close()

    def test_connection_info(self):
        """Test diagnostic connection information."""
        backend = SQLiteBackend(database_path=":memory:")
        backend.initialize()

        info = backend.get_connection_info()
        self.assertEqual("sqlite", info["backend"])
        self.assertEqual("sqlite:///:memory:", info["database_uri"])
        self.assertTrue(info["initialized"])

        backend.close()