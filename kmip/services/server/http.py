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

"""HTTP helper service for KMIP health and replication endpoints."""

from __future__ import annotations

import http.server
import json
import logging
import os
import socketserver
import threading
from urllib.parse import urlparse


class ThreadingHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


class KmipHTTPService(threading.Thread):
    def __init__(self, host, port, status_provider, replication_manager=None, logger=None):
        super(KmipHTTPService, self).__init__(daemon=True)
        self._logger = logger or logging.getLogger("kmip.server.http")
        self._server = ThreadingHTTPServer(
            (host, port),
            KmipHTTPHandler
        )
        self._server.status_provider = status_provider
        self._server.replication_manager = replication_manager
        self._server.logger = self._logger

    def run(self) -> None:
        self._logger.info("Starting HTTP service on %s:%s", *self._server.server_address)
        self._server.serve_forever(poll_interval=0.5)

    def stop(self) -> None:
        self._logger.info("Stopping HTTP service.")
        self._server.shutdown()
        self._server.server_close()


class KmipHTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "PyKMIPHTTP/1.0"

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        path = urlparse(self.path).path
        if path == "/health":
            self._handle_health()
            return
        if path == "/replication/backup":
            self._handle_replication_backup()
            return
        self.send_error(404, "Not Found")

    def do_HEAD(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler naming
        path = urlparse(self.path).path
        if path == "/health":
            self._handle_health(head_only=True)
            return
        self.send_error(404, "Not Found")

    def log_message(self, format, *args):  # noqa: A003 - BaseHTTPRequestHandler API
        logger = getattr(self.server, "logger", None)
        if logger:
            logger.info("%s - %s", self.address_string(), format % args)

    def _handle_health(self, head_only: bool = False) -> None:
        try:
            payload = self.server.status_provider() if self.server.status_provider else {}
            body = json.dumps(payload, sort_keys=True).encode("utf-8")
        except Exception as exc:
            self.send_error(500, "Health check failed")
            logger = getattr(self.server, "logger", None)
            if logger:
                logger.exception("Health check failed: %s", exc)
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if not head_only:
            self.wfile.write(body)

    def _handle_replication_backup(self) -> None:
        manager = getattr(self.server, "replication_manager", None)
        if not manager or not manager.is_leader:
            self.send_error(404, "Replication backup not available")
            return

        if not manager.authorize(self.headers):
            self.send_response(401)
            self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            return

        try:
            backup_path = manager.create_backup()
        except Exception as exc:
            self.send_error(503, "Backup failed")
            logger = getattr(self.server, "logger", None)
            if logger:
                logger.exception("Replication backup failed: %s", exc)
            return

        if not backup_path or not os.path.exists(backup_path):
            self.send_error(503, "Backup unavailable")
            return

        try:
            file_size = os.path.getsize(backup_path)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(file_size))
            self.send_header(
                "Content-Disposition",
                'attachment; filename="{0}"'.format(os.path.basename(backup_path))
            )
            self.end_headers()
            with open(backup_path, "rb") as handle:
                while True:
                    chunk = handle.read(1024 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        finally:
            try:
                os.remove(backup_path)
            except OSError:
                pass
