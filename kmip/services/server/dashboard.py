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

"""Lightweight Flask dashboard for KMIP server monitoring."""

from __future__ import annotations

import datetime
import logging
import threading
from typing import Any, Callable, Mapping

from flask import Flask, abort, redirect, render_template, request, url_for
from jinja2 import DictLoader
from sqlalchemy import func
from werkzeug.serving import make_server

from kmip.core import enums
from kmip.core import policy as core_policy
from kmip.pie import objects as pie_objects
from kmip.pie import sqltypes

StatusProvider = Callable[[], Mapping[str, Any]]
PolicyProvider = Callable[[], Mapping[str, Any]]
SessionFactory = Callable[[], Any]


TEMPLATES: dict[str, str] = {}

TEMPLATES["layout.html"] = """
<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>{{ page_title }} - KMIP Dashboard</title>
    <style>
      @import url("https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600&family=IBM+Plex+Mono:wght@400;500&display=swap");

      :root {
        --bg-1: #0b1020;
        --bg-2: #12223f;
        --card: rgba(10, 18, 36, 0.78);
        --border: rgba(148, 163, 184, 0.2);
        --text: #f8fafc;
        --muted: #94a3b8;
        --accent: #f97316;
        --accent-2: #22c55e;
        --danger: #ef4444;
        --shadow: 0 20px 40px rgba(3, 7, 18, 0.4);
      }

      * { box-sizing: border-box; }

      body {
        margin: 0;
        min-height: 100vh;
        font-family: "Space Grotesk", "IBM Plex Sans", sans-serif;
        color: var(--text);
        background:
          radial-gradient(900px 600px at 10% 10%, rgba(34, 197, 94, 0.18), transparent 55%),
          radial-gradient(900px 600px at 85% 15%, rgba(249, 115, 22, 0.2), transparent 55%),
          linear-gradient(180deg, var(--bg-1), var(--bg-2));
      }

      body::before {
        content: "";
        position: fixed;
        inset: 0;
        pointer-events: none;
        background-image:
          repeating-linear-gradient(90deg, rgba(148, 163, 184, 0.05), rgba(148, 163, 184, 0.05) 1px, transparent 1px, transparent 40px);
        mix-blend-mode: screen;
      }

      a { color: inherit; text-decoration: none; }

      .wrap { position: relative; z-index: 1; }

      .topbar {
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 22px 8vw 12px;
        gap: 16px;
        flex-wrap: wrap;
      }

      .title h1 { margin: 0; font-size: 28px; }
      .title span { font-size: 13px; color: var(--muted); }

      .status-pill {
        display: inline-flex;
        align-items: center;
        gap: 8px;
        padding: 6px 14px;
        border-radius: 999px;
        border: 1px solid rgba(148, 163, 184, 0.25);
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 1px;
        background: rgba(15, 23, 42, 0.4);
      }

      .status-pill::before {
        content: "";
        width: 8px;
        height: 8px;
        border-radius: 50%;
        background: var(--accent-2);
        box-shadow: 0 0 12px rgba(34, 197, 94, 0.7);
      }

      .status-pill.degraded::before {
        background: var(--danger);
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.7);
      }

      nav {
        display: flex;
        gap: 12px;
        flex-wrap: wrap;
        padding: 0 8vw 12px;
      }

      nav a {
        padding: 8px 14px;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.35);
        font-size: 13px;
        color: var(--muted);
      }

      nav a.active {
        color: var(--text);
        border: 1px solid rgba(249, 115, 22, 0.45);
        background: rgba(249, 115, 22, 0.12);
      }

      main { padding: 0 8vw 60px; }

      .grid { display: grid; gap: 18px; }
      .grid.cols-3 { grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); }
      .grid.cols-2 { grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); }

      .card {
        background: var(--card);
        border: 1px solid var(--border);
        border-radius: 18px;
        padding: 18px;
        box-shadow: var(--shadow);
        backdrop-filter: blur(6px);
        animation: fadeUp 0.6s ease both;
      }

      .card h3 {
        margin: 0 0 12px;
        font-size: 14px;
        text-transform: uppercase;
        letter-spacing: 1px;
        color: var(--muted);
      }

      .metric { font-size: 30px; font-weight: 600; }
      .muted { color: var(--muted); }
      .mono { font-family: "IBM Plex Mono", ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; font-size: 12px; }

      .table { width: 100%; border-collapse: collapse; font-size: 14px; }
      .table th, .table td { text-align: left; padding: 10px 6px; border-bottom: 1px solid rgba(148, 163, 184, 0.12); }
      .table th { color: var(--muted); font-weight: 500; text-transform: uppercase; letter-spacing: 0.8px; font-size: 11px; }

      .notice {
        margin: 16px 0;
        padding: 12px 14px;
        border-radius: 12px;
        background: rgba(34, 197, 94, 0.12);
        border: 1px solid rgba(34, 197, 94, 0.35);
        color: #bbf7d0;
      }

      .form-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: center; }
      input, select, button {
        font-family: inherit;
        padding: 8px 12px;
        border-radius: 10px;
        border: 1px solid rgba(148, 163, 184, 0.25);
        background: rgba(15, 23, 42, 0.6);
        color: var(--text);
      }
      button { border-color: rgba(249, 115, 22, 0.45); background: rgba(249, 115, 22, 0.15); cursor: pointer; }
      button.danger { border-color: rgba(239, 68, 68, 0.45); background: rgba(239, 68, 68, 0.2); }

      .tag { display: inline-flex; padding: 4px 10px; border-radius: 999px; background: rgba(34, 197, 94, 0.16); color: #bbf7d0; font-size: 12px; }

      .footer { padding: 20px 8vw 40px; color: var(--muted); font-size: 12px; }

      @keyframes fadeUp { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }

      @media (max-width: 720px) {
        .topbar { padding: 18px 6vw 10px; }
        nav, main, .footer { padding-left: 6vw; padding-right: 6vw; }
      }
    </style>
  </head>
  <body>
    <div class="wrap">
      <div class="topbar">
        <div class="title">
          <h1>KMIP Dashboard</h1>
          <span>{{ subtitle }}</span>
        </div>
        <div class="status-pill {% if status_label != 'ok' %}degraded{% endif %}">{{ status_label }}</div>
      </div>
      <nav>
        <a href="{{ url_for('index') }}" class="{% if active == 'index' %}active{% endif %}">Overview</a>
        <a href="{{ url_for('objects') }}" class="{% if active == 'objects' %}active{% endif %}">Objects</a>
        <a href="{{ url_for('policies') }}" class="{% if active == 'policies' %}active{% endif %}">Policies</a>
      </nav>
      <main>
        {% if notice %}<div class="notice">{{ notice }}</div>{% endif %}
        {% block content %}{% endblock %}
      </main>
      <div class="footer">Intended for local monitoring and demos. Changes apply directly to the KMIP database.</div>
    </div>
  </body>
</html>
"""

TEMPLATES["index.html"] = """
{% extends "layout.html" %}
{% block content %}
  <div class="grid cols-3">
    <div class="card">
      <h3>Total Objects</h3>
      <div class="metric">{{ summary.total_objects }}</div>
      <div class="muted">Managed objects stored in SQLAlchemy.</div>
    </div>
    <div class="card">
      <h3>KMIP Server</h3>
      <div class="metric">{{ summary.kmip_port }}</div>
      <div class="muted">{{ summary.kmip_host }}</div>
    </div>
    <div class="card">
      <h3>Storage</h3>
      <div class="metric">{{ summary.storage_status }}</div>
      <div class="muted mono">{{ summary.storage_uri }}</div>
    </div>
  </div>

  <div class="grid cols-2" style="margin-top: 20px;">
    <div class="card">
      <h3>Objects By Type</h3>
      {% if summary.by_type %}
        <table class="table">
          <thead><tr><th>Type</th><th>Count</th></tr></thead>
          <tbody>
            {% for row in summary.by_type %}
              <tr><td>{{ row.name }}</td><td>{{ row.count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <div class="muted">No objects yet.</div>
      {% endif %}
    </div>
    <div class="card">
      <h3>Crypto States</h3>
      {% if summary.by_state %}
        <table class="table">
          <thead><tr><th>State</th><th>Count</th></tr></thead>
          <tbody>
            {% for row in summary.by_state %}
              <tr><td>{{ row.name }}</td><td>{{ row.count }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <div class="muted">No cryptographic objects yet.</div>
      {% endif %}
    </div>
  </div>

  <div class="card" style="margin-top: 20px;">
    <h3>Recent Objects</h3>
    {% if summary.recent %}
      <table class="table">
        <thead><tr><th>ID</th><th>Type</th><th>Name</th><th>State</th><th></th></tr></thead>
        <tbody>
          {% for obj in summary.recent %}
            <tr>
              <td class="mono">{{ obj.uid }}</td>
              <td>{{ obj.object_type }}</td>
              <td>{{ obj.name }}</td>
              <td>{{ obj.state }}</td>
              <td><a href="{{ url_for('object_detail', uid=obj.uid) }}">View</a></td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <div class="muted">No objects available.</div>
    {% endif %}
  </div>
{% endblock %}
"""

TEMPLATES["objects.html"] = """
{% extends "layout.html" %}
{% block content %}
  <div class="card">
    <h3>Filters</h3>
    <form class="form-row" method="get">
      <input name="name" placeholder="Name contains" value="{{ filters.name }}" />
      <select name="object_type">
        <option value="">All Types</option>
        {% for item in filters.object_types %}
          <option value="{{ item.value }}" {% if item.value == filters.object_type %}selected{% endif %}>{{ item.label }}</option>
        {% endfor %}
      </select>
      <select name="state">
        <option value="">All States</option>
        {% for item in filters.states %}
          <option value="{{ item.value }}" {% if item.value == filters.state %}selected{% endif %}>{{ item.label }}</option>
        {% endfor %}
      </select>
      <select name="page_size">
        {% for size in filters.page_sizes %}
          <option value="{{ size }}" {% if size == filters.page_size %}selected{% endif %}>{{ size }} / page</option>
        {% endfor %}
      </select>
      <button type="submit">Apply</button>
    </form>
  </div>

  <div class="card" style="margin-top: 18px;">
    <h3>Managed Objects</h3>
    {% if objects %}
      <table class="table">
        <thead><tr><th>ID</th><th>Type</th><th>Name</th><th>State</th><th>Policy</th><th></th></tr></thead>
        <tbody>
          {% for obj in objects %}
            <tr>
              <td class="mono">{{ obj.uid }}</td>
              <td>{{ obj.object_type }}</td>
              <td>{{ obj.name }}</td>
              <td>{{ obj.state }}</td>
              <td>{{ obj.policy }}</td>
              <td><a href="{{ url_for('object_detail', uid=obj.uid) }}">View</a></td>
            </tr>
          {% endfor %}
        </tbody>
      </table>
    {% else %}
      <div class="muted">No objects match the current filters.</div>
    {% endif %}

    <div class="form-row" style="margin-top: 16px;">
      <span class="muted">Page {{ pagination.page }} of {{ pagination.total_pages }} ({{ pagination.total }} total)</span>
      {% if pagination.prev_url %}<a href="{{ pagination.prev_url }}">Previous</a>{% endif %}
      {% if pagination.next_url %}<a href="{{ pagination.next_url }}">Next</a>{% endif %}
    </div>
  </div>
{% endblock %}
"""

TEMPLATES["object_detail.html"] = """
{% extends "layout.html" %}
{% block content %}
  <div class="grid cols-2">
    <div class="card">
      <h3>Overview</h3>
      <table class="table">
        <tbody>
          {% for row in details.attributes %}
            <tr><th>{{ row.label }}</th><td>{{ row.value }}</td></tr>
          {% endfor %}
        </tbody>
      </table>
    </div>
    <div class="card">
      <h3>Names</h3>
      {% if details.names %}
        <table class="table">
          <thead><tr><th>Name</th><th>Type</th></tr></thead>
          <tbody>
            {% for name in details.names %}
              <tr><td>{{ name.value }}</td><td>{{ name.name_type }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <div class="muted">No names assigned.</div>
      {% endif %}
    </div>
  </div>

  <div class="grid cols-2" style="margin-top: 18px;">
    <div class="card">
      <h3>Application Info</h3>
      {% if details.app_specific_info %}
        <table class="table">
          <thead><tr><th>Namespace</th><th>Data</th></tr></thead>
          <tbody>
            {% for row in details.app_specific_info %}
              <tr><td>{{ row.namespace }}</td><td>{{ row.data }}</td></tr>
            {% endfor %}
          </tbody>
        </table>
      {% else %}
        <div class="muted">No application specific information.</div>
      {% endif %}
    </div>
    <div class="card">
      <h3>Object Groups</h3>
      {% if details.object_groups %}
        <ul>{% for group in details.object_groups %}<li>{{ group }}</li>{% endfor %}</ul>
      {% else %}
        <div class="muted">No object groups.</div>
      {% endif %}
    </div>
  </div>

  <div class="grid cols-2" style="margin-top: 18px;">
    <div class="card">
      <h3>Value Preview</h3>
      <div class="mono">{{ details.value_preview }}</div>
    </div>
    <div class="card">
      <h3>Manual Actions</h3>
      <form class="form-row" method="post" action="{{ url_for('update_state', uid=details.uid) }}">
        <select name="state">
          {% for state in details.states %}
            <option value="{{ state.value }}">{{ state.label }}</option>
          {% endfor %}
        </select>
        <button type="submit">Update State</button>
      </form>
      <form class="form-row" method="post" action="{{ url_for('delete_object', uid=details.uid) }}" style="margin-top: 12px;">
        <input type="hidden" name="confirm" value="delete" />
        <button type="submit" class="danger">Delete Object</button>
      </form>
      <div class="muted" style="margin-top: 10px;">State updates apply only to cryptographic objects.</div>
    </div>
  </div>
{% endblock %}
"""

TEMPLATES["policies.html"] = """
{% extends "layout.html" %}
{% block content %}
  <div class="card">
    <h3>Operation Policies</h3>
    {% if policies %}
      {% for policy in policies %}
        <div style="margin-bottom: 18px;">
          <div class="tag">{{ policy.name }}</div>
          {% for group in policy.groups %}
            <h4 class="muted" style="margin-top: 12px;">{{ group.name }}</h4>
            <table class="table">
              <thead><tr><th>Object Type</th><th>Operation</th><th>Policy</th></tr></thead>
              <tbody>
                {% for row in group.rows %}
                  <tr>
                    <td>{{ row.object_type }}</td>
                    <td>{{ row.operation }}</td>
                    <td>{{ row.policy }}</td>
                  </tr>
                {% endfor %}
              </tbody>
            </table>
          {% endfor %}
        </div>
      {% endfor %}
    {% else %}
      <div class="muted">No policies loaded.</div>
    {% endif %}
  </div>
{% endblock %}
"""


def _enum_label(value: Any) -> str:
    if value is None:
        return "-"
    if hasattr(value, "name"):
        return value.name.replace("_", " ").title()
    return str(value)


def _format_timestamp(value: Any) -> str:
    if value in (None, 0):
        return "-"
    try:
        dt = datetime.datetime.utcfromtimestamp(int(value))
        return dt.isoformat() + "Z"
    except Exception:
        return str(value)


def _format_value_preview(value: Any, sensitive: bool) -> str:
    if value is None:
        return "-"
    if sensitive:
        return "{0} bytes (sensitive)".format(len(value))
    if isinstance(value, bytes):
        hex_value = value.hex()
        preview = hex_value[:32]
        if len(hex_value) > 32:
            preview += "..."
        return "{0} bytes 0x{1}".format(len(value), preview)
    return str(value)


def _parse_enum(enum_cls, value: str | None):
    if not value:
        return None
    key = value.strip().upper()
    return enum_cls.__members__.get(key)


def _safe_status(status_provider: StatusProvider | None) -> dict[str, Any]:
    if not status_provider:
        return {}
    try:
        return dict(status_provider())
    except Exception:
        return {}


def _normalize_policy_source(source: Mapping[str, Any] | None) -> Mapping[str, Any]:
    if source is None:
        return {}
    if isinstance(source, dict):
        return source
    try:
        return {k: v for k, v in source.items()}
    except Exception:
        return {}


def _serialize_policies(policy_map: Mapping[str, Any]) -> list[dict[str, Any]]:
    policies = []
    for name, policy in policy_map.items():
        groups = []
        for group_name, group_policy in policy.items():
            rows = []
            for object_type, operations in group_policy.items():
                for operation, policy_value in operations.items():
                    rows.append(
                        {
                            "object_type": _enum_label(object_type),
                            "operation": _enum_label(operation),
                            "policy": _enum_label(policy_value),
                        }
                    )
            rows.sort(key=lambda row: (row["object_type"], row["operation"]))
            groups.append({"name": group_name, "rows": rows})
        policies.append({"name": name, "groups": groups})
    return policies


def _build_summary(session_factory: SessionFactory, status_provider: StatusProvider | None) -> dict[str, Any]:
    status = _safe_status(status_provider)
    with session_factory() as session:
        total_objects = session.query(func.count(pie_objects.ManagedObject.unique_identifier)).scalar() or 0

        by_type_rows = session.query(
            pie_objects.ManagedObject._object_type,
            func.count(pie_objects.ManagedObject.unique_identifier),
        ).group_by(pie_objects.ManagedObject._object_type).all()
        by_type = [
            {"name": _enum_label(row[0]), "count": row[1]}
            for row in by_type_rows
        ]
        by_type.sort(key=lambda row: row["count"], reverse=True)

        by_state_rows = session.query(
            pie_objects.CryptographicObject.state,
            func.count(pie_objects.CryptographicObject.unique_identifier),
        ).group_by(pie_objects.CryptographicObject.state).all()
        by_state = [
            {"name": _enum_label(row[0]), "count": row[1]}
            for row in by_state_rows
        ]
        by_state.sort(key=lambda row: row["count"], reverse=True)

        recent_objects = session.query(pie_objects.ManagedObject).order_by(
            pie_objects.ManagedObject.unique_identifier.desc()
        ).limit(10).all()

    recent = []
    for obj in recent_objects:
        name = obj.names[0] if getattr(obj, "names", None) else "-"
        state = _enum_label(getattr(obj, "state", None))
        recent.append(
            {
                "uid": obj.unique_identifier,
                "object_type": _enum_label(getattr(obj, "_object_type", None)),
                "name": name,
                "state": state,
            }
        )

    kmip_info = status.get("kmip", {})
    storage_info = status.get("storage", {}).get("info", {})

    return {
        "total_objects": total_objects,
        "by_type": by_type,
        "by_state": by_state,
        "recent": recent,
        "kmip_host": kmip_info.get("hostname", "-"),
        "kmip_port": kmip_info.get("port", "-"),
        "storage_status": "healthy" if status.get("storage", {}).get("healthy") else "degraded",
        "storage_uri": storage_info.get("database_uri", "-"),
    }


def create_app(
    session_factory: SessionFactory,
    status_provider: StatusProvider | None = None,
    policy_provider: PolicyProvider | None = None,
) -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "pykmip-dashboard"
    app.jinja_loader = DictLoader(TEMPLATES)

    def _base_context(active: str, subtitle: str, notice: str | None = None):
        status = _safe_status(status_provider)
        status_label = status.get("status", "unknown")
        return {
            "active": active,
            "subtitle": subtitle,
            "status_label": status_label,
            "notice": notice,
        }

    @app.get("/")
    def index():
        notice = request.args.get("notice")
        summary = _build_summary(session_factory, status_provider)
        context = _base_context("index", "Server overview", notice)
        return render_template(
            "index.html",
            page_title="Overview",
            summary=summary,
            **context,
        )

    @app.get("/objects")
    def objects():
        notice = request.args.get("notice")
        name_filter = request.args.get("name", "").strip()
        object_type_filter = request.args.get("object_type", "").strip()
        state_filter = request.args.get("state", "").strip()

        page_size = int(request.args.get("page_size", 25))
        page_size = max(5, min(page_size, 100))
        page = max(1, int(request.args.get("page", 1)))

        object_type = _parse_enum(enums.ObjectType, object_type_filter)
        state = _parse_enum(enums.State, state_filter)

        with session_factory() as session:
            query = session.query(pie_objects.ManagedObject)

            if object_type:
                query = query.filter(pie_objects.ManagedObject._object_type == object_type)

            if name_filter:
                name_ids = session.query(sqltypes.ManagedObjectName.mo_uid).filter(
                    sqltypes.ManagedObjectName.name.ilike("%{0}%".format(name_filter))
                ).subquery()
                query = query.filter(pie_objects.ManagedObject.unique_identifier.in_(name_ids))

            if state:
                state_ids = session.query(pie_objects.CryptographicObject.unique_identifier).filter(
                    pie_objects.CryptographicObject.state == state
                ).subquery()
                query = query.filter(pie_objects.ManagedObject.unique_identifier.in_(state_ids))

            total = query.count()
            items = query.order_by(
                pie_objects.ManagedObject.unique_identifier.desc()
            ).limit(page_size).offset((page - 1) * page_size).all()

        objects_view = []
        for obj in items:
            name = obj.names[0] if getattr(obj, "names", None) else "-"
            objects_view.append(
                {
                    "uid": obj.unique_identifier,
                    "object_type": _enum_label(getattr(obj, "_object_type", None)),
                    "state": _enum_label(getattr(obj, "state", None)),
                    "name": name,
                    "policy": obj.operation_policy_name or "-",
                }
            )

        total_pages = max(1, (total + page_size - 1) // page_size)
        pagination = {
            "page": page,
            "total_pages": total_pages,
            "total": total,
            "prev_url": None,
            "next_url": None,
        }

        def _build_page_url(target_page: int) -> str:
            args = dict(request.args)
            args["page"] = str(target_page)
            return url_for("objects", **args)

        if page > 1:
            pagination["prev_url"] = _build_page_url(page - 1)
        if page < total_pages:
            pagination["next_url"] = _build_page_url(page + 1)

        filters = {
            "name": name_filter,
            "object_type": object_type_filter,
            "state": state_filter,
            "page_size": page_size,
            "page_sizes": [10, 25, 50, 100],
            "object_types": [
                {"value": item.name, "label": _enum_label(item)}
                for item in enums.ObjectType
            ],
            "states": [
                {"value": item.name, "label": _enum_label(item)}
                for item in enums.State
            ],
        }

        context = _base_context("objects", "Browse managed objects", notice)
        return render_template(
            "objects.html",
            page_title="Objects",
            objects=objects_view,
            pagination=pagination,
            filters=filters,
            **context,
        )

    @app.get("/objects/<int:uid>")
    def object_detail(uid: int):
        notice = request.args.get("notice")
        with session_factory() as session:
            obj = session.get(pie_objects.ManagedObject, uid)
            if not obj:
                abort(404)

            names = [
                {
                    "value": name.name,
                    "name_type": _enum_label(name.name_type),
                }
                for name in getattr(obj, "_names", [])
            ]

            app_specific_info = [
                {
                    "namespace": info.application_namespace or "-",
                    "data": info.application_data or "-",
                }
                for info in getattr(obj, "app_specific_info", [])
            ]

            object_groups = [
                group.object_group
                for group in getattr(obj, "object_groups", [])
            ]

            attributes = [
                {"label": "Unique Identifier", "value": obj.unique_identifier},
                {"label": "Object Type", "value": _enum_label(getattr(obj, "_object_type", None))},
                {"label": "Operation Policy", "value": obj.operation_policy_name or "-"},
                {"label": "Owner", "value": getattr(obj, "_owner", None) or "-"},
                {"label": "Sensitive", "value": "yes" if obj.sensitive else "no"},
                {"label": "Initial Date", "value": _format_timestamp(obj.initial_date)},
            ]

            if hasattr(obj, "state"):
                attributes.append({"label": "State", "value": _enum_label(obj.state)})

            if isinstance(obj, pie_objects.Key):
                attributes.extend(
                    [
                        {"label": "Algorithm", "value": _enum_label(obj.cryptographic_algorithm)},
                        {"label": "Length", "value": obj.cryptographic_length or "-"},
                        {"label": "Key Format", "value": _enum_label(obj.key_format_type)},
                        {
                            "label": "Usage Masks",
                            "value": ", ".join(_enum_label(mask) for mask in obj.cryptographic_usage_masks)
                            if obj.cryptographic_usage_masks else "-",
                        },
                    ]
                )

            if isinstance(obj, pie_objects.Certificate):
                attributes.append({"label": "Certificate Type", "value": _enum_label(obj.certificate_type)})

            if isinstance(obj, pie_objects.SecretData):
                attributes.append({"label": "Data Type", "value": _enum_label(obj.data_type)})

            if isinstance(obj, pie_objects.OpaqueObject):
                attributes.append({"label": "Opaque Type", "value": _enum_label(obj.opaque_type)})

            details = {
                "uid": obj.unique_identifier,
                "attributes": attributes,
                "names": names,
                "app_specific_info": app_specific_info,
                "object_groups": object_groups,
                "value_preview": _format_value_preview(obj.value, obj.sensitive),
                "states": [
                    {"value": item.name, "label": _enum_label(item)}
                    for item in enums.State
                ],
            }

        context = _base_context("objects", "Object details", notice)
        return render_template(
            "object_detail.html",
            page_title="Object {0}".format(uid),
            details=details,
            **context,
        )

    @app.post("/objects/<int:uid>/state")
    def update_state(uid: int):
        state_value = request.form.get("state")
        state = _parse_enum(enums.State, state_value)
        if state is None:
            return redirect(url_for("object_detail", uid=uid, notice="Invalid state"))

        with session_factory() as session:
            obj = session.get(pie_objects.ManagedObject, uid)
            if not obj:
                abort(404)
            if not hasattr(obj, "state"):
                return redirect(url_for("object_detail", uid=uid, notice="State not supported"))
            obj.state = state
            session.commit()

        return redirect(url_for("object_detail", uid=uid, notice="State updated"))

    @app.post("/objects/<int:uid>/delete")
    def delete_object(uid: int):
        confirm = request.form.get("confirm")
        if confirm != "delete":
            return redirect(url_for("object_detail", uid=uid, notice="Delete canceled"))

        with session_factory() as session:
            obj = session.get(pie_objects.ManagedObject, uid)
            if not obj:
                abort(404)
            session.delete(obj)
            session.commit()

        return redirect(url_for("objects", notice="Object deleted"))

    @app.get("/policies")
    def policies():
        notice = request.args.get("notice")
        source = _normalize_policy_source(
            policy_provider() if policy_provider else core_policy.policies
        )
        rendered = _serialize_policies(source)
        context = _base_context("policies", "Operation policies", notice)
        return render_template(
            "policies.html",
            page_title="Policies",
            policies=rendered,
            **context,
        )

    return app


class KmipDashboardService(threading.Thread):
    def __init__(
        self,
        host: str,
        port: int,
        session_factory: SessionFactory,
        status_provider: StatusProvider | None = None,
        policy_provider: PolicyProvider | None = None,
        logger: logging.Logger | None = None,
    ) -> None:
        super(KmipDashboardService, self).__init__(daemon=True)
        self._logger = logger or logging.getLogger("kmip.server.dashboard")
        self._app = create_app(
            session_factory=session_factory,
            status_provider=status_provider,
            policy_provider=policy_provider,
        )
        self._server = make_server(host, port, self._app, threaded=True)
        self._server.timeout = 0.5

    def run(self) -> None:
        address = self._server.server_address
        self._logger.info("Starting dashboard on %s:%s", *address)
        self._server.serve_forever()

    def stop(self) -> None:
        self._logger.info("Stopping dashboard service.")
        self._server.shutdown()
