from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest


def test_structured_config_boolean_values_are_not_coerced_by_truthiness():
    from web.api.server import _normalize_config_value

    definition = {"type": "boolean"}
    assert _normalize_config_value(definition, False) is False
    assert _normalize_config_value(definition, "false") is False
    assert _normalize_config_value(definition, "true") is True
    with pytest.raises(ValueError):
        _normalize_config_value(definition, "not-a-boolean")
    assert _normalize_config_value({"type": "ports"}, "11434, 7799 9200") == [7799, 9200, 11434]


def test_structured_config_exposes_curated_fields_not_internal_yaml():
    from web.api.server import CONFIG_FIELD_DEFINITIONS

    paths = {item["path"] for item in CONFIG_FIELD_DEFINITIONS}
    assert "llm.provider" in paths
    assert "graph_enrichment.duckduckgo_fallback" in paths
    assert "db.password" not in paths
    assert all("default" in item for item in CONFIG_FIELD_DEFINITIONS)


async def _request(app, method, path, **kwargs):
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        return await client.request(method, path, **kwargs)


def test_action_approval_endpoint_dispatches_only_manifest_gated_skill():
    from web.api import server

    captured = {}
    skill = SimpleNamespace(metadata={"manifest": {"risk_level": "privileged_approval_required"}})

    class _Runner:
        _skills = {"defensive_action": skill}

        def _build_context(self):
            return {}

        def dispatch(self, skill_name, context):
            captured.update({"skill": skill_name, "context": context})
            return {"status": "ok", "action": context["parameters"]["action"]}

    context = SimpleNamespace(runner=_Runner(), llm=SimpleNamespace(), cfg=SimpleNamespace())
    service = SimpleNamespace(context=context, start=lambda: None, stop=lambda: None, restart=lambda: None)
    with patch.object(server, "SecurityClawService", lambda **kwargs: service), \
         patch.object(server, "add_user_message_to_history"), \
         patch.object(server, "add_assistant_message_to_history"):
        app = server.create_app(enable_scheduler=False)
        app.state.service = service
        response = asyncio.run(_request(app, "POST", "/api/actions/approve", json={
            "conversation_id": "incident-1",
            "skill": "defensive_action",
            "action": "block_ip",
            "arguments": {"ip": "203.0.113.8"},
            "authorization_token": "single-use-token",
        }))

    assert response.status_code == 200
    assert captured["skill"] == "defensive_action"
    assert captured["context"]["parameters"] == {
        "action": "block_ip",
        "ip": "203.0.113.8",
        "authorization_token": "single-use-token",
    }
    assert captured["context"]["operator_message"] == "AUTHORIZE single-use-token"
