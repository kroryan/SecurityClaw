from core.llm_provider import OllamaProvider


class _Config:
    values = {
        ("llm", "ollama_base_url"): "http://localhost:11434",
        ("llm", "ollama_model"): "test-chat",
        ("llm", "ollama_embed_model"): "test-embed",
        ("llm", "temperature"): 0.2,
        ("llm", "think"): False,
        ("llm", "max_tokens"): 256,
        ("llm", "request_timeout_seconds"): 600,
        ("llm", "embedding_timeout_seconds"): 120,
    }

    def get(self, *keys, default=None):
        return self.values.get(keys, default)


class _Response:
    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": "ok"}, "embeddings": [[0.1, 0.2]]}


class _Requests:
    def __init__(self):
        self.calls = []

    def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return _Response()


def test_chat_uses_configurable_local_generation_timeout(monkeypatch):
    monkeypatch.setattr("core.llm_provider.Config", _Config)
    provider = OllamaProvider()
    requests = _Requests()
    provider._requests = requests

    assert provider.chat([{"role": "user", "content": "hello"}]) == "ok"
    assert requests.calls[0][1]["timeout"] == (10, 600)
    assert requests.calls[0][1]["json"]["think"] is False


def test_embed_uses_separate_configurable_timeout(monkeypatch):
    monkeypatch.setattr("core.llm_provider.Config", _Config)
    provider = OllamaProvider()
    requests = _Requests()
    provider._requests = requests

    assert provider.embed("hello") == [0.1, 0.2]
    assert requests.calls[0][1]["timeout"] == (10, 120)
