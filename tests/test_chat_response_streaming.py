from core.chat_router.logic import _chat_response


class _StreamingLLM:
    def __init__(self):
        self.stream_calls = 0
        self.chat_calls = 0

    def stream_chat(self, messages, *, token_callback):
        self.stream_calls += 1
        token_callback("Security")
        token_callback("Claw")
        return "SecurityClaw"

    def chat(self, messages):
        self.chat_calls += 1
        return "blocking"


def test_chat_response_forwards_streamed_tokens_with_phase():
    llm = _StreamingLLM()
    events = []

    response = _chat_response(
        llm,
        [{"role": "user", "content": "hello"}],
        token_callback=lambda phase, token: events.append((phase, token)),
        phase="answer",
    )

    assert response == "SecurityClaw"
    assert events == [("answer", "Security"), ("answer", "Claw")]
    assert llm.stream_calls == 1
    assert llm.chat_calls == 0


def test_chat_response_falls_back_to_blocking_without_callback():
    llm = _StreamingLLM()

    response = _chat_response(
        llm,
        [{"role": "user", "content": "hello"}],
    )

    assert response == "blocking"
    assert llm.stream_calls == 0
    assert llm.chat_calls == 1
