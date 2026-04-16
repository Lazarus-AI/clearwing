from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from clearwing.llm.compat import invoke_text_compat


class _AsyncOnlyClient:
    async def aask_text(self, *, system: str, user: str):
        return SimpleNamespace(text=f"{system}:{user}")


class TestInvokeTextCompat:
    def test_prefers_aask_text_for_native_client_shapes(self):
        llm = MagicMock()
        llm.aask_text.return_value = SimpleNamespace(text="PONG")

        text = invoke_text_compat(llm, system="Reply with exactly PONG", user="ping")

        assert text == "PONG"
        llm.aask_text.assert_called_once_with(
            system="Reply with exactly PONG",
            user="ping",
        )
        llm.invoke.assert_not_called()
        llm.chat.assert_not_called()

    def test_runs_async_aask_text_synchronously(self):
        class Client:
            async def aask_text(self, *, system: str, user: str):
                assert system == "s"
                assert user == "u"
                return SimpleNamespace(text="ok")

        assert invoke_text_compat(Client(), system="s", user="u") == "ok"

    def test_falls_back_to_invoke_for_chat_models(self):
        response = SimpleNamespace(content="from-invoke")
        llm = MagicMock()
        llm.invoke.return_value = response

        text = invoke_text_compat(llm, system="sys", user="usr")

        assert text == "from-invoke"
        llm.invoke.assert_called_once()
        llm.chat.assert_not_called()

    @pytest.mark.asyncio
    async def test_running_loop_with_async_only_client_raises_cleanly(self):
        with pytest.raises(RuntimeError, match="event loop is running"):
            invoke_text_compat(_AsyncOnlyClient(), system="s", user="u")
