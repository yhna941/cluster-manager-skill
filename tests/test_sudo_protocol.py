import asyncio
import json
from types import SimpleNamespace

import pytest

from cluster_manager.managed import engine, worker


class Reader:
    def __init__(self):
        self.queue = asyncio.Queue()
        self.buffer = ""
        self.eof = False

    def feed(self, value):
        self.queue.put_nowait(value)

    async def read(self, size):
        if not self.buffer and not self.eof:
            self.buffer = await self.queue.get()
            if not self.buffer:
                self.eof = True
        result, self.buffer = self.buffer[:size], self.buffer[size:]
        return result


class Process:
    def __init__(self, prompt):
        self.stdout = Reader()
        self.stderr = Reader()
        self.stdin = self
        self.exit_status = 0
        self.prompt = prompt
        self.writes = []
        self.request = None

    async def __aenter__(self):
        if self.prompt:
            self.stderr.feed("CM_SUDO_PASSWORD_V2:")
        else:
            self.stdout.feed("CM_WORKER_READY_V2\n")
        return self

    async def __aexit__(self, *args):
        pass

    def write(self, value):
        self.writes.append(value)
        if self.prompt and len(self.writes) == 1:
            assert value == "sudo-test-value\n"
            self.stdout.feed("CM_WORKER_READY_V2\n")
        else:
            self.request = json.loads(value)
            self.stdout.feed('{"status":"verified"}')
            self.stdout.feed("")
            self.stderr.feed("")

    def write_eof(self):
        pass

    async def wait_closed(self):
        pass


@pytest.mark.parametrize("prompt", [True, False])
def test_sudo_password_and_worker_secrets_use_distinct_protocol_stages(monkeypatch, prompt):
    async def scenario():
        process = Process(prompt)
        commands = []

        def create(command, **kwargs):
            commands.append(command)
            return process

        conn = SimpleNamespace(create_process=create)
        result = await engine.invoke(
            conn, {"phase": "execute", "secrets": {"linux": "account-test-value"}}
        )
        assert result["status"] == "verified"
        assert process.request["secrets"]["linux"] == "account-test-value"
        assert "sudo-test-value" not in json.dumps(process.request)
        assert all("account-test-value" not in c and "sudo-test-value" not in c for c in commands)
        assert len(process.writes) == (2 if prompt else 1)

    monkeypatch.setattr(engine.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(engine.getpass, "getpass", lambda prompt: "sudo-test-value")
    asyncio.run(scenario())


def test_sudo_prompt_without_terminal_is_rejected(monkeypatch):
    async def scenario():
        process = Process(True)
        conn = SimpleNamespace(create_process=lambda *args, **kwargs: process)
        with pytest.raises(worker.Refusal, match="local authentication"):
            await engine.invoke(conn, {"phase": "discover"})
        assert process.writes == []

    monkeypatch.setattr(engine.sys.stdin, "isatty", lambda: False)
    asyncio.run(scenario())
