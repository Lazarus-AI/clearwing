"""Tests for the memory subsystem: SessionStore, EpisodicMemory, SemanticMemory, ContextSummarizer."""

import tempfile
from datetime import datetime
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock

import pytest

from clearwing.data.memory.episodic_memory import Episode, EpisodicMemory
from clearwing.data.memory.semantic_memory import Knowledge, SemanticMemory
from clearwing.data.memory.session_store import SessionInfo, SessionStore
from clearwing.data.memory.summarizer import ContextSummarizer
from clearwing.llm import AIMessage, HumanMessage

# =========================================================================
# SessionStore
# =========================================================================


class TestSessionInfo:
    def test_creation(self):
        s = SessionInfo(
            session_id="abc12345",
            target="10.0.0.1",
            model="claude-sonnet-4-6",
            status="running",
            start_time=datetime.now(),
            langgraph_thread_id="thread123",
        )
        assert s.session_id == "abc12345"
        assert s.flags_found == []
        assert s.cost_usd == 0.0


class TestSessionStore:
    def setup_method(self):
        self._tmpdir = tempfile.mkdtemp()
        self.store = SessionStore()
        self.store.BASE_DIR = Path(self._tmpdir)

    def test_create(self):
        session = self.store.create("10.0.0.1", "claude-sonnet-4-6")
        assert len(session.session_id) == 8
        assert session.target == "10.0.0.1"
        assert session.status == "running"
        assert session.langgraph_thread_id

    def test_save_and_load(self):
        session = self.store.create("10.0.0.1", "claude-sonnet-4-6")
        session.cost_usd = 0.05
        session.flags_found = [{"flag": "flag{test}", "context": "found it", "timestamp": "now"}]
        self.store.save(session)

        loaded = self.store.load(session.session_id)
        assert loaded.session_id == session.session_id
        assert loaded.cost_usd == 0.05
        assert len(loaded.flags_found) == 1
        assert loaded.flags_found[0]["flag"] == "flag{test}"

    def test_load_nonexistent_raises(self):
        with pytest.raises(FileNotFoundError):
            self.store.load("nonexistent")

    def test_list_sessions(self):
        self.store.create("10.0.0.1", "claude-sonnet-4-6")
        self.store.create("10.0.0.2", "claude-opus-4-6")
        sessions = self.store.list_sessions()
        assert len(sessions) == 2

    def test_list_sessions_filter_by_target(self):
        self.store.create("10.0.0.1", "claude-sonnet-4-6")
        self.store.create("10.0.0.2", "claude-opus-4-6")
        sessions = self.store.list_sessions(target="10.0.0.1")
        assert len(sessions) == 1
        assert sessions[0].target == "10.0.0.1"

    def test_get_latest(self):
        self.store.create("10.0.0.1", "claude-sonnet-4-6")
        s2 = self.store.create("10.0.0.1", "claude-sonnet-4-6")
        latest = self.store.get_latest()
        assert latest is not None
        # The latest should be s2 since it was created after s1
        assert latest.session_id == s2.session_id

    def test_get_latest_none(self):
        assert self.store.get_latest() is None

    def test_delete(self):
        session = self.store.create("10.0.0.1", "claude-sonnet-4-6")
        self.store.delete(session.session_id)
        with pytest.raises(FileNotFoundError):
            self.store.load(session.session_id)

    def test_delete_nonexistent_is_noop(self):
        self.store.delete("nonexistent")  # should not raise

    def test_datetime_serialization(self):
        session = self.store.create("10.0.0.1", "claude-sonnet-4-6")
        session.end_time = datetime(2025, 6, 15, 12, 30, 0)
        self.store.save(session)
        loaded = self.store.load(session.session_id)
        assert isinstance(loaded.start_time, datetime)
        assert isinstance(loaded.end_time, datetime)
        assert loaded.end_time.year == 2025


# =========================================================================
# EpisodicMemory
# =========================================================================


class TestEpisodicMemory:
    def setup_method(self):
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self._tmpdir) / "test_memory.db")
        self.mem = EpisodicMemory(db_path=self.db_path, session_id="test-session")

    def test_record_and_recall(self):
        self.mem.record("10.0.0.1", "port_found", "Port 22 open (SSH)")
        self.mem.record("10.0.0.1", "port_found", "Port 80 open (HTTP)")
        episodes = self.mem.recall("10.0.0.1")
        assert len(episodes) == 2
        assert all(isinstance(e, Episode) for e in episodes)

    def test_recall_empty(self):
        episodes = self.mem.recall("192.168.1.1")
        assert episodes == []

    def test_recall_limit(self):
        for i in range(10):
            self.mem.record("10.0.0.1", "port_found", f"Port {i}")
        episodes = self.mem.recall("10.0.0.1", limit=3)
        assert len(episodes) == 3

    def test_recall_by_type(self):
        self.mem.record("10.0.0.1", "port_found", "Port 22")
        self.mem.record("10.0.0.1", "vuln_found", "CVE-2021-44228")
        self.mem.record("10.0.0.1", "port_found", "Port 80")

        ports = self.mem.recall_by_type("10.0.0.1", "port_found")
        assert len(ports) == 2
        vulns = self.mem.recall_by_type("10.0.0.1", "vuln_found")
        assert len(vulns) == 1

    def test_search_fts(self):
        self.mem.record("10.0.0.1", "vuln_found", "SQL injection vulnerability in login form")
        self.mem.record("10.0.0.1", "port_found", "Port 3306 MySQL open")
        results = self.mem.search("10.0.0.1", "SQL injection")
        assert len(results) >= 1
        assert "SQL injection" in results[0].content

    def test_metadata_stored(self):
        self.mem.record(
            "10.0.0.1", "port_found", "Port 22", metadata={"protocol": "tcp", "service": "ssh"}
        )
        episodes = self.mem.recall("10.0.0.1")
        assert episodes[0].metadata["service"] == "ssh"

    def test_different_targets_isolated(self):
        self.mem.record("10.0.0.1", "port_found", "Port 22")
        self.mem.record("10.0.0.2", "port_found", "Port 80")
        assert len(self.mem.recall("10.0.0.1")) == 1
        assert len(self.mem.recall("10.0.0.2")) == 1

    def test_session_id_default(self):
        ep = self.mem.record("10.0.0.1", "note_added", "test note")
        assert ep.session_id == "test-session"

    def test_session_id_override(self):
        ep = self.mem.record("10.0.0.1", "note_added", "test", session_id="other")
        assert ep.session_id == "other"


# =========================================================================
# SemanticMemory
# =========================================================================


class TestSemanticMemory:
    def setup_method(self):
        self._tmpdir = tempfile.mkdtemp()
        self.db_path = str(Path(self._tmpdir) / "test_semantic.db")
        # Force FTS5 fallback by clearing the model cache
        SemanticMemory._model = None
        SemanticMemory._model_checked = False
        self.mem = SemanticMemory(db_path=self.db_path)

    def test_store_and_search(self):
        self.mem.store("successful_exploits", "Used SQL injection on port 3306 to dump database")
        self.mem.store("successful_exploits", "Exploited XSS to steal session cookies")
        results = self.mem.search("SQL injection")
        assert len(results) >= 1

    def test_store_returns_knowledge(self):
        k = self.mem.store("custom_techniques", "Custom technique for bypassing WAF")
        assert isinstance(k, Knowledge)
        assert k.category == "custom_techniques"
        assert k.id > 0

    def test_search_empty(self):
        results = self.mem.search("nonexistent query")
        assert results == []

    def test_search_with_category_filter(self):
        self.mem.store("successful_exploits", "SQL injection worked")
        self.mem.store("tool_usage_patterns", "Use sqlmap with --level=5")
        results = self.mem.search("SQL", category="tool_usage_patterns")
        for r in results:
            assert r.category == "tool_usage_patterns"

    def test_metadata_stored(self):
        self.mem.store("target_profiles", "Target runs Apache", metadata={"target": "10.0.0.1"})
        results = self.mem.search("Apache")
        assert len(results) >= 1
        assert results[0].metadata.get("target") == "10.0.0.1"

    def test_fts_fallback_works(self):
        """Verify FTS5 search works even without sentence-transformers."""
        SemanticMemory._model = None
        SemanticMemory._model_checked = True  # Skip model loading
        mem = SemanticMemory(db_path=self.db_path)
        mem.store("custom_techniques", "buffer overflow exploitation technique")
        results = mem._fts_search("buffer overflow", None, 5)
        assert len(results) >= 1


# =========================================================================
# ContextSummarizer
# =========================================================================


class TestContextSummarizer:
    def setup_method(self):
        self.summarizer = ContextSummarizer()

    def test_should_summarize_false_when_short(self):
        messages = [HumanMessage(content="hello")]
        assert self.summarizer.should_summarize(messages) is False

    def test_should_summarize_true_when_long(self):
        # 120000 tokens * 4 chars = 480000 chars needed to exceed 80% of 150000
        big_msg = HumanMessage(content="x" * 500000)
        assert self.summarizer.should_summarize([big_msg]) is True

    def test_should_summarize_custom_threshold(self):
        msg = HumanMessage(content="x" * 1000)
        # 1000 chars / 4 = 250 tokens. 80% of 200 = 160. 250 > 160 → True
        assert self.summarizer.should_summarize([msg], max_tokens=200) is True

    @pytest.mark.asyncio
    async def test_summarize_preserves_flags(self):
        messages = []
        for i in range(10):
            messages.append(HumanMessage(content=f"Message {i}"))
            messages.append(AIMessage(content=f"Response {i}"))

        # Add a flag-bearing message in the old section
        messages.insert(2, AIMessage(content="Found flag{test_flag_123}"))

        mock_llm = AsyncMock()
        mock_llm.ainvoke.return_value = MagicMock(content="Summary of findings")

        result = await self.summarizer.summarize(messages, mock_llm)

        # The flag message should be preserved
        flag_found = False
        for msg in result:
            content = msg.content if hasattr(msg, "content") else ""
            if "flag{test_flag_123}" in content:
                flag_found = True
                break
        assert flag_found, "Flag-bearing message was not preserved"

    @pytest.mark.asyncio
    async def test_summarize_keeps_recent_messages(self):
        messages = [HumanMessage(content=f"Msg {i}") for i in range(10)]

        mock_llm = AsyncMock()
        mock_llm.ainvoke.return_value = MagicMock(content="Summary")

        result = await self.summarizer.summarize(messages, mock_llm)

        # Recent 30% (3 messages) should be preserved as-is
        assert any("Msg 9" in m.content for m in result if hasattr(m, "content"))
        assert any("Msg 8" in m.content for m in result if hasattr(m, "content"))

    @pytest.mark.asyncio
    async def test_summarize_empty_returns_empty(self):
        mock_llm = AsyncMock()
        result = await self.summarizer.summarize([], mock_llm)
        assert result == []
