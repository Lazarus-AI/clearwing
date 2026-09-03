"""H2 bake-off harness: sampling on the wire + hunter-only scoring."""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import patch

from genai_pyo3 import ChatMessage, ChatOptions, ChatRequest

from clearwing.llm.native import AsyncLLMClient
from clearwing.sourcehunt.hunter import (
    SUBSYSTEM_HUNT_PROMPT_LEGACY,
    SUBSYSTEM_HUNT_PROMPT_TRUTHFUL,
    _build_subsystem_prompt,
    _subsystem_initial_user_message,
)
from clearwing.sourcehunt.state import SubsystemTarget
from clearwing.sourcehunt.subsystem import (
    files_for_prompt_listing,
    subsystem_from_path,
)

EVALS = Path(__file__).resolve().parents[1] / "evaluations"
if str(EVALS) not in sys.path:
    sys.path.insert(0, str(EVALS))

from qwen_ab_scoring import (  # noqa: E402
    COMMUNITY_TEMPERATURE,
    COMMUNITY_TOP_K,
    COMMUNITY_TOP_P,
    community_sampling_env,
    count_findings,
    is_hunter_finding,
)


class HunterOnlyScoringTests(unittest.TestCase):
    def test_static_dumps_are_not_hunter_hits(self) -> None:
        static = {"discovered_by": "source_analyzer", "description": "regex"}
        hunter = {"discovered_by": "hunter", "description": "dual"}
        self.assertFalse(is_hunter_finding(static))
        self.assertTrue(is_hunter_finding(hunter))
        scored = count_findings([static] * 185 + [hunter])
        self.assertEqual(scored["n_findings"], 186)
        self.assertEqual(scored["n_hunter_findings"], 1)
        self.assertEqual(scored["n_static_findings"], 185)

    def test_community_sampling_env(self) -> None:
        env = community_sampling_env()
        self.assertEqual(env["CLEARWING_TEMPERATURE"], "1.0")
        self.assertEqual(env["CLEARWING_TOP_P"], "0.95")
        self.assertEqual(env["CLEARWING_TOP_K"], "20")
        self.assertEqual(COMMUNITY_TEMPERATURE, 1.0)
        self.assertEqual(COMMUNITY_TOP_P, 0.95)
        self.assertEqual(COMMUNITY_TOP_K, 20)


class WireSamplingTests(unittest.TestCase):
    def _client(self, **env: str) -> AsyncLLMClient:
        with patch.dict("os.environ", env, clear=False):
            return AsyncLLMClient(
                model_name="Qwen3.8-27B-NVFP4",
                provider_name="openai_compat",
                api_key="sk-test",
                base_url="http://example.test/v1",
                reasoning_effort="medium",
            )

    def test_unset_sampling_is_noop(self) -> None:
        with patch.dict(
            "os.environ",
            {"CLEARWING_TEMPERATURE": "", "CLEARWING_TOP_P": "", "CLEARWING_TOP_K": ""},
            clear=False,
        ):
            client = AsyncLLMClient(
                model_name="Qwen3.8-27B-NVFP4",
                provider_name="openai_compat",
                api_key="sk-test",
                reasoning_effort="medium",
            )
        temperature, top_p, extra = client._wire_sampling(None)
        self.assertIsNone(temperature)
        self.assertIsNone(top_p)
        self.assertIsNone(extra)

    def test_community_pins_land_on_openai_fallback_body(self) -> None:
        env = community_sampling_env()
        client = self._client(**env)
        temperature, top_p, extra = client._wire_sampling(None)
        self.assertEqual(temperature, 1.0)
        self.assertEqual(top_p, 0.95)
        self.assertEqual(extra, {"top_k": 20})
        request = ChatRequest(messages=[ChatMessage("user", "hi")])
        options = ChatOptions(
            temperature=temperature,
            top_p=top_p,
            extra_body=extra,
            reasoning_effort="medium",
        )
        body = client._openai_chat_request_body(request, options, stream=False)
        self.assertEqual(body["temperature"], 1.0)
        self.assertEqual(body["top_p"], 0.95)
        self.assertEqual(body["top_k"], 20)
        self.assertEqual(body["reasoning_effort"], "medium")


def _ft(path: str, priority: float = 2.0) -> dict:
    return {
        "path": path,
        "language": "c",
        "loc": 50,
        "tags": [],
        "priority": priority,
        "surface": 3,
        "influence": 2,
        "reachability": 3,
    }


class SubsystemPinTests(unittest.TestCase):
    def test_no_rank_keeps_exact_file_pin(self) -> None:
        decoys = [_ft(f"src/decoy_{i}.c", 3.4) for i in range(60)]
        result = subsystem_from_path(
            "src/access.rs",
            decoys + [_ft("src/access.rs", 2.8)],
            max_files=50,
            no_rank=True,
        )
        paths = [ft["path"] for ft in result.files]
        self.assertIn("src/access.rs", paths)
        self.assertEqual(paths[0], "src/access.rs")

    def test_prompt_listing_puts_pin_first(self) -> None:
        files = [_ft(f"pkg/n{i}.c", 3.4) for i in range(80)]
        pin = _ft("pkg/target.c", 2.8)
        subsystem = SubsystemTarget(
            name="pkg_target_c",
            root_path="pkg/target.c",
            files=files + [pin],
        )
        listing = files_for_prompt_listing(subsystem, limit=50)
        self.assertEqual(listing[0]["path"], "pkg/target.c")
        prompt = _build_subsystem_prompt(subsystem, "demo")
        self.assertIn("pkg/target.c", prompt)
        self.assertNotIn("Per-file hunters already found", prompt)

    def test_disk_fallback_loads_missed_pin(self) -> None:
        import tempfile

        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw) / "repo"
            pin_dir = root / "filter" / "source" / "graphicfilter" / "idxf"
            pin_dir.mkdir(parents=True)
            (pin_dir / "dxf2gdi.cxx").write_text("int w = width * height;\n")
            result = subsystem_from_path(
                "filter/source/graphicfilter/idxf",
                [],
                repo_path=str(root),
                no_rank=True,
            )
            self.assertTrue(result.files)
            self.assertTrue(any(ft["path"].endswith("dxf2gdi.cxx") for ft in result.files))

    def test_source_analyzer_rows_stay_out_of_prompt(self) -> None:
        from clearwing.findings.types import Finding
        from clearwing.sourcehunt.findings_pool import FindingsPool

        pool = FindingsPool()
        pool._findings["static"] = Finding(
            id="static",
            file="pkg/target.c",
            line_number=1,
            cwe="CWE-89",
            severity="high",
            description="regex dump that is not a hunter hit",
            primitive_type="sql_injection",
            cluster_id="c-static",
            discovered_by="source_analyzer",
        )
        subsystem = SubsystemTarget(
            name="pkg",
            root_path="pkg",
            files=[_ft("pkg/target.c", 4.0)],
        )
        prompt = _build_subsystem_prompt(subsystem, "demo", findings_pool=pool)
        self.assertNotIn("regex dump that is not a hunter hit", prompt)
        self.assertNotIn("Per-file hunters already found", prompt)
        self.assertNotIn("Prior hunter findings", prompt)


_CROSS_FILE_MISSION = (
    "Your mission is to find vulnerabilities that EMERGE FROM CROSS-FILE INTERACTIONS:"
)
_LEGACY_BULLETS = (
    "- Shared state (globals, structs, locks) modified by one file but consumed by another\n"
    "- Protocol/API contracts violated across call boundaries\n"
    "- State machine transitions that can be corrupted by concurrent callers\n"
    "- Lifetime/ownership confusion when objects cross module boundaries\n"
    "- Inconsistent validation: File A validates, File B doesn't, both call File C"
)
_LIE = "Single-file bugs have already been hunted."
_DUAL_LEAD = "Also in-policy (do not replace the cross-file mission):"


class UnionPromptTests(unittest.TestCase):
    def test_legacy_bullets_are_verbatim_in_truthful_and_come_first(self) -> None:
        self.assertIn(_CROSS_FILE_MISSION, SUBSYSTEM_HUNT_PROMPT_LEGACY)
        self.assertIn(_LEGACY_BULLETS, SUBSYSTEM_HUNT_PROMPT_LEGACY)
        self.assertIn(_LIE, SUBSYSTEM_HUNT_PROMPT_LEGACY)

        truthful = SUBSYSTEM_HUNT_PROMPT_TRUTHFUL
        self.assertIn(_CROSS_FILE_MISSION, truthful)
        self.assertIn(_LEGACY_BULLETS, truthful)
        self.assertNotIn(_LIE, truthful)
        self.assertIn("Per-file hunt was skipped", truthful)
        self.assertIn(_DUAL_LEAD, truthful)
        self.assertLess(
            truthful.index(_LEGACY_BULLETS),
            truthful.index(_DUAL_LEAD),
        )
        self.assertLess(
            truthful.index(_DUAL_LEAD),
            truthful.index("Integer overflow or wrap"),
        )
        self.assertNotIn(
            "PDU length vs struct written",
            truthful.split(_DUAL_LEAD)[0],
        )

    def test_built_truthful_prompt_keeps_mission_order(self) -> None:
        subsystem = SubsystemTarget(
            name="pkg",
            root_path="pkg",
            files=[_ft("pkg/target.c", 4.0)],
        )
        with patch.dict(
            "os.environ",
            {"CLEARWING_SUBSYSTEM_PROMPT_MODE": "truthful"},
            clear=False,
        ):
            prompt = _build_subsystem_prompt(subsystem, "demo")
            user = _subsystem_initial_user_message(subsystem)
        self.assertIn(_CROSS_FILE_MISSION, prompt)
        self.assertIn(_LEGACY_BULLETS, prompt)
        self.assertNotIn(_LIE, prompt)
        self.assertLess(prompt.index(_LEGACY_BULLETS), prompt.index(_DUAL_LEAD))
        self.assertTrue(user.startswith("Hunt cross-file contract bugs first"))
        self.assertIn("do not drop the cross-file mission", user)

    def test_built_legacy_prompt_still_closed_world(self) -> None:
        subsystem = SubsystemTarget(
            name="pkg",
            root_path="pkg",
            files=[_ft("pkg/target.c", 4.0)],
        )
        with patch.dict(
            "os.environ",
            {"CLEARWING_SUBSYSTEM_PROMPT_MODE": "legacy"},
            clear=False,
        ):
            prompt = _build_subsystem_prompt(subsystem, "demo")
            user = _subsystem_initial_user_message(subsystem)
        self.assertIn(_LIE, prompt)
        self.assertNotIn(_DUAL_LEAD, prompt)
        self.assertTrue(user.startswith("Hunt for cross-file vulnerabilities"))


if __name__ == "__main__":
    unittest.main()
