"""Preprocessing A/B evaluation runner (spec 018).

Runs the sourcehunt pipeline under different configurations for the same
(project, model, budget) triple and compares finding quality metrics.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from clearwing.core.event_payloads import EvalProgressPayload
from clearwing.core.events import EventBus

from .metrics import (
    ConfigResult,
    ConfigRunResult,
    EvalMetrics,
    EvalResult,
    aggregate_runs,
    compute_metrics,
    save_eval_result,
)

logger = logging.getLogger(__name__)


CONFIGURATIONS: dict[str, dict[str, Any]] = {
    "glasswing_minimal": {
        "prompt_mode": "unconstrained",
        "preprocessing": False,
        "seed_harness_crashes": False,
    },
    "sourcehunt_full": {
        "prompt_mode": "specialist",
        "preprocessing": True,
        "seed_harness_crashes": False,
    },
    "glasswing_plus_crashes": {
        "prompt_mode": "unconstrained",
        "preprocessing": False,
        "seed_harness_crashes": True,
    },
}


@dataclass
class EvalConfig:
    """Resolved configuration for a single eval arm."""

    name: str
    prompt_mode: str = "unconstrained"
    preprocessing: bool = False
    seed_harness_crashes: bool = False

    def to_runner_kwargs(self) -> dict[str, Any]:
        """Return kwargs to pass to SourceHuntRunner.__init__."""
        return {
            "prompt_mode": self.prompt_mode,
            "preprocessing": self.preprocessing,
            "seed_harness_crashes": self.seed_harness_crashes,
        }


def resolve_config(name: str) -> EvalConfig:
    """Resolve a config name to an EvalConfig."""
    if name not in CONFIGURATIONS:
        raise ValueError(
            f"Unknown eval config: {name!r}. "
            f"Available: {', '.join(sorted(CONFIGURATIONS))}"
        )
    cfg = CONFIGURATIONS[name]
    return EvalConfig(
        name=name,
        prompt_mode=cfg.get("prompt_mode", "unconstrained"),
        preprocessing=cfg.get("preprocessing", False),
        seed_harness_crashes=cfg.get("seed_harness_crashes", False),
    )


class PreprocessingEval:
    """A/B test runner for preprocessing pipeline evaluation."""

    def __init__(
        self,
        provider_manager: Any,
        project: str,
        commit: str = "",
        configs: list[str] | None = None,
        model_name: str = "",
        budget_per_config: float = 500.0,
        runs: int = 1,
        depth: str = "standard",
        output_dir: str | None = None,
        ground_truth_cves: list[str] | None = None,
    ):
        self._provider_manager = provider_manager
        self._project = project
        self._commit = commit
        self._configs = configs or ["glasswing_minimal", "sourcehunt_full"]
        self._model_name = model_name
        self._budget_per_config = budget_per_config
        self._runs = runs
        self._depth = depth
        if output_dir is None:
            from clearwing.core.config import default_results_dir

            output_dir = default_results_dir("eval")
        self._output_dir = output_dir
        self._ground_truth_cves = ground_truth_cves or []

    async def arun(self) -> EvalResult:
        """Run evaluation across all configs."""
        start_time = time.monotonic()

        result = EvalResult(
            project=self._project,
            commit=self._commit,
            model=self._model_name,
            budget_per_config=self._budget_per_config,
            num_runs=self._runs,
            timestamp=datetime.now(timezone.utc).isoformat(),
            ground_truth_cves=self._ground_truth_cves,
            metadata={
                "depth": self._depth,
                "configs": self._configs,
            },
        )

        out_dir = Path(self._output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        local_path = self._prepare_repo()

        bus = EventBus()
        for config_idx, config_name in enumerate(self._configs):
            eval_config = resolve_config(config_name)
            config_result = ConfigResult(config_name=config_name)

            config_dir = out_dir / config_name
            config_dir.mkdir(parents=True, exist_ok=True)

            for run_idx in range(self._runs):
                run_file = config_dir / f"run_{run_idx}.json"

                if run_file.exists():
                    try:
                        run_data = json.loads(
                            run_file.read_text(encoding="utf-8"),
                        )
                        metrics = EvalMetrics(**{
                            k: v
                            for k, v in run_data.get("metrics", {}).items()
                            if k in EvalMetrics.__dataclass_fields__
                        })
                        config_result.runs.append(ConfigRunResult(
                            run_index=run_idx,
                            metrics=metrics,
                            error=run_data.get("error"),
                        ))
                        logger.info(
                            "Loaded cached run %d for %s",
                            run_idx, config_name,
                        )
                        bus.emit_eval_progress(EvalProgressPayload(
                            project=self._project, config_name=config_name,
                            run_index=run_idx, runs_total=self._runs,
                            configs_completed=config_idx, configs_total=len(self._configs),
                            status="cached", cost_usd=0.0,
                        ))
                        continue
                    except Exception:
                        pass

                bus.emit_eval_progress(EvalProgressPayload(
                    project=self._project, config_name=config_name,
                    run_index=run_idx, runs_total=self._runs,
                    configs_completed=config_idx, configs_total=len(self._configs),
                    status="running", cost_usd=0.0,
                ))
                run_result = await self._single_run(
                    eval_config, local_path, run_idx, config_dir,
                )
                config_result.runs.append(run_result)
                bus.emit_eval_progress(EvalProgressPayload(
                    project=self._project, config_name=config_name,
                    run_index=run_idx, runs_total=self._runs,
                    configs_completed=config_idx, configs_total=len(self._configs),
                    status="error" if run_result.error else "completed",
                    cost_usd=run_result.metrics.cost_usd if run_result.metrics and not run_result.error else 0.0,
                ))

                try:
                    from dataclasses import asdict
                    run_file.write_text(
                        json.dumps(asdict(run_result), indent=2, default=str),
                        encoding="utf-8",
                    )
                except Exception:
                    pass

            run_metrics = [
                r.metrics for r in config_result.runs if r.error is None
            ]
            if run_metrics:
                config_result.mean_metrics, config_result.stddev = (
                    aggregate_runs(run_metrics)
                )

            result.configs.append(config_result)

        result_path = out_dir / f"eval_{self._model_name}.json"
        save_eval_result(result, str(result_path))

        return result

    async def _single_run(
        self,
        eval_config: EvalConfig,
        local_path: str | None,
        run_idx: int,
        config_dir: Path,
    ) -> ConfigRunResult:
        """Execute a single eval run under a config."""
        from clearwing.sourcehunt.runner import SourceHuntRunner

        runner_kwargs = eval_config.to_runner_kwargs()
        run_output_dir = config_dir / f"sourcehunt_run_{run_idx}"
        run_output_dir.mkdir(parents=True, exist_ok=True)
        session_seed = "|".join(
            [
                str(self._project or ""),
                str(self._commit or ""),
                str(eval_config.name or ""),
                str(run_idx),
                str(self._depth or ""),
                str(self._budget_per_config),
                str(self._model_name or ""),
            ]
        )
        session_hash = hashlib.sha256(session_seed.encode("utf-8")).hexdigest()[:12]
        stable_session_id = (
            f"sh-eval-{eval_config.name}-{run_idx}-{session_hash}".replace("_", "-")
        )

        try:
            runner = SourceHuntRunner(
                repo_url=self._project,
                local_path=local_path,
                depth=self._depth,
                budget_usd=self._budget_per_config,
                depth_is_explicit=True,
                budget_is_explicit=True,
                provider_manager=self._provider_manager,
                no_exploit=True,
                enable_variant_loop=False,
                enable_mechanism_memory=False,
                enable_auto_patch=False,
                export_disclosures=False,
                enable_elaboration=False,
                enable_behavior_monitor=False,
                enable_artifact_store=False,
                output_dir=str(run_output_dir),
                parent_session_id=stable_session_id,
                checkpoint_root=str(run_output_dir / "checkpoints"),
                **runner_kwargs,
            )

            hunt_result = await runner.arun()
            metrics = compute_metrics(hunt_result)

            return ConfigRunResult(
                run_index=run_idx,
                metrics=metrics,
            )
        except Exception as e:
            logger.warning(
                "Eval run %d for %s failed: %s",
                run_idx, eval_config.name, e,
            )
            return ConfigRunResult(
                run_index=run_idx,
                error=str(e),
            )

    def _prepare_repo(self) -> str | None:
        """Prepare repo at the specified commit, return local_path or None."""
        if not self._commit:
            if os.path.isdir(self._project):
                return self._project
            return None

        if os.path.isdir(self._project):
            try:
                subprocess.run(
                    ["git", "checkout", self._commit],
                    cwd=self._project,
                    capture_output=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                logger.warning(
                    "Failed to checkout %s in %s",
                    self._commit, self._project,
                )
            return self._project

        return None
