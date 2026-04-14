"""Build system detection for source-hunt sandbox image generation.

Inspects a cloned repo and detects make/cmake/cargo/go/maven/npm/python.
Returns a BuildRecipe that the HunterSandbox uses to write a Dockerfile that
compiles the project with the requested sanitizers.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class BuildRecipe:
    """Per-language build recipe for the hunter sandbox image."""

    system: str  # "make" | "cmake" | "cargo" | "go" | "maven" | "npm" | "python" | "unknown"
    primary_language: str  # "c" | "cpp" | "rust" | "go" | "java" | "node" | "python" | "unknown"
    base_image: str  # docker base image
    apt_packages: list[str] = field(default_factory=list)
    build_cmd: str = ""  # shell command to build the project
    test_cmd: str = ""  # shell command to run tests
    sanitizer_flags: dict[str, str] = field(default_factory=dict)
    # {"asan": "-fsanitize=address", ...}
    env: dict[str, str] = field(default_factory=dict)

    def env_for_sanitizers(self, sanitizers: list[str]) -> dict[str, str]:
        """Compute the env dict for a specific sanitizer variant.

        The recipe's default `env` reflects the ASan+UBSan combo. This
        method recomputes CFLAGS/CXXFLAGS/LDFLAGS for any subset, so the
        HunterSandbox can build an MSan variant image with the right flags.

        MSan cannot coexist with ASan in the same binary — the caller is
        responsible for not passing both (HunterSandbox validates this).
        """
        return compute_sanitizer_env(self, sanitizers)


# Per-language base images. gcc:13 ships libasan/libubsan; rust uses the
# nightly image for sanitizer support; python doesn't need a build but does
# benefit from gcc for native extensions.
DEFAULT_BASE_IMAGES = {
    "c": "gcc:13",
    "cpp": "gcc:13",
    "rust": "rust:1-slim",
    "go": "golang:1.22",
    "python": "python:3.12-slim",
    "java": "eclipse-temurin:21",
    "node": "node:20-slim",
    "unknown": "debian:12-slim",
}


# Per-sanitizer compile flags. MSan's flag set is intentionally different
# from ASan/UBSan because MSan requires track-origins for useful reports
# and cannot coexist with ASan in the same binary.
_SANITIZER_COMPILE_FLAGS: dict[str, list[str]] = {
    "asan": ["-fsanitize=address"],
    "ubsan": ["-fsanitize=undefined"],
    "msan": ["-fsanitize=memory", "-fsanitize-memory-track-origins=2", "-fno-omit-frame-pointer"],
    "tsan": ["-fsanitize=thread"],
    "lsan": ["-fsanitize=leak"],
}

# Per-sanitizer runtime env tuning. These go into ASAN_OPTIONS, MSAN_OPTIONS,
# etc. so the container inherits sane defaults.
_SANITIZER_RUNTIME_ENV: dict[str, dict[str, str]] = {
    "asan": {
        "ASAN_OPTIONS": "abort_on_error=0:halt_on_error=0:detect_leaks=0:"
        "allocator_may_return_null=1"
    },
    "ubsan": {"UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=0"},
    "msan": {
        "MSAN_OPTIONS": "abort_on_error=0:halt_on_error=0:print_stats=0:"
        "exit_code=77:origin_history_size=16"
    },
    "tsan": {"TSAN_OPTIONS": "halt_on_error=0:second_deadlock_stack=1"},
    "lsan": {"LSAN_OPTIONS": "exitcode=23"},
}


# Mutually-exclusive sanitizer combinations. Passing any of these pairs
# to HunterSandbox raises ValueError — the instrumentation libraries
# cannot coexist in the same binary.
INCOMPATIBLE_SANITIZER_PAIRS: tuple[tuple[str, str], ...] = (
    ("asan", "msan"),
    ("asan", "tsan"),
    ("msan", "tsan"),
    ("msan", "lsan"),
)


def validate_sanitizer_combo(sanitizers: list[str]) -> None:
    """Raise ValueError if the sanitizer list contains incompatible members."""
    s = set(sanitizers)
    for a, b in INCOMPATIBLE_SANITIZER_PAIRS:
        if a in s and b in s:
            raise ValueError(
                f"sanitizers {a!r} and {b!r} cannot coexist in the same binary; "
                f"build them as separate variants via HunterSandbox.extra_variants"
            )


def compute_sanitizer_env(recipe: BuildRecipe, sanitizers: list[str]) -> dict[str, str]:
    """Return the env dict for a given sanitizer variant.

    Starts from the recipe's defaults and overrides CFLAGS / CXXFLAGS /
    LDFLAGS to reflect the requested sanitizer combo. Runtime options
    (ASAN_OPTIONS, MSAN_OPTIONS, etc.) are merged in for each sanitizer.
    """
    validate_sanitizer_combo(sanitizers)
    env: dict[str, str] = {}

    # Languages that don't use CFLAGS (python, node, java, rust, go) get
    # the recipe's env unchanged — sanitizers are a C/C++ concept here.
    lang = recipe.primary_language
    if lang not in ("c", "cpp"):
        return dict(recipe.env)

    flags: list[str] = []
    for san in sanitizers:
        flag_list = _SANITIZER_COMPILE_FLAGS.get(san)
        if flag_list is None:
            logger.debug("Unknown sanitizer %r — skipping", san)
            continue
        flags.extend(flag_list)

    # Debug + O1 + frame pointers give usable stack traces under instrumentation
    base_flags = "-g -O1 -fno-omit-frame-pointer"
    san_flags = " ".join(flags)

    env["CFLAGS"] = f"{san_flags} {base_flags}".strip()
    env["CXXFLAGS"] = env["CFLAGS"]
    env["LDFLAGS"] = san_flags

    # Merge runtime options for every sanitizer in the combo
    for san in sanitizers:
        env.update(_SANITIZER_RUNTIME_ENV.get(san, {}))

    return env


# Tools we want available in every hunter sandbox image: ripgrep for grep_source,
# gdb/strace for debugging, coreutils' `timeout` for exec timeouts.
COMMON_APT_PACKAGES = [
    "ripgrep",
    "gdb",
    "strace",
    "ltrace",
    "coreutils",
    "ca-certificates",
    "build-essential",
]


class BuildSystemDetector:
    """Detect the build system of a cloned repo and emit a BuildRecipe.

    Heuristics, in priority order:
        1. CMakeLists.txt → cmake
        2. Cargo.toml → cargo
        3. go.mod → go
        4. pom.xml → maven
        5. package.json → npm
        6. setup.py / pyproject.toml → python
        7. Makefile (last) → make

    Languages are inferred from the build system; if a project has both Cargo
    and Make, we trust Cargo because it's more specific.
    """

    @classmethod
    def detect(cls, repo_path: str) -> BuildRecipe:
        root = Path(repo_path)
        if not root.exists():
            return cls._unknown()

        # Check in priority order
        if (root / "CMakeLists.txt").exists():
            return cls._cmake_recipe()
        if (root / "Cargo.toml").exists():
            return cls._cargo_recipe()
        if (root / "go.mod").exists():
            return cls._go_recipe()
        if (root / "pom.xml").exists():
            return cls._maven_recipe()
        if (root / "package.json").exists():
            return cls._npm_recipe()
        if (root / "pyproject.toml").exists() or (root / "setup.py").exists():
            return cls._python_recipe()
        if (root / "Makefile").exists() or (root / "makefile").exists():
            return cls._make_recipe()

        # No recognised build system — pick a language guess based on file mix
        return cls._language_guess(root)

    # --- Recipes ------------------------------------------------------------

    @staticmethod
    def _make_recipe() -> BuildRecipe:
        return BuildRecipe(
            system="make",
            primary_language="c",
            base_image=DEFAULT_BASE_IMAGES["c"],
            apt_packages=COMMON_APT_PACKAGES,
            build_cmd="make",
            test_cmd="make test || true",
            sanitizer_flags={
                "asan": "-fsanitize=address",
                "ubsan": "-fsanitize=undefined",
                "msan": "-fsanitize=memory",
            },
            env={
                "CFLAGS": "-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer",
                "CXXFLAGS": "-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer",
                "LDFLAGS": "-fsanitize=address,undefined",
                "ASAN_OPTIONS": "abort_on_error=0:halt_on_error=0:detect_leaks=0",
                "UBSAN_OPTIONS": "print_stacktrace=1:halt_on_error=0",
            },
        )

    @staticmethod
    def _cmake_recipe() -> BuildRecipe:
        return BuildRecipe(
            system="cmake",
            primary_language="cpp",
            base_image=DEFAULT_BASE_IMAGES["cpp"],
            apt_packages=COMMON_APT_PACKAGES + ["cmake"],
            build_cmd="mkdir -p build && cd build && cmake -DCMAKE_BUILD_TYPE=Debug .. && make",
            test_cmd="cd build && ctest --output-on-failure || true",
            sanitizer_flags={
                "asan": "-fsanitize=address",
                "ubsan": "-fsanitize=undefined",
                "msan": "-fsanitize=memory",
            },
            env={
                "CFLAGS": "-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer",
                "CXXFLAGS": "-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer",
                "LDFLAGS": "-fsanitize=address,undefined",
                "ASAN_OPTIONS": "abort_on_error=0:halt_on_error=0:detect_leaks=0",
            },
        )

    @staticmethod
    def _cargo_recipe() -> BuildRecipe:
        return BuildRecipe(
            system="cargo",
            primary_language="rust",
            base_image=DEFAULT_BASE_IMAGES["rust"],
            apt_packages=COMMON_APT_PACKAGES,
            build_cmd="cargo build",
            test_cmd="cargo test || true",
            sanitizer_flags={
                # Rust sanitizers require nightly; v0.1 doesn't enable by default
                "asan": "-Z sanitizer=address",
            },
            env={
                "RUSTFLAGS": "-g",
                "CARGO_TERM_COLOR": "never",
            },
        )

    @staticmethod
    def _go_recipe() -> BuildRecipe:
        return BuildRecipe(
            system="go",
            primary_language="go",
            base_image=DEFAULT_BASE_IMAGES["go"],
            apt_packages=COMMON_APT_PACKAGES,
            build_cmd="go build ./...",
            test_cmd="go test -race ./... || true",
            sanitizer_flags={"race": "-race"},
            env={"GOFLAGS": "-mod=mod"},
        )

    @staticmethod
    def _maven_recipe() -> BuildRecipe:
        return BuildRecipe(
            system="maven",
            primary_language="java",
            base_image=DEFAULT_BASE_IMAGES["java"],
            apt_packages=["maven", "ripgrep", "ca-certificates"],
            build_cmd="mvn -B -DskipTests package",
            test_cmd="mvn -B test || true",
        )

    @staticmethod
    def _npm_recipe() -> BuildRecipe:
        return BuildRecipe(
            system="npm",
            primary_language="node",
            base_image=DEFAULT_BASE_IMAGES["node"],
            apt_packages=["ripgrep", "ca-certificates"],
            build_cmd="npm install --no-audit --no-fund || true",
            test_cmd="npm test || true",
        )

    @staticmethod
    def _python_recipe() -> BuildRecipe:
        return BuildRecipe(
            system="python",
            primary_language="python",
            base_image=DEFAULT_BASE_IMAGES["python"],
            apt_packages=["ripgrep", "gcc", "g++", "ca-certificates"],
            build_cmd="pip install --quiet -e . || pip install --quiet . || true",
            test_cmd="pytest -q || true",
        )

    @classmethod
    def _language_guess(cls, root: Path) -> BuildRecipe:
        """Fallback when no build system file is found: count source extensions."""
        counts: dict[str, int] = {}
        for _dirpath, dirnames, filenames in os.walk(root):
            # Skip vendor/build/cache dirs
            dirnames[:] = [
                d
                for d in dirnames
                if d
                not in {
                    ".git",
                    "node_modules",
                    "vendor",
                    "dist",
                    "build",
                    "__pycache__",
                    ".venv",
                    "venv",
                    "target",
                }
            ]
            for fname in filenames:
                ext = Path(fname).suffix.lower()
                if ext:
                    counts[ext] = counts.get(ext, 0) + 1
        if not counts:
            return cls._unknown()

        ext_to_lang = {
            ".py": "python",
            ".c": "c",
            ".h": "c",
            ".cpp": "cpp",
            ".cc": "cpp",
            ".hpp": "cpp",
            ".rs": "rust",
            ".go": "go",
            ".java": "java",
            ".js": "node",
            ".ts": "node",
            ".jsx": "node",
            ".tsx": "node",
        }
        lang_counts: dict[str, int] = {}
        for ext, count in counts.items():
            lang = ext_to_lang.get(ext)
            if lang:
                lang_counts[lang] = lang_counts.get(lang, 0) + count
        if not lang_counts:
            return cls._unknown()
        primary = max(lang_counts.items(), key=lambda kv: kv[1])[0]

        if primary == "python":
            return cls._python_recipe()
        if primary == "c" or primary == "cpp":
            return cls._make_recipe()
        if primary == "rust":
            return cls._cargo_recipe()
        if primary == "go":
            return cls._go_recipe()
        if primary == "java":
            return cls._maven_recipe()
        if primary == "node":
            return cls._npm_recipe()
        return cls._unknown()

    @staticmethod
    def _unknown() -> BuildRecipe:
        return BuildRecipe(
            system="unknown",
            primary_language="unknown",
            base_image=DEFAULT_BASE_IMAGES["unknown"],
            apt_packages=["ripgrep", "ca-certificates"],
        )
