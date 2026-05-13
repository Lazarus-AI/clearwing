"""Interactive provider-configuration wizard.

`clearwing setup` walks a first-time user through picking an LLM
backend, entering credentials, and persisting the result to
`~/.clearwing/config.yaml`. Every step validates before moving on
(API key shape, base_url reachability, optional test invoke) so a
misconfigured file doesn't silently make the rest of Clearwing
unusable.

The wizard is a thin shell over the primitives the `config
--set-provider` subcommand already ships; its value is the
decision tree, not new file handling.
"""

from __future__ import annotations

import os
import time
from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

from clearwing import __version__

if TYPE_CHECKING:
    from clearwing.providers import ProviderPreset


#: Subcommand aliases recognized by the CLI dispatcher.
ALIASES: tuple[str, ...] = ("init",)


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "setup",
        aliases=["init"],
        help="Interactive wizard to configure your LLM provider",
        description=(
            "Walk through provider selection, credential entry, optional "
            "connection testing, and persistence to ~/.clearwing/config.yaml. "
            "Safe to re-run — existing config is shown and can be overwritten."
        ),
    )
    parser.add_argument(
        "--provider",
        metavar="KEY",
        help=(
            "Skip the menu and configure this provider directly "
            "(e.g. openrouter, ollama, lmstudio, anthropic, openai, "
            "openai-oauth, together, groq, deepseek, fireworks, custom)"
        ),
    )
    parser.add_argument(
        "--no-open",
        action="store_true",
        help="For OAuth providers, don't open the browser automatically",
    )
    parser.add_argument(
        "--timeout-seconds",
        type=int,
        default=60,
        help="For OAuth providers, local callback wait timeout",
    )
    parser.add_argument(
        "--no-test",
        action="store_true",
        help="Don't test the endpoint after writing config (default: test)",
    )
    parser.add_argument(
        "--yes",
        "-y",
        action="store_true",
        help="Assume 'yes' on overwrite confirmations (non-interactive mode)",
    )
    return parser


def handle(cli, args) -> None:
    """Run the setup wizard."""
    from clearwing.providers import KNOWN_PROVIDERS, preset_by_key

    console: Console = cli.console

    _print_welcome(console, cli)

    # Direct mode — user knows exactly which provider they want
    if args.provider:
        preset = preset_by_key(args.provider)
        if preset is None:
            console.print(
                f"[red]Error: unknown provider '{args.provider}'. "
                f"Known keys: {', '.join(p.key for p in KNOWN_PROVIDERS)}[/red]"
            )
            return
    else:
        preset = _prompt_provider_choice(console, KNOWN_PROVIDERS)
        if preset is None:
            console.print("[yellow]Setup cancelled.[/yellow]")
            return

    console.print(f"\n[bold cyan]Configuring {preset.display_name}[/bold cyan]")
    console.print(f"[dim]Docs: {preset.docs_url}[/dim]\n")

    # Per-provider inputs
    base_url = _prompt_base_url(console, preset)
    if base_url == "":
        base_url = None  # Anthropic direct has no base_url
    api_key_literal = _prompt_api_key(
        console,
        preset,
        no_open=bool(getattr(args, "no_open", False)),
        timeout_seconds=int(getattr(args, "timeout_seconds", 60)),
    )
    model = _prompt_model(console, preset)

    if model == "" and preset.key != "anthropic":
        console.print("[red]Error: model cannot be empty for OpenAI-compat endpoints.[/red]")
        return

    # Confirm + write
    _print_config_preview(console, preset, base_url, api_key_literal, model)
    if not args.yes:
        existing = cli.config.get_provider_section()
        if existing:
            console.print(
                "\n[yellow]An existing provider config was found in "
                f"{cli.config.DEFAULT_CONFIG_PATH}[/yellow]"
            )
            if not Confirm.ask("Overwrite it?", default=True):
                console.print("[yellow]Setup cancelled.[/yellow]")
                return
        elif not Confirm.ask("\nWrite this to ~/.clearwing/config.yaml?", default=True):
            console.print("[yellow]Setup cancelled.[/yellow]")
            return

    # Persist
    _write_config(cli, preset, base_url, api_key_literal, model)

    # Test invoke (unless --no-test)
    if not args.no_test:
        _run_test_invoke(console, preset, base_url, api_key_literal, model)

    # Final status
    console.print("\n[bold green]Setup complete.[/bold green]")
    console.print("Run [bold]clearwing config --show-provider[/bold] anytime to inspect.")
    console.print("Run [bold]clearwing doctor[/bold] to validate your full environment.")


# --- UI helpers -----------------------------------------------------------


def _print_welcome(console: Console, cli) -> None:
    existing = cli.config.get_provider_section()
    lines = [
        f"[bold]Clearwing {__version__} — LLM provider setup[/bold]",
        "",
        "This wizard configures an LLM backend for Clearwing's network-agent",
        "and source-code hunter pipelines. Your selection persists to",
        f"  {cli.config.DEFAULT_CONFIG_PATH}",
    ]
    if existing:
        base_url = existing.get("base_url") or "(Anthropic direct)"
        model = existing.get("model") or "(default)"
        lines += [
            "",
            "[dim]Current config:[/dim]",
            f"  model:    {model}",
            f"  base_url: {base_url}",
        ]
    console.print(Panel("\n".join(lines), border_style="cyan"))
    console.print()


def _prompt_provider_choice(
    console: Console, presets: tuple[ProviderPreset, ...]
) -> ProviderPreset | None:
    """Menu-driven provider selection."""
    table = Table(title="Choose a provider", title_style="bold", show_lines=False)
    table.add_column("#", justify="right", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold")
    table.add_column("Description")

    for i, preset in enumerate(presets, start=1):
        table.add_row(str(i), preset.display_name, preset.description)
    table.add_row("0", "[dim]Cancel[/dim]", "")

    console.print(table)
    choice = IntPrompt.ask(
        "\nSelection",
        default=1,
        choices=[str(i) for i in range(0, len(presets) + 1)],
        show_choices=False,
    )
    if choice == 0:
        return None
    return presets[choice - 1]


def _prompt_base_url(console: Console, preset: ProviderPreset) -> str:
    """Prompt for base_url with a provider-appropriate default."""
    if preset.auth_flow == "openai_codex":
        console.print(
            "[dim]OpenAI OAuth uses the ChatGPT Codex backend "
            "(no Platform API key or /v1 base URL).[/dim]"
        )
        return preset.default_base_url or "https://chatgpt.com/backend-api"

    if preset.auth_flow == "anthropic_oauth":
        console.print("[dim]Anthropic OAuth uses api.anthropic.com (no base URL to set).[/dim]")
        return ""

    if preset.default_base_url is None:
        # Anthropic direct — no base_url to configure
        console.print("[dim]Anthropic direct uses api.anthropic.com (no base URL to set).[/dim]")
        return ""

    default = preset.default_base_url
    return Prompt.ask(
        "Base URL",
        default=default,
    ).strip()


def _prompt_api_key(
    console: Console,
    preset: ProviderPreset,
    *,
    no_open: bool = False,
    timeout_seconds: int = 60,
) -> str:
    """Prompt for the API key literal to store in config.yaml.

    Three behaviors depending on provider:

    - Keyless backends (Ollama, LM Studio): skip the prompt entirely
      and store `"ollama"` / `"not-needed"` as a placeholder.
    - Keyed backend with a known env var that's set in the current
      shell: offer to store `${NAME}` as a literal instead of the
      actual secret, so the YAML file never contains credentials.
    - Otherwise: prompt for the literal secret (Rich's Prompt masks
      it by default).
    """
    if preset.auth_flow == "openai_codex":
        from clearwing.providers.openai_oauth import (
            ensure_fresh_openai_oauth_credentials,
            load_openai_oauth_credentials,
            login_openai_oauth,
        )

        existing = load_openai_oauth_credentials()
        if existing:
            try:
                creds = ensure_fresh_openai_oauth_credentials()
                reuse = Confirm.ask(
                    f"Found existing OpenAI OAuth credentials (account_id={creds.account_id}). Use them?",
                    default=True,
                )
                if reuse:
                    console.print(
                        f"[dim]Using stored OpenAI OAuth credentials for "
                        f"account_id={creds.account_id}.[/dim]"
                    )
                    return ""
            except Exception as exc:
                console.print(
                    f"[yellow]Stored OpenAI OAuth credentials need renewal: {exc}[/yellow]"
                )

        console.print(
            "[dim]Starting OpenAI browser OAuth. Credentials are stored under ~/.clearwing/auth/.[/dim]"
        )
        creds = login_openai_oauth(
            no_open=no_open,
            timeout_seconds=timeout_seconds,
            print_fn=console.print,
        )
        console.print(f"[green]OpenAI OAuth login complete.[/green] account_id={creds.account_id}")
        return ""

    if preset.auth_flow == "anthropic_oauth":
        from clearwing.providers.openai_oauth import (
            ensure_fresh_anthropic_oauth_credentials,
            load_anthropic_oauth_credentials,
            login_anthropic_oauth,
        )

        existing = load_anthropic_oauth_credentials()
        if existing:
            try:
                creds = ensure_fresh_anthropic_oauth_credentials()
                reuse = Confirm.ask(
                    "Found existing Anthropic OAuth credentials. Use them?",
                    default=True,
                )
                if reuse:
                    console.print("[dim]Using stored Anthropic OAuth credentials.[/dim]")
                    return ""
            except Exception as exc:
                console.print(
                    f"[yellow]Stored Anthropic OAuth credentials need renewal: {exc}[/yellow]"
                )

        console.print(
            "[dim]Starting Anthropic browser OAuth. Credentials are stored under ~/.clearwing/auth/.[/dim]"
        )
        creds = login_anthropic_oauth(
            no_open=no_open,
            timeout_seconds=timeout_seconds,
            print_fn=console.print,
        )
        console.print("[green]Anthropic OAuth login complete.[/green]")
        return ""

    if preset.is_local and preset.api_key_env_var is None:
        placeholder = "ollama" if "11434" in (preset.default_base_url or "") else "not-needed"
        console.print(
            f"[dim]{preset.display_name} is keyless — storing '{placeholder}' as a placeholder.[/dim]"
        )
        return placeholder

    env_var = preset.api_key_env_var
    env_value = os.environ.get(env_var) if env_var else None

    if env_var and env_value:
        console.print(
            f"[dim]Detected ${env_var} in your environment (length {len(env_value)}).[/dim]"
        )
        use_env = Confirm.ask(
            f"Store as [bold]${{{env_var}}}[/bold] (keeps the secret out of the file)?",
            default=True,
        )
        if use_env:
            return f"${{{env_var}}}"

    if env_var:
        console.print(
            f"[dim]Get an API key at {preset.docs_url} (or set ${env_var} and re-run setup).[/dim]"
        )
    else:
        console.print(f"[dim]Get an API key at {preset.docs_url}.[/dim]")

    api_key = Prompt.ask("API key", password=True, default="").strip()
    return api_key


def _prompt_model(console: Console, preset: ProviderPreset) -> str:
    """Prompt for the default model identifier."""
    if preset.alt_models:
        console.print("\n[dim]Common models for this provider:[/dim]")
        console.print(f"[dim]  {preset.default_model} (default)[/dim]")
        for alt in preset.alt_models:
            console.print(f"[dim]  {alt}[/dim]")

    return Prompt.ask(
        "\nModel",
        default=preset.default_model,
    ).strip()


def _print_config_preview(
    console: Console,
    preset: ProviderPreset,
    base_url: str | None,
    api_key_literal: str,
    model: str,
) -> None:
    """Show the YAML that's about to be written, masking secrets."""
    masked = _mask_secret(api_key_literal)
    lines = ["provider:"]
    if preset.auth_flow:
        lines.append(f"  auth: {preset.auth_flow}")
    if base_url:
        lines.append(f"  base_url: {base_url}")
    if masked:
        lines.append(f"  api_key: {masked}")
    lines.append(f"  model: {model}")

    console.print(
        Panel("\n".join(lines), title=f"{preset.display_name} config", border_style="green")
    )


def _mask_secret(value: str) -> str:
    """Hide the middle of a literal secret. `${ENV_VAR}` references
    pass through unchanged because they're not actually secrets."""
    if not value:
        return ""
    if value.startswith("${") and value.endswith("}"):
        return value
    if value in ("ollama", "not-needed", "lm-studio"):
        return value
    if len(value) <= 12:
        return "*" * len(value)
    return f"{value[:4]}...{value[-4:]} ({len(value)} chars)"


def _write_config(
    cli,
    preset: ProviderPreset,
    base_url: str | None,
    api_key_literal: str,
    model: str,
) -> None:
    """Persist the provider section to ~/.clearwing/config.yaml.

    Merges with any existing config file — leaves unrelated sections
    (scanning, exploitation, reporting, database) untouched. We do
    NOT go through `cli.config.save()` because that dumps the entire
    merged default config (including the 1024-port scanning defaults),
    which would balloon the file to ~1000 lines for a 3-key write.
    """
    import yaml

    provider_section: dict[str, str] = {}
    if preset.auth_flow:
        provider_section["auth"] = preset.auth_flow
    if base_url:
        provider_section["base_url"] = base_url
    if api_key_literal:
        provider_section["api_key"] = api_key_literal
    if model:
        provider_section["model"] = model
    if preset.provider_adapter:
        # Presets like `openai-responses` that target a specific
        # genai-pyo3 adapter persist the name so the provider manager
        # doesn't have to guess from the base URL.
        provider_section["adapter"] = preset.provider_adapter

    path = cli.config.DEFAULT_CONFIG_PATH
    path.parent.mkdir(parents=True, exist_ok=True)

    # Read existing file (if any), merge provider:, write back.
    existing: dict = {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text()) or {}
            if isinstance(loaded, dict):
                existing = loaded
        except Exception:
            existing = {}

    existing["provider"] = provider_section
    path.write_text(yaml.safe_dump(existing, default_flow_style=False, sort_keys=True))

    # Keep the in-memory Config object in sync for the current process.
    cli.config.set("provider", value=provider_section)

    cli.console.print(f"\n[green]Wrote {path}[/green]")


def _run_test_invoke(
    console: Console,
    preset: ProviderPreset,
    base_url: str | None,
    api_key_literal: str,
    model: str,
) -> None:
    """Best-effort health check: build the LLM and fire one tiny prompt.

    Logs the round-trip time on success, or a helpful error message on
    failure. Never raises — a failed test shouldn't block the user
    from completing setup (their config might be right but the
    service might be temporarily down).
    """
    from clearwing.providers import LLMEndpoint, ProviderManager

    if preset.auth_flow in ("openai_codex", "anthropic_oauth"):
        provider_name = "openai_codex" if preset.auth_flow == "openai_codex" else "anthropic_oauth"
        endpoint = LLMEndpoint(
            provider=provider_name,
            model=model,
            base_url=base_url or None,
            api_key=None,
            source="cli",
        )
        console.print("\n[dim]Testing endpoint...[/dim]", end=" ")
        try:
            llm = ProviderManager.for_endpoint(endpoint).get_llm("default")
            start = time.monotonic()
            response = llm.invoke("Reply with exactly the word PONG.")
            elapsed_ms = int((time.monotonic() - start) * 1000)
        except Exception as exc:
            console.print(f"\n[red]Test failed: {exc}[/red]")
            console.print(
                "[yellow]The config was still written. "
                "Run `clearwing doctor` for a fuller diagnosis.[/yellow]"
            )
            return

        content = getattr(response, "content", str(response))
        if isinstance(content, list):
            content = " ".join(str(p) for p in content)
        snippet = str(content).strip()[:60]
        console.print(f"[green]ok[/green] ({elapsed_ms}ms, reply: {snippet!r})")
        return

    # Resolve the literal api_key if the user chose ${ENV_VAR} form
    resolved_key = api_key_literal
    if api_key_literal.startswith("${") and api_key_literal.endswith("}"):
        env_name = api_key_literal[2:-1]
        resolved_key = os.environ.get(env_name, "")
        if not resolved_key:
            console.print(
                f"[yellow]Skipping test: ${env_name} is not set in this shell. "
                "Export it and re-run, or use `clearwing doctor`.[/yellow]"
            )
            return

    if preset.is_openai_compat and base_url:
        endpoint = LLMEndpoint(
            provider="openai_compat",
            model=model,
            base_url=base_url,
            api_key=resolved_key or "not-needed",
            source="cli",
        )
    else:
        # Anthropic direct (base_url=None) or an Anthropic-compatible gateway
        # like MiniMax (base_url set, provider still "anthropic").
        endpoint = LLMEndpoint(
            provider="anthropic",
            model=model,
            base_url=base_url or None,
            api_key=resolved_key or None,
            source="cli",
        )

    console.print("\n[dim]Testing endpoint...[/dim]", end=" ")
    try:
        llm = ProviderManager.for_endpoint(endpoint).get_llm("default")
        start = time.monotonic()
        response = llm.invoke("Reply with exactly the word PONG.")
        elapsed_ms = int((time.monotonic() - start) * 1000)
    except Exception as exc:
        console.print(f"\n[red]Test failed: {exc}[/red]")
        console.print(
            "[yellow]The config was still written. "
            "Run `clearwing doctor` for a fuller diagnosis.[/yellow]"
        )
        return

    content = getattr(response, "content", str(response))
    if isinstance(content, list):
        content = " ".join(str(p) for p in content)
    snippet = str(content).strip()[:60]
    console.print(f"[green]ok[/green] ({elapsed_ms}ms, reply: {snippet!r})")
