# Sandbox backends

SourceHunt separates the environment it needs from the runtime that provides
it. `HunterSandbox` selects a logical toolchain profile, tool features,
sanitizers, resource limits, mounts, and security policy. A trusted
`SandboxBackend` prepares that environment and creates `SandboxInstance`
objects that execute commands and transfer files.

An environment is not necessarily an OCI image. A Docker backend may build
and cache an image, Kubernetes may use a configured image plus an ephemeral
volume, and a local backend may use a rootfs overlay. These choices, including
base images and package-manager commands, belong to the provider.

Docker remains the zero-configuration default:

```python
from clearwing.sandbox import HunterSandbox

sandbox = HunterSandbox("/path/to/source")
sandbox.prepare_environment()
instance = sandbox.spawn()
```

Applications can inject a backend directly:

```python
from clearwing.sandbox import HunterSandbox, SocketSandboxBackend

backend = SocketSandboxBackend("unix:///run/my-service/sandbox.sock")
sandbox = HunterSandbox("/path/to/source", backend=backend)
```

Alternatively, set `CLEARWING_SANDBOX_ENDPOINT`. When it is absent or empty,
Clearwing uses `DockerSandboxBackend`. Supported endpoint forms are:

- `unix:///absolute/path.sock` — connect to a Unix stream socket.
- `fd://N` — adopt an inherited, already-connected Unix stream socket.

An inherited endpoint is normally a `socketpair`, not an OS pipe: JSON-RPC
requests and responses need one full-duplex stream. A process supervisor can
reserve any descriptor of at least 3 and pass, for example,
`CLEARWING_SANDBOX_ENDPOINT=fd://4` to Clearwing. Clearwing takes ownership of
the inherited descriptor and closes it with the RPC connection; the supervisor
retains only its own endpoint of the socketpair.

## Environment contract

`SandboxEnvironmentSpec` contains only logical requirements:

- `cache_key` — SHA-256 identity of the complete logical request.
- `profile` — one of `c-cpp`, `rust`, `go`, `python`, `java`, `node`, or
  `generic`.
- `features` — required capability codes. Unknown or unsupported required
  codes must fail preparation.
- `optional_features` — capabilities that may be unavailable without failing
  preparation.
- `sanitizers` — the requested instrumentation variants.
- `environment` — compiler and sanitizer environment variables associated
  with the variant.
- `timeout_seconds` — preparation deadline.

The current feature vocabulary is deliberately closed and maintained in
Clearwing. It includes codes such as `build.make`, `build.cmake`,
`build.cargo`, `build.go`, `build.maven`, `build.npm`, `build.native`,
`toolchain.native`, `toolchain.clang`, `source.search`, `debug.native`,
`debug.valgrind`, `trace.syscalls`, `trace.library-calls`, `process.timeout`,
`runtime.python`, `trust.roots`, and `vcs.git`.

Build-system detection is deterministic. Repository markers such as
`CMakeLists.txt`, `Cargo.toml`, `go.mod`, `pom.xml`, `package.json`, and
`pyproject.toml` select a hardcoded profile and feature set. The hunter model
does not submit environment codes, package names, setup commands, images, or
runtime flags.

The environment request intentionally contains no Dockerfile, base-image
name, registry reference, distro package name, or arbitrary setup command.
For example, Clearwing requests `source.search`; the default Docker adapter
privately resolves that code to its Debian package. Another provider may
satisfy it from a preinstalled tool bundle. Provider-specific resolution must
not leak back into the logical contract.

`ensure_environment` returns an opaque environment reference. Clearwing only
passes that reference back to `create`; it does not interpret it as an image,
pod, path, or provider-native identifier. `release_environment` permits an
explicit cleanup request, but a provider may retain safe content-addressed
caches according to deployment policy.

The checked-out repository is separate from environment preparation. It is
mounted read-only for normal hunts or copied into the sandbox for explicitly
writable flows. This separation allows environment preparation to use narrowly
controlled package access without exposing source or mission secrets, while
actual repository commands run with networking disabled.

Version 1 is a local-or-shared-filesystem protocol: mount entries and
`sandbox.tree.copy` identify host paths. The backend must resolve them inside
the same filesystem namespace, or translate them to an equivalent approved
workspace mount. Transporting a workspace to an arbitrary remote host is
outside this contract.

## Backend interface

`SandboxBackend` provides four operations:

- Report available CPU capacity.
- Ensure a logical environment exists and return an opaque reference.
- Create a sandbox from that reference and `SandboxRunConfig`.
- Release a prepared environment when cleanup is requested.

The returned `SandboxInstance` provides `start`, `exec`, `write_file`,
`read_file`, `copy_tree_into`, and `stop`, plus runtime-neutral identity and
lifecycle properties. Downstream SourceHunt code depends on this protocol,
not on the Docker SDK implementation.

## JSON-RPC protocol

The socket adapter uses JSON-RPC 2.0. Each request or response is one UTF-8
JSON object followed by `\n`; an individual record is limited to 16 MiB.
Requests may be concurrent and responses may arrive out of order. The client
correlates them by integer `id`.

| Method | Parameters | Result |
|---|---|---|
| `sandbox.capabilities` | `{}` | `{"protocol_version": 1}` |
| `sandbox.capacity` | `{}` | `{"cpus": number|null, "source": string}` |
| `sandbox.environment.ensure` | `{"spec": SandboxEnvironmentSpec}` | `{"environment_ref": string, "cached": bool, "output"?: [string]}` |
| `sandbox.environment.release` | `{"environment_ref": string}` | `{}` |
| `sandbox.start` | `{"environment_ref": string, "config": SandboxRunConfig}` | `{"sandbox_id": string, "short_id"?: string}` |
| `sandbox.exec` | sandbox id, command, timeout, environment, working directory | `ExecResult` fields |
| `sandbox.file.write` | sandbox id, path, base64 content | `{}` |
| `sandbox.file.read` | sandbox id and path | `{"content_base64": string}` |
| `sandbox.tree.copy` | sandbox id, host path, container path | `{}` |
| `sandbox.stop` | `{"sandbox_id": string}` | `{}` |

Binary file bodies use strict standard base64. The v1 API returns buffered
command output, matching the existing `SandboxContainer.exec` contract. For
`sandbox.exec`, a command array is direct argv while a string runs through
`/bin/sh -c`; `env` overlays the instance environment, a null `workdir` uses
the configured working directory, and a non-positive effective timeout means
no execution deadline.

JSON-RPC errors use the standard `error.code`, `error.message`, and optional
`error.data` fields. Clearwing exposes them as `SandboxRpcError`.

## Security responsibilities

A sandbox backend is trusted infrastructure, not an agent tool. A service
implementing this protocol must independently:

- Authenticate or physically confine access to the endpoint. Inherited
  socketpairs are preferred; pathname sockets should have restrictive owner
  and mode settings.
- Validate every code and field and bound runtime output, file bodies, and
  preparation logs. Unknown required environment codes fail closed.
- Constrain host paths to the run's approved workspace. A path received from
  Clearwing is a request, not authorization to expose arbitrary host files.
- Enforce requested no-network behavior, read-only source semantics, resource
  limits, capabilities, seccomp policy, deadlines, and cleanup.
- Treat environment references and sandbox ids as opaque, connection- or
  run-scoped handles and reconcile leaked workloads when the client
  disconnects.
- Keep registry, cloud, cluster, and package-repository credentials on the
  trusted side of the socket and out of prepared execution sandboxes.

Environment preparation should be secretless and isolated from the repository.
Repository build, test, fuzz, and PoC commands run in the no-network execution
sandbox because project build systems themselves are untrusted code.
