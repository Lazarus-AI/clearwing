# Sandbox backends

SourceHunt separates its sandbox policy from the runtime that enforces it.
`HunterSandbox` renders sanitizer images and chooses resource, mount, and
security settings. A `SandboxBackend` prepares those images and creates
`SandboxInstance` objects that execute commands and transfer files.

Docker remains the default and requires no configuration:

```python
from clearwing.sandbox import HunterSandbox

sandbox = HunterSandbox("/path/to/source")
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
- `fd://N` — duplicate an inherited, already-connected Unix stream socket.

An inherited endpoint is normally a `socketpair`, not an OS pipe: JSON-RPC
requests and responses need one full-duplex stream. A process supervisor can
reserve any descriptor of at least 3 and pass, for example,
`CLEARWING_SANDBOX_ENDPOINT=fd://4` to Clearwing.

## Backend interface

`SandboxBackend` provides four operations:

- Report available CPU capacity.
- Ensure a content-addressed OCI image exists from a Dockerfile build request.
- Create a sandbox from `SandboxConfig`.
- Remove an image during requested cleanup.

The returned `SandboxInstance` provides `start`, `exec`, `write_file`,
`read_file`, `copy_tree_into`, and `stop`, plus runtime-neutral identity and
lifecycle properties. Downstream SourceHunt code depends on this protocol,
not on the Docker SDK implementation.

The current build contract intentionally carries a Dockerfile. Docker,
BuildKit, Kaniko, and most Kubernetes image-building services can consume it.
A backend that cannot prepare OCI images should reject `ensure_image` instead
of silently weakening the requested toolchain.

Version 1 is a local-or-shared-filesystem protocol: mount entries and
`sandbox.tree.copy` identify host paths. The backend must resolve them inside
the same filesystem namespace, or translate them to an equivalent approved
workspace mount. Transporting a workspace to an arbitrary remote host is
deliberately outside this contract.

## JSON-RPC protocol

The socket adapter uses JSON-RPC 2.0. Each request or response is one UTF-8
JSON object followed by `\n`; an individual record is limited to 16 MiB.
Requests may be concurrent and responses may arrive out of order. The client
correlates them by integer `id`.

| Method | Parameters | Result |
|---|---|---|
| `sandbox.capabilities` | `{}` | `{"protocol_version": 1}` |
| `sandbox.capacity` | `{}` | `{"cpus": number|null, "source": string}` |
| `sandbox.image.ensure` | `{"build": SandboxImageBuild}` | `{"cached": bool, "output"?: [string]}` |
| `sandbox.image.remove` | `{"image": string}` | `{}` |
| `sandbox.start` | `{"config": SandboxConfig}` | `{"sandbox_id": string, "short_id"?: string}` |
| `sandbox.exec` | sandbox id, command, timeout, environment, working directory | `ExecResult` fields |
| `sandbox.file.write` | sandbox id, path, base64 content | `{}` |
| `sandbox.file.read` | sandbox id and path | `{"content_base64": string}` |
| `sandbox.tree.copy` | sandbox id, host path, container path | `{}` |
| `sandbox.stop` | `{"sandbox_id": string}` | `{}` |

Binary file bodies use strict standard base64. The v1 API returns buffered
command output, matching the existing `SandboxContainer.exec` contract.
For `sandbox.exec`, a command array is direct argv while a string runs through
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
- Validate every field and bound runtime output, file bodies, and build logs.
- Constrain host paths to the run's approved workspace. A path received from
  Clearwing is a request, not authorization to expose arbitrary host files.
- Enforce the requested no-network mode, read-only source semantics, resource
  limits, capabilities, seccomp policy, deadlines, and cleanup.
- Treat sandbox ids as opaque, connection- or run-scoped handles and reconcile
  leaked workloads when the client disconnects.

The JSON-RPC endpoint carries no cloud, registry, or cluster credentials.
Those belong to the backend service on the trusted side of the socket.
