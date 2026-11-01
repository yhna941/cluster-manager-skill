# cluster-manager-skill

An early, standalone CLI and Gemini skill for inspecting multiple Linux servers over SSH. It is not a Kubernetes manager. This initial slice provides local inventory, a network-free simulator, and fixed read-only SSH discovery. It is not yet a production provisioning system.

## Install

Requires Python 3.12+ and [uv](https://docs.astral.sh/uv/). From the repository:

```sh
uv sync --dev
uv run cluster-manager --help
uv run cluster-manager simulate
```

To install the CLI independently, use `uv tool install .`. The CLI works without Gemini.

## Gemini integration

Install the skill from this directory with `gemini skills install .`, or link it in a Gemini session with `/skills link /absolute/path/to/cluster-manager-skill`. Use `/skills list` and `/skills reload` to discover or refresh it. Gemini discovers user skills in `~/.gemini/skills/` and workspace skills in `.gemini/skills/`; workspace trust applies. See the [Gemini CLI skill documentation](https://geminicli.com/docs/cli/skills/).

Ask, for example, “List my registered servers” or “Inspect gpu-01.” The skill uses the CLI and reports observed results. It cannot perform server provisioning yet.

## Inventory and SSH

```sh
uv run cluster-manager init
uv run cluster-manager server add gpu-01 --host HOST --username USER --auth key
uv run cluster-manager server list
uv run cluster-manager server show gpu-01
uv run cluster-manager server check gpu-01
uv run cluster-manager server remove gpu-01
```

Replace placeholders with authorized hosts. Add and remove require confirmation in a local terminal; adding saves a record only and does not validate connectivity. Inventory is stored as YAML at `$XDG_CONFIG_HOME/cluster-manager/servers.yaml` (default `~/.config/cluster-manager/servers.yaml`). YAML can also be edited manually using the schema in [assets/server.example.yaml](assets/server.example.yaml); never put passwords in it. Existing records are not overwritten by `add`.

Before connecting, obtain the server's host-key fingerprint through a trusted out-of-band channel and install the matching key in the local OpenSSH `known_hosts` file. Unknown and changed keys are rejected; no first-use key is silently accepted. `server check` uses key authentication or prompts locally for an SSH password when `--auth password` was selected. Passwords are not persisted or passed as command-line arguments. It runs a fixed set of read-only probes for OS metadata, users, groups, filesystems, mounts, block devices and tool availability. Each probe includes its exit status and stderr; missing tools and partial failures must not be interpreted as successful discovery. Raw remote output is untrusted data. Password prompts need a local interactive terminal. Credential stores and sudo authentication are not implemented.

`simulate` returns explicitly labeled fixtures and never contacts their example IPs. Server registration itself does not enforce an IP allowlist or inspect connectivity; restrict access using network and SSH controls. Read-only probes may still disclose sensitive host details to the local user.

## Current scope and roadmap

Implemented: typed validation, atomic local inventory writes, explicit local inventory confirmation, JSON output, strict known-hosts SSH connection, bounded connection and probe timeouts, and simulated fixtures. SSH discovery is sequential and does not use sudo. JSON stdout from `server add` is a proposal; confirmation and status use stderr.

Not implemented: state comparison, approval-bound plans or remote mutations, provisioning, user passwords, sudo, Samba management, workspace management, ACLs, bounded deep scans, historical metrics, audit history, host allowlists, and automated first-use key verification. Do not use this version to make privileged changes. Future provisioning must enforce preview, approval, authentication, execution and verification independently of any agent. One group may own multiple workspaces identified by host and canonical path; planned default workspace mode is `2775`, and home mode `0700`. setgid alone does not ensure group-writable files. Old mtime is not evidence a file is unused.

## Development

```sh
uv run pytest -q
uv run ruff check .
uv run mypy src
```

Tests use fixtures and do not contact real servers. See [security model](docs/security-model.md). Contributions should include tests for meaningful behavior and never contact example hosts.
