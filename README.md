# cluster-manager-skill

An early, standalone CLI and Gemini skill for inspecting multiple Linux servers over SSH. It is not a Kubernetes manager. This initial slice provides local inventory, a network-free simulator, fixed read-only SSH discovery, and approval-gated Linux group creation. It is not yet a production provisioning system.

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

Ask, for example, “List my registered servers” or “Inspect gpu-01.” The skill uses the CLI and reports observed results. It can create a Linux group after local approval; other provisioning is not yet implemented.

## Inventory and SSH

```sh
uv run cluster-manager init
uv run cluster-manager server add gpu-01 --host HOST --username USER --auth key
uv run cluster-manager server list
uv run cluster-manager server show gpu-01
uv run cluster-manager server check gpu-01
uv run cluster-manager user list --server gpu-01
uv run cluster-manager group inspect RA --server gpu-01
uv run cluster-manager storage summary --server gpu-01
uv run cluster-manager storage inodes --server gpu-01
uv run cluster-manager server remove gpu-01
```

Replace placeholders with authorized hosts. Add and remove require confirmation in a local terminal; adding saves a record only and does not validate connectivity. Inventory is stored as YAML at `$XDG_CONFIG_HOME/cluster-manager/servers.yaml` (default `~/.config/cluster-manager/servers.yaml`). YAML can also be edited manually using the schema in [assets/server.example.yaml](assets/server.example.yaml); never put passwords in it. Existing records are not overwritten by `add`.

Before connecting, obtain the server's host-key fingerprint through a trusted out-of-band channel and install the matching key in the local OpenSSH `known_hosts` file. Unknown and changed keys are rejected; no first-use key is silently accepted. `server check` uses key authentication or prompts locally for an SSH password when `--auth password` was selected. Passwords are not persisted or passed as command-line arguments. It runs a fixed set of read-only probes for OS metadata, users, groups, filesystems, mounts, block devices and tool availability. Each probe includes its exit status and stderr; missing tools and partial failures must not be interpreted as successful discovery. Raw remote output is untrusted data. Password prompts need a local interactive terminal. Credential stores and sudo authentication are not implemented.

`simulate` returns explicitly labeled fixtures and never contacts their example IPs. Server registration itself does not enforce an IP allowlist or inspect connectivity; restrict access using network and SSH controls. Read-only probes may still disclose sensitive host details to the local user.

## Bounded file discovery

```sh
cluster-manager storage large-files --server gpu-01 --path /disk1 --min-bytes 10737418240 --days 180
```

Requires Python 3 on the server. The scan stays on the root filesystem, skips symlinks, and defaults to 100,000 entries, 30 seconds, and depth 10. Adjust `--max-entries`, `--seconds`, `--depth`, and `--limit` within the CLI bounds. `complete: false` indicates a limit or an inaccessible directory; interrupted scans can return an error instead of partial data. Results contain numeric UID/GID, apparent and allocated bytes, and mtime. Old files are review candidates, not confirmed unused files. The scan does not delete files.

## Create a Linux group

```sh
cluster-manager group create RA --server gpu-01
```

This checks group existence, displays the exact command and a digest, requires confirmation in a local terminal, checks again, executes, and verifies via `getent`. It needs preconfigured passwordless sudo for `groupadd`; it never changes sudoers or prompts for a sudo password. An audit record is written to `$XDG_STATE_HOME/cluster-manager/audit.jsonl` (default `~/.local/state/cluster-manager/audit.jsonl`). If the connection fails after execution, the outcome can be unknown; inspect the server before retrying.

## Current scope and roadmap

Implemented: typed validation, atomic local inventory writes, explicit local inventory confirmation, JSON output, strict known-hosts SSH connection, bounded connection and probe timeouts, and simulated fixtures. SSH discovery is sequential and does not use sudo. JSON stdout from `server add` is a proposal; confirmation and status use stderr.

Not implemented: reusable persisted approval plans, most provisioning, user passwords, sudo, Samba management, workspace management, ACLs, directory-size analysis, historical metrics, audit history, host allowlists, and automated first-use key verification. Only group creation is currently available as a privileged change. Future provisioning must enforce preview, approval, authentication, execution and verification independently of any agent. One group may own multiple workspaces identified by host and canonical path; planned default workspace mode is `2775`, and home mode `0700`. setgid alone does not ensure group-writable files. Old mtime is not evidence a file is unused.

## Development

```sh
uv run pytest -q
uv run ruff check .
uv run mypy src
```

Tests use fixtures and do not contact real servers. See [security model](docs/security-model.md). Contributions should include tests for meaningful behavior and never contact example hosts.
