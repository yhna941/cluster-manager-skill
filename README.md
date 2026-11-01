# cluster-manager-skill

Standalone Linux infrastructure administration over SSH, with a Gemini skill as the natural-language interface. The Python engine works independently of Gemini. It manages Linux accounts, group memberships, private homes, setgid workspaces, Samba users, and bounded file discovery. It is not a Kubernetes manager.

## Existing Samba configuration is preserved

If `/disk1` is already shared, creating `/disk1/RA` does **not** require another share. The default workflow inspects the existing share and manages Linux groups, directories and Samba accounts. The application never writes `/etc/samba/smb.conf`, include files, or firewall rules, and never installs or reloads Samba.

A user may need both `RA` (workspace access) and `smbuser` (the existing share's `valid users` policy). Linux groups do not contain other groups. Membership additions use additive `usermod --append --groups` operations. Access still depends on the existing share's read/write rules and Unix permissions; configuration inspection is not an SMB login test. Reconnect existing SMB sessions after membership changes.

Workspace mode `2775` permits others to read/traverse; choose `2770` to restrict Unix access to the group. setgid preserves group inheritance, but file writability also depends on umask, ACLs and existing Samba masks. A `0700` home is private through ordinary Unix access, but its name may still be visible. Existing `force user` shares are rejected for new private/group paths because they can defeat per-user isolation. See [Samba policy](references/samba.md).

## Install and try without servers

Requires Python 3.12+ locally and [uv](https://docs.astral.sh/uv/). Managed hosts require Debian/Ubuntu-compatible Linux tools and Python 3.10+ at `/usr/bin/python3`.

```sh
uv sync --dev
uv run cluster-manager --help
uv run cluster-manager simulate
uv run cluster-manager simulate --scenario examples/simulation.yaml
```

The simulator never connects to fixture IP addresses. It executes typed operations against in-memory fixture state and labels all results as simulated. Install the standalone executable with `uv tool install .` (use `uv tool upgrade cluster-manager` after upgrading an installed source).

## Register and inspect

```sh
cluster-manager init
cluster-manager server add gpu-01 --host YOUR_HOST --username YOUR_USER \
  --storage-root /disk1 --storage-root /disk2
cluster-manager server list
cluster-manager server check gpu-01
cluster-manager user list --server gpu-01
cluster-manager group inspect RA --server gpu-01
cluster-manager storage summary --server gpu-01
cluster-manager storage inodes --server gpu-01
```

Registration/removal requires local terminal confirmation. Registration stores nonsecret connection information; it does not prove connectivity. Verify host-key fingerprints through an independent trusted channel before populating OpenSSH `known_hosts`. Unknown or changed keys fail closed. SSH keys are the default; use `--auth password` for local hidden password prompts. No passwords go in YAML, command arguments or chat.

Configuration is `$XDG_CONFIG_HOME/cluster-manager/servers.yaml`, default `~/.config/cluster-manager/servers.yaml`. [Example configuration](assets/server.example.yaml) shows storage roots and sudo authentication. Storage roots must be actual writable mounts, not unmounted directories. Supported managed filesystems are ext2/3/4, XFS, Btrfs and tmpfs. Their ancestors must be root-owned and not group/world-writable. The filesystem root and system paths are excluded.

## Plan, approve, apply, verify

Every mutation convenience command **creates a saved plan**; it does not immediately change the server. Apply the returned ID in a local terminal. No `--yes`, piped approval or stored reusable approval token is accepted.

```sh
cluster-manager group create RA --server gpu-01
cluster-manager apply PLAN_ID
cluster-manager workspace create --server gpu-01 --path /disk1/RA --group RA --mode 2770
cluster-manager apply PLAN_ID
cluster-manager workspace create --server gpu-01 --path /disk2/RA --group RA --mode 2770
cluster-manager apply PLAN_ID
```

One Linux group owns both workspaces. Each workspace is identified by host and path. New workspaces contain `usr/` (`root:GROUP`, `2755`); no extra `shared/` directory is created. Existing conflicting directories are rejected. Permission changes are explicit and nonrecursive:

```sh
cluster-manager permissions set --server gpu-01 --path /disk1/RA --group RA --mode 2770
cluster-manager workspace inspect --server gpu-01 --path /disk1/RA
cluster-manager workspace list --server gpu-01
```

`workspace list` reports setgid directory candidates, not proof that the tool created them. Existing POSIX ACLs and inherited default ACLs are rejected for mutation until an explicit ACL adapter is available.

Plans include observed state, desired operation, exact SSH worker command, subprocess argument arrays, filesystem actions, warnings, expiry, host-key identity and SHA-256 digest. The helper performs filesystem operations through pinned file descriptors, so they are listed as actions rather than fictitious shell commands. The compressed worker source in the exact SSH command corresponds to the shipped [worker module](src/cluster_manager/managed/worker.py).

```sh
cluster-manager plan --file examples/workspace.yaml
cluster-manager plan show PLAN_ID
cluster-manager apply PLAN_ID
cluster-manager verify PLAN_ID
cluster-manager audit show PLAN_ID
```

Plans expire after 15 minutes and must match current server configuration, host key, engine version and observed state. Apply independently recompiles allowed operations and rechecks preconditions. Every apply needs a new human approval bound to the exact digest; an attempted plan cannot be replayed. Desired YAML can be reused to generate a fresh plan. Plans from version 0.1 must be regenerated.

## Accounts, private homes and Samba users

Create required groups/workspaces first, applying each returned plan. Then:

```sh
cluster-manager user create alice --server gpu-01 --group RA --group smbuser \
  --home /disk1/RA/usr/alice --samba
cluster-manager apply PLAN_ID
```

The account is created locked first, a single private `0700` home is created, and passwords are set after approval through hidden terminal prompts. The initial Samba password equals the Linux password by default; `apply --independent-samba` prompts separately. This is initial provisioning, not ongoing synchronization. If later steps fail, created accounts and data are retained and successful/failed/unattempted steps are reported. Existing users or homes are never silently overwritten. Repeating an already satisfied create operation generates a no-op, not a password reset.

Without `--home`, account creation does not create a home directory. `--no-password` leaves it locked. For existing accounts:

```sh
cluster-manager user add-group alice RA --server gpu-01
cluster-manager user add-group alice smbuser --server gpu-01
cluster-manager user remove-group alice RA --server gpu-01
cluster-manager user password alice --server gpu-01 --samba
cluster-manager user lock alice --server gpu-01
cluster-manager user unlock alice --server gpu-01
cluster-manager samba user-add alice --server gpu-01
cluster-manager samba password alice --server gpu-01
cluster-manager samba user-disable alice --server gpu-01
cluster-manager samba shares --server gpu-01
cluster-manager samba users --server gpu-01
cluster-manager samba audit --server gpu-01 --path /disk1/RA
```

Mutation commands return plans. Password locking does not disable SSH keys or existing sessions. UID < 1000/system accounts and centrally managed identities are outside the mutation scope. Samba account operations require a standalone local passdb; AD/domain roles, external passdb backends and `unix password sync = yes` are refused. No configuration is changed to make an unsupported server pass validation.

## sudo, credentials and audit

Privileged discovery and execution run a constrained Python worker through existing sudo authorization. The default is interactive sudo authentication on the local terminal; SSH and sudo passwords may differ. A protocol handshake keeps the sudo password separate from the worker request and account passwords. The program does not change sudoers. `sudo.authentication: noninteractive` is available when the administrator already configured suitable authorization. Approval and authentication are separate; entering a sudo password does not approve a mutation.

Local state uses mode `0700`; plan files and the SQLite audit database use `0600`. State is stored at `$XDG_STATE_HOME/cluster-manager/`, default `~/.local/state/cluster-manager/`. Logs exclude password values. Python cannot guarantee in-memory secret erasure. A timeout/disconnect after execution can leave the outcome unknown; run `verify`, inspect the audit, and replan rather than assuming rollback. The local OS user and installed engine are trusted: this is an application policy boundary, not an OS sandbox against someone who can replace its Python code.

## Bounded file discovery

```sh
cluster-manager storage large-files --server gpu-01 --path /disk1 \
  --min-bytes 10737418240 --days 180 --limit 20
```

Defaults: 100,000 entries, 30 seconds, depth 10, one filesystem, no symlink following. `--max-entries`, `--seconds` and `--depth` have hard caps. Results include numeric UID/GID, apparent and allocated bytes, and mtime. `complete: false` reports limits or inaccessible paths. An interrupted scan may produce an error instead of partial output. Old files are review candidates, never automatic deletion targets.

## Gemini integration

Install from the repository with `gemini skills install .`; use `/skills list` and `/skills reload` in Gemini to discover it. User skills live under `~/.gemini/skills/`; workspace skills under `.gemini/skills/` require workspace trust. See the [official Gemini skill documentation](https://geminicli.com/docs/cli/skills/).

Natural-language examples: “Create RA workspaces on disk1 and disk2 using the existing Samba shares,” “Create alice with a private home and an initial Samba password,” or “Find large files older than 180 days.” Gemini generates typed requests and explains plans; the human applies them from a local terminal.

## Validation and limits

```sh
uv run pytest -q
uv run ruff check .
uv run mypy src
uv build
```

Ordinary tests require no root and no real servers. CI additionally tests actual Linux accounts, permissions and Samba passdb commands in a disposable Ubuntu container with tmpfs storage, checking that existing `smb.conf` is unchanged. See [contributing](CONTRIBUTING.md).

This release intentionally does not edit Samba configuration or install packages. Home migration, recursive ownership changes, ACL mutation, filesystem administration, live SMB login verification, external credential stores, storage history and directory-size aggregation are not implemented. Those are distinct operations and cannot be requested through arbitrary shell input. Multi-step changes are not transactional; inspect partial failures. Read [the security model](docs/security-model.md) before using privileged operations.
