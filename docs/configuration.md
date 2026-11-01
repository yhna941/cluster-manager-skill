# Configuration

See assets/server.example.yaml. Nonsecret YAML inventory defaults to ~/.config/cluster-manager/servers.yaml and follows XDG_CONFIG_HOME. Strict Pydantic schemas reject unknown keys. SSH authentication is key or password. sudo.authentication is interactive (default) or noninteractive. Noninteractive mode does not create authorization. Credential references are metadata only; external credential-store persistence is not implemented.

storage_roots lists actual mounts such as /disk1 and /disk2. Workspaces are direct children. Private homes use WORKSPACE/usr/USERNAME. Reject root/system paths and roots with untrusted writable ancestors. Samba is existing-share only; there is no config-write switch.

Local state defaults to ~/.local/state/cluster-manager and follows XDG_STATE_HOME. It holds version-2 plan files and operations.sqlite3. Never place passwords in any configuration or desired-state YAML. Version-1 plans must be regenerated.
