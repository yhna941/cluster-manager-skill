# Supported desired operations

Every document has server: REGISTERED_NAME and operation: {type: ..., ...}.

- group.create: group
- user.create: username, groups (default []), home (optional), password (boolean, default true), samba (boolean, default false)
- user.password: username, samba (boolean, default false)
- user.membership: username, group, action (add/remove)
- user.lock / user.unlock: username; affects password authentication only
- workspace.create: path, group, mode (2775 default or 2770), samba (existing default or off)
- permissions.set: path, group, mode (2770 or 2775); nonrecursive
- samba.user.ensure / samba.user.password / samba.user.disable: username

A plan holds one typed operation; user.create can comprise account, home and initial Linux/Samba password steps. Separate dependent plans must be applied in order. Attempted plans cannot be replayed; use verify and audit show, then regenerate desired state. Existing-state conflicts fail rather than being overwritten. Initial password equality is a convention, not ongoing synchronization.
