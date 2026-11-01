# Servers

Use server list/show/check and inventory metadata; never infer connectivity from a saved registration. Register with server add NAME --host HOST --username USER --storage-root PATH, using a local confirmation. The default SSH method is key authentication; --auth password uses hidden local prompts. Default sudo authentication is interactive; YAML can select noninteractive when already authorized. Never edit sudoers or skip host-key checking automatically. storage_roots are policy boundaries and must match real mounts before mutation.
