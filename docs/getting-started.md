# Getting started

1. Install with uv sync --dev, or uv tool install . for the CLI.
2. Run cluster-manager simulate --scenario examples/simulation.yaml without any servers.
3. Verify your real server's SSH fingerprint independently and add its key to known_hosts.
4. Register the server and real storage roots with server add.
5. Inspect server check, samba shares and storage summary.
6. Plan/apply the group, then workspace, then user with a single private home.
7. Inspect verify PLAN_ID and audit show PLAN_ID after each apply.

Use the README examples for exact commands. Existing /disk shares do not need to be duplicated for each group. If current share rules do not permit access, the tool reports that and leaves configuration unchanged.
