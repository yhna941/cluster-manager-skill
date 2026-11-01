# Security

Verified SSH host keys are mandatory. The CLI validates typed operations and never accepts a free-form root command. All mutation CLI paths use the shared engine. Plans bind server configuration, host key, observed state, compiled steps, worker version, local UID and expiry. Apply shows the exact command and actions and requires a local digest-bound human approval. No automatic confirmation switch exists. Do not invoke lower-level APIs to bypass this.

sudo authentication is a separate local prompt. A handshake keeps its password separate from JSON input and account-password stdin. Only an authenticated, approved execution receives account secrets. SQLite records redacted stages/results. Timeouts and partial changes are not rollback guarantees. The installed local engine and its owner remain trusted; the Python package is not an OS sandbox.
