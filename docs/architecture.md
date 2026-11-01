# Architecture

cli.py routes human/agent requests to typed operations. managed/worker.py is a self-contained standard-library Linux adapter with shared validation, deterministic compilation, observation, descriptor-based filesystem changes and verification. managed/engine.py manages registered targets, SSH, plan persistence, digest/identity checks, local approval, credentials and SQLite stage history. The exact versioned worker source is compressed into the SSH command; no permanent daemon/helper installation is required.

The worker command is shown in plans alongside actual subprocess argv and filesystem actions. Request JSON cannot contain arbitrary commands. Password values are sent only for execution and never persisted. The client recompiles the preview independently from operation/state rather than trusting remote command suggestions. Engine or configuration updates invalidate pending plans.

The simulator uses the same compiler with in-memory fixtures. Unit tests use fake OS/SSH boundaries, while a disposable Ubuntu CI container exercises actual Linux and Samba tools. Normal tests never contact example IPs or need root. Existing v0.1 mutation paths were removed so all public CLI mutations share one approval boundary.
