# Contributing

Use Python 3.12+ and uv. Run uv run pytest -q, uv run ruff check ., uv run mypy src and uv build. Unit tests are rootless and network-free. Do not contact fixture IPs. tests/integration runs only when CM_LINUX_INTEGRATION=1 and asserts a disposable Docker environment; never enable it on a real server. CI provides an Ubuntu container and tmpfs storage for these tests.

Keep operation schemas closed, previews deterministic and approval separate from authentication. Add regression tests for new security boundaries and partial failures. Do not reintroduce legacy mutation paths or arbitrary root commands. Samba configuration preservation is intentional product policy.
