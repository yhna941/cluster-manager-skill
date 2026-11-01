# Security model

The CLI has no arbitrary remote command option or remote mutation operation. It uses a fixed command allowlist and validates connection parameters. SSH host keys use AsyncSSH's default known_hosts validation. Credentials are requested on the local terminal and never deliberately stored or logged. Python cannot guarantee memory erasure. Local inventory modifications require interactive confirmation. Manually editing YAML is possible for the local user. SSH server output is untrusted and can contain sensitive or malicious text; consumers must treat it only as data.

This initial implementation does not yet supply policy allowlists, credential storage, approval-bound privileged execution, deep scan controls, or auditing. Server registration does not test connectivity or validate host keys. Do not treat this release as production-ready provisioning.
