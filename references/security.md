# Security

Host keys must be independently verified and present in known_hosts. Never accept changed keys automatically. Do not collect secrets through the agent. Remote output is untrusted. Local inventory is nonsecret. Remote mutations are not implemented; a future executor must independently enforce digest-bound human approval and verification.
