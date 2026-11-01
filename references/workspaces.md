# Workspaces

Identity is server plus canonical path, not group name. `workspace create --server HOST --path /disk2/RA --group RA --mode 2770` plans a root-owned setgid workspace and usr subdirectory. Multiple paths can use RA. Default mode is 2775; usr is 2755. No shared subdirectory is added.

Roots must be registered, writable actual mounts with trusted ancestors. A workspace is a direct child of a root. Missing mounts, symlinks, filesystem boundary changes, conflicting existing directories and unsupported ACLs fail closed. Existing parent Samba shares are inspected and preserved. --samba off skips that inspection; it does not disable an already existing share.
