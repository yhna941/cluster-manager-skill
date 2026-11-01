# Permissions

`permissions audit --server HOST --path /disk1/RA` reports mount and Unix metadata. `permissions set --server HOST --path /disk1/RA --group RA --mode 2770` plans a nonrecursive root-owned workspace change. Supported workspace modes are 2770 and 2775. Child files and homes are not changed. Existing ACLs/default ACL inheritance are refused rather than silently changing ACL masks.

The worker uses directory file descriptors with O_NOFOLLOW, checks expected inode/device/ownership/mode and mount identity, and verifies afterward. setgid supplies group inheritance; umask and Samba creation masks still affect new files. Home migration, recursive ownership and immutable-attribute changes are outside this release.
