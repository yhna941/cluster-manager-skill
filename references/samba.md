# Existing-share policy

Samba configuration is read-only. `samba shares --server NAME` runs testparm inspection; `samba audit --server NAME --path /disk1/RA` combines parent-share policy with filesystem information. `samba users` enumerates local passdb names, never hashes.

For an existing share with `path=/disk1`, `valid users=@smbuser`, `read only=no`, a user can receive both `RA` and `smbuser` memberships. `user add-group alice RA` and `user add-group alice smbuser` are separate explicit plans. `samba user-add alice` provisions the Samba account; the user must already exist locally. Membership changes can require reconnecting SMB sessions.

Unix mode 2770 restricts group access; 2775 permits others to read/traverse. A share's read-only/write-list rules may still prohibit writing. `force user` overrides filesystem identity and is refused for new private/group paths. `force group`, ACLs, masks, guest access, dynamic paths and active sessions need review; configuration diagnostics do not prove SMB authentication. A private 0700 home can have a visible name. The application never changes hide-unreadable or other share settings.

Missing Samba is reported; no package installation, service reload, firewall edit or new share occurs. Standalone tdbsam/smbpasswd are supported; central/domain authentication and Unix password synchronization configurations are refused for mutation.

Reference: [Samba smb.conf manual](https://www.samba.org/samba/docs/current/man-html/smb.conf.5.html).
