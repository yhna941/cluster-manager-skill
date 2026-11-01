# Local identities

`user create NAME --server HOST --group GROUP --home /disk1/GROUP/usr/NAME --samba` creates a plan. Missing groups/workspaces must be created and applied first. The account begins locked; the private home is created without skeleton files, then initial passwords are set through secret stdin. Existing users are never silently overwritten or reset by a create operation. Without --home no home directory is created. --no-password leaves the account locked.

Use user password, add-group, remove-group, lock and unlock for explicit changes. Group additions are additive. Primary-group removal is refused. Password locking does not disable SSH keys. Root/system accounts and non-files/systemd NSS providers are unsupported for mutation. Password-status verification does not prove that a login works.
