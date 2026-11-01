# Storage

Use storage summary and storage inodes for df-style observations. storage large-files --server HOST --path /disk1 --min-bytes N --days N returns bounded large/old file candidates. It does not cross filesystem boundaries or follow symlinks by default. Defaults are 100000 entries, 30 seconds and depth 10. Explain complete=false and errors. Do not treat old mtime as proof of disuse; ctime is not creation time. Apparent size and allocated bytes differ for sparse files. No deletion, mount, format or recurring scan operation exists.
