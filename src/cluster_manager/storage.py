"""Bounded, read-only remote file scan. No paths are passed as shell syntax."""

from __future__ import annotations

import asyncio
import json
import shlex
from pathlib import PurePosixPath
from typing import Any

import asyncssh

from .models import Server

# Constant code; parameters are separate quoted command arguments, never interpolated into code.
SCANNER = r"""import heapq,json,os,stat,sys,time
root=sys.argv[1]; minimum=int(sys.argv[2]); days=int(sys.argv[3]); limit=int(sys.argv[4]); max_entries=int(sys.argv[5]); seconds=int(sys.argv[6]); max_depth=int(sys.argv[7])
start=time.monotonic(); cutoff=time.time()-days*86400; count=0; errors=0; complete=True; heap=[]; stack=[((),0)]
rootfd=None
try:
    rootfd=os.open('/',os.O_RDONLY|os.O_DIRECTORY)
    for part in root.split('/'):
        if not part: continue
        child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=rootfd)
        os.close(rootfd); rootfd=child
    device=os.fstat(rootfd).st_dev
    while stack:
        if time.monotonic()-start >= seconds or count >= max_entries: complete=False; break
        parts,depth=stack.pop(); fd=os.dup(rootfd)
        try:
            for part in parts:
                child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
                os.close(fd); fd=child
            if os.fstat(fd).st_dev != device: continue
            with os.scandir(fd) as entries:
                for entry in entries:
                    if time.monotonic()-start >= seconds or count >= max_entries: complete=False; break
                    count+=1
                    try:
                        info=entry.stat(follow_symlinks=False)
                        if info.st_dev != device or stat.S_ISLNK(info.st_mode): continue
                        if stat.S_ISDIR(info.st_mode):
                            if depth < max_depth: stack.append((parts+(entry.name,),depth+1))
                            else: complete=False
                        elif stat.S_ISREG(info.st_mode) and info.st_size >= minimum and (days == 0 or info.st_mtime <= cutoff):
                            path=os.path.join(root,*parts,entry.name)
                            row=(info.st_size,path,info.st_uid,info.st_gid,info.st_mtime,info.st_blocks*512)
                            if len(heap)<limit: heapq.heappush(heap,row)
                            elif row>heap[0]: heapq.heapreplace(heap,row)
                    except OSError: errors+=1; complete=False
        except OSError: errors+=1; complete=False
        finally: os.close(fd)
    print(json.dumps({'files':[{'path':p,'size_bytes':s,'allocated_bytes':a,'uid':u,'gid':g,'mtime':m} for s,p,u,g,m,a in sorted(heap,reverse=True)],'entries_scanned':count,'errors':errors,'complete':complete,'elapsed_seconds':round(time.monotonic()-start,3),'review_candidates':days>0}))
except (OSError,ValueError) as exc:
    print(json.dumps({'error':str(exc),'complete':False})); sys.exit(2)
finally:
    if rootfd is not None: os.close(rootfd)
"""


def scan_command(
    path: str, minimum: int, days: int, limit: int, entries: int, seconds: int, depth: int
) -> str:
    p = PurePosixPath(path)
    if not p.is_absolute() or str(p) != path or ".." in p.parts or "\x00" in path:
        raise ValueError("path must be canonical and absolute")
    if not (
        0 <= minimum <= 2**63 - 1
        and 0 <= days <= 36500
        and 1 <= limit <= 1000
        and 1 <= entries <= 1_000_000
        and 1 <= seconds <= 120
        and 0 <= depth <= 50
    ):
        raise ValueError("scan limits are out of range")
    return shlex.join(
        [
            "python3",
            "-c",
            SCANNER,
            path,
            str(minimum),
            str(days),
            str(limit),
            str(entries),
            str(seconds),
            str(depth),
        ]
    )


async def scan(
    server: Server,
    path: str,
    minimum: int,
    days: int,
    limit: int,
    entries: int,
    seconds: int,
    depth: int,
    password: str | None,
) -> dict[str, Any]:
    command = scan_command(path, minimum, days, limit, entries, seconds, depth)
    kwargs: dict[str, Any] = {
        "username": server.ssh.username,
        "port": server.port,
        "connect_timeout": 10,
        "login_timeout": 15,
    }
    if server.ssh.auth == "password":
        kwargs.update(password=password, client_keys=[], preferred_auth="password")
    else:
        kwargs.update(preferred_auth="publickey")
    async with asyncssh.connect(server.host, **kwargs) as connection:
        result = await asyncio.wait_for(connection.run(command, check=False), seconds + 15)
    if result.exit_status != 0:
        raise RuntimeError("remote scan failed; check path and python3 availability")
    if result.stdout is None:
        raise ValueError("empty scan output")
    data = json.loads(result.stdout)
    if not isinstance(data, dict):
        raise TypeError("invalid scan output")
    return data
