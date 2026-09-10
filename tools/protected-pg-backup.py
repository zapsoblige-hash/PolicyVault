#!/usr/bin/env python3
"""Capture pg_dump stdout privately, validate it, then export for one operator.

Commands are JSON argv arrays, never shell strings. The validator receives the
dump on stdin (for example docker run --rm -i postgres:16-alpine pg_restore -l).
Credentials belong in the child's inherited environment, never command output.
This helper does not restore databases or change existing dump contents.
"""
import argparse
import datetime
import hashlib
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys


def utc():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def trusted_directory(fd):
    """Only root/the caller may control a pathname component or rename children."""
    info = os.fstat(fd)
    if info.st_uid not in (0, os.geteuid()):
        raise PermissionError("directory ancestry must belong to root or the invoking user")
    if info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX:
        raise PermissionError("writable directory ancestry requires the sticky bit")


def open_directory(path):
    """Open trusted ancestry without symlinks, retaining a directory fd."""
    if not os.path.isabs(path) or ".." in path.split("/"):
        raise ValueError("directory must be an absolute path without '..'")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        trusted_directory(fd)
        for component in filter(None, path.split("/")):
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            trusted_directory(fd)
        return fd
    except BaseException:
        os.close(fd)
        raise


def exclusive(fd, name):
    result = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
    os.fchmod(result, 0o600)
    return result


def digest(fd):
    os.lseek(fd, 0, os.SEEK_SET)
    h = hashlib.sha256()
    while chunk := os.read(fd, 1024 * 1024):
        h.update(chunk)
    os.lseek(fd, 0, os.SEEK_SET)
    return h.hexdigest()


def backup(directory, export_parent, name, operator, dump_command, validate_command):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*\.dump", name):
        raise ValueError("invalid dump basename")
    for command in (dump_command, validate_command):
        if not isinstance(command, list) or not command or not all(isinstance(x, str) for x in command):
            raise ValueError("commands must be nonempty JSON argv arrays")
    account = pwd.getpwnam(operator)
    # Validate both pathnames before producing any snapshot. Reopen below only
    # through the same trusted ancestry; no unrelated UID may replace a child.
    export_check = open_directory(export_parent)
    os.close(export_check)
    parent_path, leaf = os.path.split(directory.rstrip("/"))
    parent = open_directory(parent_path)
    try:
        try:
            os.mkdir(leaf, 0o700, dir_fd=parent)
        except FileExistsError:
            pass
        source_dir = os.open(leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    finally:
        os.close(parent)
    source = export_root = export_dir = export_file = pointer = None
    partial = ".partial-" + secrets.token_hex(16)
    export_leaf = "pv-backup-export-" + secrets.token_hex(16)
    pointer_tmp = ".latest-" + secrets.token_hex(16)
    try:
        if os.fstat(source_dir).st_uid != os.geteuid():
            raise PermissionError("backup directory must belong to the invoking user")
        os.fchmod(source_dir, 0o700)
        # Refuse collisions before running pg_dump; link below repeats this
        # atomically at publication, so a concurrent writer cannot be clobbered.
        try:
            os.stat(name, dir_fd=source_dir, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise FileExistsError("backup destination already exists")
        source = exclusive(source_dir, partial)
        started = utc()
        result = subprocess.run(dump_command, stdout=source, stderr=subprocess.PIPE)
        ended = utc()
        if result.returncode or not os.fstat(source).st_size:
            raise RuntimeError("dump failed or was empty; private partial retained")
        os.fsync(source)
        os.lseek(source, 0, os.SEEK_SET)
        check = subprocess.run(validate_command, stdin=source, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if check.returncode:
            raise RuntimeError("dump validation failed; private partial retained")
        table_entries = check.stdout.count(b"TABLE DATA")
        if not table_entries:
            raise RuntimeError("dump validation has no TABLE DATA entries; private partial retained")
        sha = digest(source)
        os.link(partial, name, src_dir_fd=source_dir, dst_dir_fd=source_dir, follow_symlinks=False)
        os.unlink(partial, dir_fd=source_dir)
        os.fsync(source_dir)

        # A shared temporary parent is allowed only with the sticky bit. The
        # new random child stays private and owned by this process until ready.
        export_root = open_directory(export_parent)
        os.mkdir(export_leaf, 0o700, dir_fd=export_root)
        export_dir = os.open(export_leaf, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=export_root)
        if os.fstat(export_dir).st_uid != os.geteuid():
            raise PermissionError("new export directory must belong to the invoking user")
        os.fchmod(export_dir, 0o700)
        export_file = exclusive(export_dir, name)
        while chunk := os.read(source, 1024 * 1024):
            view = memoryview(chunk)
            while view:
                view = view[os.write(export_file, view):]
        os.fsync(export_file)
        if digest(export_file) != sha:
            raise RuntimeError("export hash mismatch")
        os.fchown(export_file, account.pw_uid, account.pw_gid)
        os.fsync(export_dir)
        # Nothing beneath this directory is accessed after ownership handoff.
        os.fchown(export_dir, account.pw_uid, account.pw_gid)
        os.fsync(export_root)

        pointer = exclusive(source_dir, pointer_tmp)
        os.write(pointer, (name + "\n").encode())
        os.fsync(pointer)
        os.replace(pointer_tmp, "latest-dump.txt", src_dir_fd=source_dir, dst_dir_fd=source_dir)
        os.fsync(source_dir)
        return {"dumpStartedAt": started, "dumpCompletedAt": ended,
                "snapshotLimit": "Consistent snapshot acquired during pg_dump; exact acquisition boundary unrecorded. No later-write inclusion claim.",
                "backup": os.path.join(directory, name),
                "operatorCopy": os.path.join(export_parent, export_leaf, name),
                "sha256": sha, "bytes": os.fstat(source).st_size,
                "tableDataEntries": table_entries, "fileMode": "0600", "directoryMode": "0700"}
    finally:
        for fd in (pointer, export_file, export_dir, export_root, source, source_dir):
            if fd is not None:
                os.close(fd)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-dir", required=True)
    parser.add_argument("--export-parent", required=True)
    parser.add_argument("--name", required=True)
    parser.add_argument("--operator", required=True)
    parser.add_argument("--dump-command-json", required=True)
    parser.add_argument("--validate-command-json", required=True)
    args = parser.parse_args()
    try:
        result = backup(args.backup_dir, args.export_parent, args.name, args.operator,
                        json.loads(args.dump_command_json), json.loads(args.validate_command_json))
    except Exception as error:
        # Child stderr may include sensitive connection context; do not echo it.
        print(json.dumps({"error": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 1
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
