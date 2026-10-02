"""POSIX descriptor-relative no-follow snapshot of one explicitly supplied file."""

import os
import stat


class InputOpen(Exception):
    def __init__(self, code):
        self.code = code


def read_snapshot(path, maximum):
    flags = ("O_DIRECTORY", "O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK")
    if (
        os.name != "posix"
        or not all(hasattr(os, name) for name in flags)
        or os.open not in os.supports_dir_fd
    ):
        raise InputOpen("snapshot_platform_unsupported")
    if type(path) is not str or not path or "\0" in path or ".." in path.split(os.sep):
        raise InputOpen("invalid_input_path")
    if type(maximum) is not int or maximum < 1:
        raise InputOpen("invalid_input_budget")
    absolute = os.path.abspath(path)
    parts = absolute.split(os.sep)[1:]
    if not parts or not parts[-1]:
        raise InputOpen("invalid_input_path")
    handles = []
    try:
        directory_flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        current = os.open(os.sep, directory_flags)
        handles.append(current)
        for component in parts[:-1]:
            if not component:
                continue
            current = os.open(component, directory_flags, dir_fd=current)
            handles.append(current)
        target = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC | os.O_NONBLOCK, dir_fd=current
        )
        handles.append(target)
        before = os.fstat(target)
        if not stat.S_ISREG(before.st_mode):
            raise InputOpen("input_not_regular_file")
        if before.st_size > maximum:
            raise InputOpen("input_bytes_budget")
        chunks, total = [], 0
        while True:
            chunk = os.read(target, min(65536, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum:
                raise InputOpen("input_bytes_budget")
        after = os.fstat(target)

        def identity(item):
            return (
                item.st_dev,
                item.st_ino,
                item.st_mode,
                item.st_size,
                item.st_mtime_ns,
                item.st_ctime_ns,
            )

        if identity(before) != identity(after) or total != after.st_size:
            raise InputOpen("input_changed_during_snapshot")
        return b"".join(chunks)
    except (OSError, ValueError):
        raise InputOpen("input_snapshot_unavailable") from None
    finally:
        for descriptor in reversed(handles):
            os.close(descriptor)
