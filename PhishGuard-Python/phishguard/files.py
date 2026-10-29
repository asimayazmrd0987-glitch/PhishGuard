"""Durable, privacy-conscious file helpers.

History and editable data files are written through a temporary file in the
same directory followed by :func:`os.replace`.  A crash or full disk therefore
leaves the previous file intact instead of truncating it halfway through.
"""
from __future__ import annotations

import os
import tempfile
from pathlib import Path
from typing import Optional, Union

PathLike = Union[str, os.PathLike[str]]


def read_text_file(path: PathLike, encoding: str = 'utf-8-sig') -> str:
    """Read a UTF-8 text file, tolerating a byte-order mark."""
    return Path(path).read_text(encoding=encoding)


def atomic_write_text(
    path: PathLike,
    text: str,
    *,
    encoding: str = 'utf-8',
    mode: Optional[int] = 0o600,
) -> None:
    """Atomically replace ``path`` with ``text``.

    ``mode`` defaults to owner-only permissions because history can contain
    sensitive message fragments.  Pass ``mode=0o644`` for shareable data files.
    """
    target = Path(path)
    parent = target.parent if str(target.parent) else Path('.')
    if not parent.is_dir():
        raise OSError(f'parent directory does not exist: {parent}')

    descriptor = -1
    temporary: Optional[Path] = None
    try:
        descriptor, temp_name = tempfile.mkstemp(
            dir=str(parent), prefix=f'.{target.name}.', suffix='.tmp'
        )
        temporary = Path(temp_name)
        with os.fdopen(descriptor, 'w', encoding=encoding, newline='\n') as output:
            descriptor = -1
            output.write(text)
            output.flush()
            os.fsync(output.fileno())
        if mode is not None:
            try:
                os.chmod(temporary, mode)
            except OSError:
                pass
        os.replace(temporary, target)
        temporary = None
        _fsync_directory(parent)
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary is not None:
            try:
                temporary.unlink()
            except OSError:
                pass


def _fsync_directory(directory: Path) -> None:
    """Best-effort directory sync so a rename survives a sudden power loss."""
    flags = getattr(os, 'O_DIRECTORY', 0) | os.O_RDONLY
    try:
        descriptor = os.open(str(directory), flags)
    except OSError:
        return
    try:
        os.fsync(descriptor)
    except OSError:
        pass
    finally:
        os.close(descriptor)


__all__ = ['PathLike', 'read_text_file', 'atomic_write_text']
