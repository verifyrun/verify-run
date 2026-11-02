"""Permission repair only for a private, single-writer disposable fixture tree.

Open relative to held directory descriptors; never follow links. Reject multiply
linked files. Concurrent hostile writers with the same OS identity are outside
this test harness's trust boundary; it is not an application isolation backend.
"""
import os
import stat


def make_disposable_writable(copy, temporary_root):
    if copy.parent != temporary_root or copy.name in ('', '.', '..'):
        raise ValueError('copy must be an immediate disposable child')
    flags = os.O_RDONLY | os.O_NOFOLLOW
    directory_flags = flags | os.O_DIRECTORY

    def visit(fd):
        info = os.fstat(fd)
        if stat.S_ISDIR(info.st_mode):
            for name in os.listdir(fd):
                info = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if not (stat.S_ISDIR(info.st_mode) or stat.S_ISREG(info.st_mode)):
                    raise ValueError('links and special files are unsupported')
                child = os.open(name, flags | (os.O_DIRECTORY if stat.S_ISDIR(info.st_mode) else 0), dir_fd=fd)
                try:
                    visit(child)
                finally:
                    os.close(child)
            os.fchmod(fd, 0o700)
        elif stat.S_ISREG(info.st_mode) and info.st_nlink == 1:
            os.fchmod(fd, 0o600)
        else:
            raise ValueError('multiply linked or special file is unsupported')

    root_fd = os.open(temporary_root, directory_flags)
    try:
        copy_fd = os.open(copy.name, directory_flags, dir_fd=root_fd)
        try:
            visit(copy_fd)
        finally:
            os.close(copy_fd)
    finally:
        os.close(root_fd)
