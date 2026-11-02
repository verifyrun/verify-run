"""New harness evidence, separate from historical kit assertions."""
from pathlib import Path
import os
import stat
import tempfile
import unittest
from tools.frozen_fixture_permissions import make_disposable_writable


class DisposablePermissions(unittest.TestCase):
    def test_plain_copy_writable(self):
        with tempfile.TemporaryDirectory() as temp:
            root=Path(temp); copy=root/'copy';copy.mkdir(); file=copy/'file'
            file.write_text('fixture');file.chmod(0o444);copy.chmod(0o555)
            make_disposable_writable(copy,root)
            self.assertEqual(stat.S_IMODE(file.stat().st_mode),0o600)
            self.assertEqual(file.read_text(),'fixture')

    def test_links_never_change_outside_permissions(self):
        for kind in ['file_symlink','directory_symlink','hardlink','root_symlink']:
            with self.subTest(kind=kind),tempfile.TemporaryDirectory() as temp:
                root=Path(temp); outside=root/'outside';outside.mkdir();sentinel=outside/'sentinel'
                sentinel.write_text('keep');sentinel.chmod(0o444);copy=root/'copy'
                if kind=='root_symlink':copy.symlink_to(outside,target_is_directory=True)
                else:
                    copy.mkdir()
                    if kind=='hardlink':os.link(sentinel,copy/'link')
                    elif kind=='file_symlink':(copy/'link').symlink_to(sentinel)
                    else:(copy/'link').symlink_to(outside,target_is_directory=True)
                with self.assertRaises((ValueError,OSError)):make_disposable_writable(copy,root)
                self.assertEqual(stat.S_IMODE(sentinel.stat().st_mode),0o444)
                self.assertEqual(sentinel.read_text(),'keep')
                self.assertEqual(stat.S_IMODE(outside.stat().st_mode),0o755)
