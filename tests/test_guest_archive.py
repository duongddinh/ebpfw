import importlib.util
import io
from pathlib import Path
import tarfile
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('fetch', Path(__file__).with_name('fetch_ufw_root.py'))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)


class ExtractionSafety(unittest.TestCase):
    def test_absolute_guest_symlink_stays_inside_guest(self):
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            fetch.root = base / 'guest'
            fetch.root.mkdir()
            outside = base / 'outside'
            outside.mkdir()
            (outside / 'marker').write_text('untouched')
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                link = tarfile.TarInfo('redirect')
                link.type = tarfile.SYMTYPE
                link.linkname = str(outside)
                archive.addfile(link)
                entry = tarfile.TarInfo('redirect/marker')
                entry.size = 5
                archive.addfile(entry, io.BytesIO(b'guest'))
            fetch.extract(data.getvalue())
            self.assertEqual((outside / 'marker').read_text(), 'untouched')
            self.assertEqual(fetch.guest_path('redirect/marker').read_bytes(), b'guest')

    def test_parent_escape_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            fetch.root = Path(directory)
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                entry = tarfile.TarInfo('../escape')
                entry.size = 1
                archive.addfile(entry, io.BytesIO(b'x'))
            with self.assertRaises(RuntimeError):
                fetch.extract(data.getvalue())


if __name__ == '__main__':
    unittest.main()
