import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path

from examples.secure_coding.python_examples import (
    find_user,
    read_upload,
    render_search_text,
)


class SecureCodingExamplesTests(unittest.TestCase):
    def test_user_id_is_bound_as_data_instead_of_sql(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            database_path = Path(temp_dir) / "users.sqlite"
            with closing(sqlite3.connect(database_path)) as connection:
                with connection:
                    connection.execute(
                        "CREATE TABLE users (id INTEGER PRIMARY KEY, display_name TEXT)"
                    )
                    connection.executemany(
                        "INSERT INTO users (id, display_name) VALUES (?, ?)",
                        [(1, "Alice"), (2, "Bob")],
                    )

            self.assertIsNone(find_user(database_path, "1 OR 1=1"))
            self.assertEqual(find_user(database_path, 1), (1, "Alice"))

    def test_search_text_is_html_escaped(self):
        self.assertEqual(
            render_search_text('<script>alert("x")</script>'),
            "&lt;script&gt;alert(&quot;x&quot;)&lt;/script&gt;",
        )

    def test_upload_reader_allows_root_file_and_blocks_parent_path(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            root = Path(temp_dir) / "uploads"
            root.mkdir()
            (root / "safe.txt").write_bytes(b"safe")

            self.assertEqual(read_upload(root, "safe.txt"), b"safe")
            with self.assertRaises(ValueError):
                read_upload(root, "../outside.txt")

    def test_upload_reader_blocks_symlink_outside_root(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            base = Path(temp_dir)
            root = base / "uploads"
            root.mkdir()
            outside = base / "outside.txt"
            outside.write_bytes(b"outside")
            link = root / "linked.txt"
            try:
                link.symlink_to(outside)
            except (OSError, NotImplementedError) as error:
                self.skipTest(f"symlink creation is unavailable: {error}")

            with self.assertRaises(ValueError):
                read_upload(root, "linked.txt")


if __name__ == "__main__":
    unittest.main()
