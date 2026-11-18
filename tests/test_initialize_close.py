"""Real SQLite lifetime regressions; retained references prevent GC hiding leaks."""
import gc
import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from leak_rehearsal import recovery


class InitializeLifetime(unittest.TestCase):
    def exercise(self, failure=None):
        connections = []
        original_connect = sqlite3.connect

        class Tracked(sqlite3.Connection):
            closes = 0

            def execute(self, sql, *args, **kwargs):
                if failure and sql.startswith('INSERT INTO reports'):
                    raise failure('synthetic failure')
                return super().execute(sql, *args, **kwargs)

            def close(self):
                self.closes += 1
                return super().close()

        def connect(*args, **kwargs):
            connection = original_connect(*args, factory=Tracked, **kwargs)
            connections.append(connection)
            return connection

        was_enabled = gc.isenabled()
        gc.disable()
        try:
            with tempfile.TemporaryDirectory() as directory:
                for i in range(12):
                    path = Path(directory) / f'{i}.sqlite'
                    with patch.object(recovery.sqlite3, 'connect', connect):
                        if failure:
                            expected = recovery.Invalid if issubclass(failure, Exception) else failure
                            with self.assertRaises(expected) as raised:
                                recovery.initialize(path)
                            if expected is recovery.Invalid:
                                self.assertEqual(str(raised.exception), 'Initialization incomplete.')
                        else:
                            self.assertEqual(recovery.initialize(path), {'initialized': True})
                    connection = connections[-1]
                    self.assertEqual(connection.closes, 1)
                    with self.assertRaises(sqlite3.ProgrammingError):
                        connection.execute('SELECT 1')
                    self.assertTrue(path.is_file())  # Never auto-delete partial output.
                    check = original_connect(path)
                    try:
                        rows = check.execute('SELECT * FROM meta').fetchall()
                        self.assertEqual(rows, [] if failure else [(1, 'old')])
                        self.assertEqual(check.execute('SELECT * FROM reports').fetchall(),
                                         [] if failure else [(1, 'PUBLIC_SYNTHETIC_REPORT_v1')])
                    finally:
                        check.close()
                self.assertEqual(len(connections), 12)
        finally:
            if was_enabled:
                gc.enable()
            for connection in connections:
                if connection.closes == 0:
                    connection.close()

    def test_success_commits_and_closes_without_gc(self):
        self.exercise()

    def test_sql_failure_rolls_back_closes_and_preserves_partial(self):
        self.exercise(sqlite3.OperationalError)

    def test_interruption_rolls_back_closes_and_propagates(self):
        self.exercise(KeyboardInterrupt)

    def test_connect_failure_is_controlled_and_preserves_partial(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'partial.sqlite'
            with patch.object(recovery.sqlite3, 'connect', side_effect=sqlite3.OperationalError('private')):
                with self.assertRaisesRegex(recovery.Invalid, '^Initialization incomplete[.]$'):
                    recovery.initialize(path)
            self.assertEqual(path.read_bytes(), b'')


if __name__ == '__main__':
    unittest.main()
