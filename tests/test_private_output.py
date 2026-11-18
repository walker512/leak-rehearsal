"""Synthetic filesystem regression tests; no real secrets or external services."""
import concurrent.futures
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from leak_rehearsal import core

class PrivateOutput(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name)

    @unittest.skipUnless(os.name=='posix','POSIX modes; Windows ACL not validated')
    def test_umask_cli_and_bytes(self):
        code="""import os
from leak_rehearsal import core
os.umask(0o022)
core.generate('fixtures')
core.audit('fixtures/capture-catalogue.json','report')
core.verify('report','fixtures/capture-catalogue.json')
"""
        env=dict(os.environ,PYTHONPATH=str(Path(core.__file__).resolve().parent.parent))
        p=subprocess.run([sys.executable,'-c',code],cwd=self.root,env=env,capture_output=True)
        self.assertEqual(p.returncode,0,p.stderr)
        for directory in (self.root/'fixtures',self.root/'report'):
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode),0o700)
            for f in directory.iterdir():self.assertEqual(stat.S_IMODE(f.stat().st_mode),0o600)
        r=core.analyze(core.read(self.root/'fixtures/capture-catalogue.json'))
        self.assertEqual((self.root/'report/report.json').read_bytes(),core.canonical(r))
        self.assertEqual((self.root/'report/review.md').read_bytes(),core.review(r))

    def test_existing_directory_preserved(self):
        out=self.root/'out';out.mkdir();marker=out/'keep';marker.write_bytes(b'old')
        before=out.stat().st_mode
        with self.assertRaises(FileExistsError):core.new_files(out,{'report.json':b'new'})
        self.assertEqual(marker.read_bytes(),b'old');self.assertEqual(out.stat().st_mode,before)
        self.assertEqual(list(out.iterdir()),[marker])

    def test_existing_file_preserved(self):
        out=self.root/'out';out.write_bytes(b'old')
        with self.assertRaises(FileExistsError):core.new_files(out,{'x':b'new'})
        self.assertEqual(out.read_bytes(),b'old')

    def test_output_symlinks_preserved(self):
        target=self.root/'target';target.mkdir()
        for name,dest in [('link',target),('dangling',self.root/'absent')]:
            link=self.root/name
            try:link.symlink_to(dest,target_is_directory=True)
            except OSError as e:self.skipTest(str(e))
            with self.assertRaises(FileExistsError):core.new_files(link,{'x':b'new'})
            self.assertTrue(link.is_symlink())
        self.assertEqual(list(target.iterdir()),[])

    def test_member_symlink_race_never_followed(self):
        target=self.root/'target';target.write_bytes(b'keep');out=self.root/'out'
        original=os.open
        def intercepted(path,flags,mode=0o777,*args,**kwargs):
            if Path(path)==out/'x':
                try:Path(path).symlink_to(target)
                except OSError as e:self.skipTest(str(e))
            return original(path,flags,mode,*args,**kwargs)
        with patch.object(core.os,'open',side_effect=intercepted):
            with self.assertRaises(FileExistsError):core.new_files(out,{'x':b'new'})
        self.assertEqual(target.read_bytes(),b'keep')

    def test_concurrent_reservation(self):
        out=self.root/'out'
        def attempt(i):
            try:core.new_files(out,{'x':str(i).encode(),'y':str(i).encode()});return i
            except FileExistsError:return None
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            winners=[i for i in pool.map(attempt,range(16)) if i is not None]
        self.assertEqual(len(winners),1)
        self.assertEqual((out/'x').read_bytes(),str(winners[0]).encode())
        self.assertEqual((out/'y').read_bytes(),str(winners[0]).encode())

    def test_partial_failure_not_deleted_or_overwritten(self):
        out=self.root/'out';original=os.open
        def fail(path,*args,**kwargs):
            if Path(path)==out/'second':raise OSError('synthetic write failure')
            return original(path,*args,**kwargs)
        with patch.object(core.os,'open',side_effect=fail):
            with self.assertRaises(OSError):core.new_files(out,{'first':b'partial','second':b'next'})
        self.assertEqual((out/'first').read_bytes(),b'partial')
        with self.assertRaises(FileExistsError):core.new_files(out,{'first':b'retry'})
        self.assertEqual((out/'first').read_bytes(),b'partial')

    def test_reject_names_and_limit_before_mkdir(self):
        for name in ('../x','/x','a/b','a\\b','x:y','', '..','x\0y'):
            with self.assertRaises(core.Invalid):core.new_files(self.root/'out',{name:b'x'})
            self.assertFalse((self.root/'out').exists())
        with self.assertRaises(core.Invalid):core.new_files(self.root/'out',{'x':b'x'*(core.OUTPUT_LIMIT+1)})
        self.assertFalse((self.root/'out').exists())

if __name__=='__main__':unittest.main()
