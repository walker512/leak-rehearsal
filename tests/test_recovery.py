import copy,json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from leak_rehearsal import recovery as r,core
class RecoveryTests(unittest.TestCase):
 def setUp(self):
  self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.root=Path(self.tmp.name);self.db=self.root/'db';r.initialize(self.db)
 def act(self,a):return r.client(self.db,a)
 def test_initial(self):
  self.assertEqual(self.act('app-read')['status'],'ok');self.assertEqual(self.act('old-read')['status'],'ok');self.assertEqual(self.act('replacement-read')['reason'],'not_issued')
 def test_redaction_not_revocation(self):
  self.assertEqual(core.analyze(core.canonical(core.demo_capture('catalogue')))['status'],'corpus_pass');self.assertEqual(self.act('old-read')['status'],'ok')
 def test_outage_and_restore(self):
  self.act('issue');self.act('revoke-old');self.assertEqual(self.act('app-read')['reason'],'revoked');self.act('switch-replacement');self.assertTrue(r.probe(self.db)['recovery_ready'])
 def test_irreversible(self):
  self.act('issue');self.act('revoke-old');self.act('issue');self.act('revoke-old');self.act('switch-old');self.assertEqual(self.act('old-read')['reason'],'revoked');self.assertEqual(self.act('app-read')['reason'],'revoked')
 def test_scopes_and_unchanged(self):
  self.act('issue');self.assertEqual(self.act('replacement-write')['status'],'forbidden');self.assertEqual(self.act('replacement-delete')['status'],'forbidden')
  with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT * FROM reports').fetchall(),[(1,'PUBLIC_SYNTHETIC_REPORT_v1')])
 def test_issue_idempotent(self):
  self.assertEqual(self.act('issue'),self.act('issue'))
  with sqlite3.connect(self.db) as c:self.assertEqual(c.execute('SELECT COUNT(*) FROM credentials').fetchone()[0],2)
 def test_switch_missing(self):self.assertEqual(self.act('switch-replacement')['status'],'not_issued')
 def test_probe_initial_not_green(self):self.assertFalse(r.probe(self.db)['recovery_ready'])
 def test_demo_verify(self):
  p=self.root/'demo';self.assertTrue(r.demo(p)['exercise_pass']);self.assertEqual(r.verify(p),r.score(core.parse((p/'receipt.json').read_bytes())))
  for f in p.iterdir():
   data=f.read_bytes()
   for token in r.TOKENS.values():self.assertNotIn(token.encode(),data)
 def test_tamper(self):
  p=self.root/'demo';r.demo(p)
  for name in ['receipt.json','report.json','review.md']:
   f=p/name;b=f.read_bytes();f.write_bytes(b+b' ')
   with self.assertRaises(core.Invalid):r.verify(p)
   f.write_bytes(b)
 def test_missing_reordered(self):
  p=self.root/'demo';r.demo(p);receipt=core.parse((p/'receipt.json').read_bytes())
  for bad in [None,[],True,{'schema':True,**{k:v for k,v in receipt.items() if k!='schema'}}]:
   with self.assertRaises(core.Invalid):r.score(bad)
  b=copy.deepcopy(receipt);b['scenarios'][0]['steps'].pop()
  with self.assertRaises(core.Invalid):r.score(b)
  b=copy.deepcopy(receipt);b['scenarios'].reverse()
  with self.assertRaises(core.Invalid):r.score(b)
 def test_recorded_failure_not_pass(self):
  p=self.root/'demo';r.demo(p);x=core.parse((p/'receipt.json').read_bytes());x['scenarios'][0]['steps'][0]['result']={'status':'unauthorized','reason':'revoked'};self.assertFalse(r.score(x)['exercise_pass'])
 def test_existing_no_overwrite(self):
  b=self.db.read_bytes()
  with self.assertRaises(OSError):r.initialize(self.db)
  self.assertEqual(b,self.db.read_bytes())
  with self.assertRaises(core.Invalid):r.demo(self.db)
 def test_unknown_action(self):
  for a in ['enable-old','http://example.invalid','REAL_KEY','old-delete']:
   with self.assertRaises(core.Invalid):self.act(a)
 def test_schema_rejection(self):
  with sqlite3.connect(self.db) as c:c.execute('CREATE TABLE foreign_data (x)')
  with self.assertRaises(core.Invalid):self.act('old-read')
 def test_sidecar_rejection(self):
  Path(str(self.db)+'-wal').write_bytes(b'')
  with self.assertRaises(core.Invalid):self.act('old-read')
 def test_special_files(self):
  link=self.root/'link';link.symlink_to(self.db)
  with self.assertRaises(core.Invalid):r.client(link,'old-read')
  if hasattr(os,'mkfifo'):
   fifo=self.root/'fifo';os.mkfifo(fifo)
   with self.assertRaises(core.Invalid):r.client(fifo,'old-read')
 def test_size_and_corrupt(self):
  self.db.write_bytes(b'0'*(1024*1024+1))
  with self.assertRaises(core.Invalid):self.act('old-read')
  self.db.write_bytes(b'not sqlite')
  with self.assertRaises(core.Invalid):self.act('old-read')
 def test_limit_prevents_mutation(self):
  for i in range(256):r.transact(self.db,'old-read')
  with self.assertRaises(core.Invalid):self.act('revoke-old')
  with sqlite3.connect(self.db) as c:self.assertEqual(c.execute("SELECT revoked FROM credentials WHERE alias='old'").fetchone()[0],0)
 def test_cli(self):
  cmd=[sys.executable,'-m','leak_rehearsal.recovery']
  self.assertEqual(subprocess.run(cmd+['probe','--db',str(self.db)],capture_output=True).returncode,3)
  self.assertEqual(subprocess.run(cmd+['act','--db',str(self.db),'revoke-old'],capture_output=True).returncode,0)
  self.assertEqual(subprocess.run(cmd+['act','--db',str(self.root/'missing'),'old-read'],capture_output=True).returncode,2)
 def test_semantic_result_tamper(self):
  p=self.root/'demo';r.demo(p);x=core.parse((p/'receipt.json').read_bytes())
  step=next(y for y in x['scenarios'][0]['steps'] if y['action']=='switch-replacement');step['result']['consumer']='old';self.assertFalse(r.score(x)['exercise_pass'])
  x=core.parse((p/'receipt.json').read_bytes());x['scenarios'][0]['steps'][4]['result']['reason']='not_issued';self.assertFalse(r.score(x)['exercise_pass'])
 def test_review_explains(self):
  p=self.root/'demo';r.demo(p);text=(p/'review.md').read_text();self.assertIn('| Expected |',text);self.assertIn('unauthorized / revoked',text);self.assertIn('removing log text does not revoke',text)
 def test_strict_protocol(self):
  for raw in [b'{"x":1,"x":2}',b'{"x":NaN}',b'{"x":"\\ud800"}']:
   with self.assertRaises(core.Invalid):core.parse(raw)
if __name__=='__main__':unittest.main()
