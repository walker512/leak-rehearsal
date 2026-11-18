import json,os,sqlite3,subprocess,sys,tempfile,unittest
from pathlib import Path
from leak_rehearsal import recovery as r

class CapacityTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.db=Path(self.tmp.name)/'exercise.sqlite3';r.initialize(self.db)
    def fill(self,n=256):
        for _ in range(n):r.transact(self.db,'old-read')
    def snapshot(self):
        with sqlite3.connect(self.db) as c:
            return c.execute('SELECT * FROM events ORDER BY seq').fetchall(),c.execute("SELECT revoked FROM credentials WHERE alias='old'").fetchone()[0]
    def test_full_old_baseline_and_reserved_revoke(self):
        self.fill();events,revoked=self.snapshot();self.assertEqual(revoked,0)
        result=r.client(self.db,'revoke-old')
        self.assertEqual(result,{'status':'revoked','audit':'reserved_containment_entry'})
        after,revoked=self.snapshot();self.assertEqual(revoked,1);self.assertEqual(after[:256],events);self.assertEqual(len(after),257)
        self.assertEqual(after[-1][1],'revoke-old')
    def test_repeat_revoke_bounded_and_explicit(self):
        self.fill();r.client(self.db,'revoke-old');before=self.snapshot()
        for _ in range(3):self.assertEqual(r.client(self.db,'revoke-old'),{'status':'revoked','audit':'existing_containment_entry'})
        self.assertEqual(self.snapshot(),before)
    def test_other_actions_fail_unchanged_at_capacity(self):
        self.fill();before=self.snapshot()
        for action in r.ACTIONS:
            if action!='revoke-old':
                with self.assertRaises(r.Invalid):r.transact(self.db,action)
        self.assertEqual(self.snapshot(),before)
    def test_after_reserved_other_actions_fail_unchanged(self):
        self.fill();r.transact(self.db,'revoke-old');before=self.snapshot()
        for action in r.ACTIONS:
            if action!='revoke-old':
                with self.assertRaises(r.Invalid):r.transact(self.db,action)
        self.assertEqual(self.snapshot(),before)
    def test_revoke_when_already_revoked_and_full(self):
        r.transact(self.db,'revoke-old');self.fill(255)
        self.assertEqual(r.client(self.db,'revoke-old')['audit'],'reserved_containment_entry')
        self.assertEqual(self.snapshot()[1],1)
    def test_255_normal_revoke_then_reserve(self):
        self.fill(255);self.assertEqual(r.transact(self.db,'revoke-old'),{'status':'revoked'})
        self.assertEqual(len(self.snapshot()[0]),256)
        self.assertEqual(r.client(self.db,'revoke-old')['audit'],'reserved_containment_entry')
    def test_corrupt_reserved_record_rejected(self):
        self.fill();r.transact(self.db,'revoke-old')
        with sqlite3.connect(self.db) as c:c.execute("UPDATE events SET action='issue' WHERE seq=257")
        with self.assertRaises(r.Invalid):r.client(self.db,'revoke-old')
    def test_reserved_record_with_unrevoked_state_rejected(self):
        self.fill();r.transact(self.db,'revoke-old')
        with sqlite3.connect(self.db) as c:c.execute("UPDATE credentials SET revoked=0 WHERE alias='old'")
        with self.assertRaises(r.Invalid):r.client(self.db,'revoke-old')
    def test_overflow_rejected(self):
        self.fill();r.transact(self.db,'revoke-old')
        with sqlite3.connect(self.db) as c:c.execute('INSERT INTO events VALUES (258,?,?)',('revoke-old',r.core.canonical({'status':'revoked'}).decode()))
        with self.assertRaises(r.Invalid):r.client(self.db,'revoke-old')
    def test_actual_cli(self):
        self.fill();p=subprocess.run([sys.executable,'-m','leak_rehearsal.recovery','act','--db',str(self.db),'revoke-old'],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr);self.assertEqual(json.loads(p.stdout)['audit'],'reserved_containment_entry')
        p=subprocess.run([sys.executable,'-m','leak_rehearsal.recovery','probe','--db',str(self.db)],capture_output=True,text=True)
        self.assertEqual(p.returncode,2);self.assertNotIn(str(self.db),p.stderr)
    def test_concurrent_fixed_workers_single_reserved_entry(self):
        import concurrent.futures
        self.fill();before=self.snapshot()[0]
        def call(_):
            try:return r.client(self.db,'revoke-old')
            except r.Invalid:return {'status':'bounded_failure'}
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:results=list(pool.map(call,range(8)))
        # The existing conservative sidecar guard can refuse an overlapping worker.
        # Refusal is not success; retry explicitly after all workers have stopped.
        if not any(x['status']=='revoked' for x in results):r.client(self.db,'revoke-old')
        final=r.client(self.db,'revoke-old');self.assertEqual(final['audit'],'existing_containment_entry')
        events,revoked=self.snapshot();self.assertEqual(len(events),257);self.assertEqual(events[:256],before);self.assertEqual(revoked,1)
        self.assertLessEqual(sum(x.get('audit')=='reserved_containment_entry' for x in results),1)
    def test_insert_and_commit_failure_roll_back_containment(self):
        from unittest.mock import patch
        self.fill();before=self.snapshot();connect=r.connect
        for failure in ('insert','commit'):
            class Proxy:
                def __init__(self,c):self.c=c
                def execute(self,sql,*args):
                    if failure=='insert' and sql.startswith('INSERT INTO events'):raise sqlite3.OperationalError('synthetic insert failure')
                    return self.c.execute(sql,*args)
                def commit(self):
                    if failure=='commit':raise sqlite3.OperationalError('synthetic commit failure')
                    return self.c.commit()
                def close(self):return self.c.close()
            with patch.object(r,'connect',side_effect=lambda p:Proxy(connect(p))):
                with self.assertRaises(sqlite3.OperationalError):r.transact(self.db,'revoke-old')
            self.assertEqual(self.snapshot(),before)
        self.assertEqual(r.client(self.db,'revoke-old')['audit'],'reserved_containment_entry')
    def test_redaction_protocol_not_widened(self):
        self.fill();result=r.client(self.db,'revoke-old')
        self.assertNotIn(str(self.db),json.dumps(result))
        for token in r.TOKENS.values():self.assertNotIn(token,json.dumps(result))
