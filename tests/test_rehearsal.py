"""Original synthetic cases; no real credentials or user logs."""
import copy,json,os,subprocess,sys,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from leak_rehearsal.core import *
ROOT=Path(__file__).resolve().parents[1]
def report(policy):return analyze(canonical(demo_capture(policy)))
class Tests(unittest.TestCase):
    def test_public_canary_not_provider_credential(self):
        self.assertTrue(CANARY.startswith('REHEARSAL_FAKE_KEY_'));self.assertEqual(len(corpus()['cases']),13)
    def test_no_redaction_leaks_all_eleven_positive_cases(self):
        r=report('none');self.assertEqual(r['status'],'failed')
        self.assertEqual(sum(bool(x['detected_forms']) for x in r['rows']),11)
        self.assertTrue(all(x['status']=='corpus_pass' for x in r['rows'] if x['stage']=='control'))
    def test_literal_cannot_remove_encoded_forms(self):
        r=report('literal');rows={x['case']:x for x in r['rows']}
        self.assertEqual(rows['config_dump']['status'],'corpus_pass');self.assertEqual(rows['split_write']['status'],'corpus_pass')
        self.assertEqual(rows['base64_export']['status'],'failed');self.assertEqual(rows['url_export']['status'],'failed')
    def test_chunkwise_redaction_misses_reassembled_plain_canary(self):
        rows={x['case']:x for x in report('chunkwise')['rows']}
        self.assertEqual(rows['config_dump']['status'],'corpus_pass');self.assertEqual(rows['split_write']['status'],'failed')
        self.assertIn('plain',rows['split_write']['detected_forms'])
    def test_catalogue_demonstration_pass(self):
        r=report('catalogue');self.assertEqual(r['status'],'corpus_pass');self.assertEqual(r['captured_cases'],13)
    def test_every_full_representation_detected_in_every_case(self):
        for form,value in representations().items():
            d=demo_capture('catalogue')
            for row in d['outputs']:row['text']+=' '+value
            r=analyze(canonical(d))
            with self.subTest(form=form):self.assertTrue(all(form in row['detected_forms'] for row in r['rows']))
    def test_every_plain_chunk_split_reassembly_detected(self):
        for i in range(1,len(CANARY)):
            text=''.join(chunk.replace(CANARY,'[REDACTED]') for chunk in (CANARY[:i],CANARY[i:]))
            d=demo_capture('catalogue');d['outputs'][0]['text']+=' '+text
            self.assertIn('plain',analyze(canonical(d))['rows'][0]['detected_forms'])
    def test_empty_captures_are_incomplete(self):
        d=demo_capture('catalogue');d['outputs']=[]
        self.assertEqual(analyze(canonical(d))['status'],'incomplete')
    def test_empty_text_is_control_loss_not_pass(self):
        d=demo_capture('catalogue')
        for item in d['outputs']:item['text']=''
        r=analyze(canonical(d));self.assertEqual(r['status'],'failed');self.assertTrue(all(x['missing_control_indices'] for x in r['rows']))
    def test_missing_one_case_incomplete(self):
        d=demo_capture('catalogue');d['outputs'].pop();r=analyze(canonical(d))
        self.assertEqual(r['status'],'incomplete');self.assertEqual(r['captured_cases'],12)
    def test_leak_and_missing_are_both_visible(self):
        d=demo_capture('none');d['outputs'].pop();r=analyze(canonical(d))
        self.assertEqual(r['status'],'failed');self.assertTrue(any(x['status']=='missing' for x in r['rows']))
    def test_benign_near_match_must_survive(self):
        d=demo_capture('catalogue');item=next(x for x in d['outputs'] if x['case']=='benign_near_match')
        item['text']=item['text'].replace('REHEARSAL_FAKE_KEY_v1_PUBLIC_DOCUMENTATION','[REDACTED]')
        row=next(x for x in analyze(canonical(d))['rows'] if x['case']==item['case'])
        self.assertEqual(row['status'],'failed');self.assertEqual(row['missing_control_indices'],[2]);self.assertEqual(row['detected_forms'],[])
    def test_reordered_capture_semantics_same_hash_changes(self):
        d=demo_capture('catalogue');a=analyze(canonical(d));d['outputs'].reverse();b=analyze(canonical(d));a.pop('capture_sha256');b.pop('capture_sha256');self.assertEqual(a,b)
    def test_duplicate_unknown_case_rejected(self):
        for change in [lambda d:d['outputs'].append(d['outputs'][0]),lambda d:d['outputs'][0].update(case='UNKNOWN_PRIVATE'),lambda d:d['outputs'][0].update(case=['config_dump'])]:
            d=demo_capture('catalogue');change(d)
            with self.assertRaises(Invalid):analyze(canonical(d))
    def test_duplicate_case_within_record_bound(self):
        d=demo_capture('catalogue');d['outputs'][1]=copy.deepcopy(d['outputs'][0])
        with self.assertRaises(Invalid):analyze(canonical(d))
    def test_schema_and_version_strict(self):
        for key,val in [('schema',True),('schema',1.0),('schema',2),('corpus_version',None),('corpus_version','other')]:
            d=demo_capture('catalogue');d[key]=val
            with self.assertRaises(Invalid):analyze(canonical(d))
    def test_text_type_length_and_unknown_fields(self):
        for val in [None,True,{},['x'],'x'*16385]:
            d=demo_capture('catalogue');d['outputs'][0]['text']=val
            with self.assertRaises(Invalid):analyze(canonical(d))
        d=demo_capture('catalogue');d['outputs'][0]['secret']='PRIVATE'
        with self.assertRaises(Invalid):analyze(canonical(d))
    def test_bound_text_all_cases_no_raw_disclosure(self):
        d=demo_capture('catalogue')
        for row in d['outputs']:row['text']+='X'*(16384-len(row['text']))
        r=analyze(canonical(d));self.assertEqual(r['status'],'corpus_pass');self.assertNotIn(b'X'*100,canonical(r));self.assertNotIn(b'X'*100,review(r))
    def test_report_does_not_echo_arbitrary_captured_text(self):
        d=demo_capture('catalogue');d['outputs'][0]['text']+=' PRIVATE_SENTINEL <script>not-for-report</script>'
        r=analyze(canonical(d))
        for out in (canonical(r),review(r)):
            self.assertNotIn(b'PRIVATE_SENTINEL',out);self.assertNotIn(b'<script>',out)
    def test_duplicate_deep_unicode_and_nonfinite_metadata(self):
        for raw in [b'{"x":1,"x":2}',b'['*20000+b'0'+b']'*20000,b'{"x":1e999}',b'"\\ud800"','{}'.encode('utf-16')]:
            with self.assertRaises(Invalid):analyze(raw)
    def test_unknown_secrets_are_explicitly_out_of_scope(self):
        d=demo_capture('catalogue');d['outputs'][0]['text']+=' DIFFERENT_SYNTHETIC_SECRET_NOT_IN_CORPUS'
        self.assertEqual(analyze(canonical(d))['status'],'corpus_pass')
    def test_arbitrary_partial_canary_is_not_claimed_detected(self):
        d=demo_capture('catalogue');d['outputs'][0]['text']+=' '+CANARY[:10]
        self.assertEqual(analyze(canonical(d))['status'],'corpus_pass')
    def test_actual_python_logging_filter_adapter(self):
        from examples.logging_adapter import capture_logging
        d=capture_logging();self.assertEqual(analyze(canonical(d))['status'],'corpus_pass')
        self.assertTrue(all(x['text'].startswith('fixture=') for x in d['outputs']))
    def test_generation_is_exact_and_does_not_overwrite(self):
        with tempfile.TemporaryDirectory() as t:
            out=Path(t)/'fixture';generate(out)
            self.assertEqual(len(list(out.iterdir())),5);self.assertEqual((out/'corpus.json').read_bytes(),canonical(corpus()))
            for policy in ('none','literal','chunkwise','catalogue'):self.assertEqual((out/('capture-'+policy+'.json')).read_bytes(),canonical(demo_capture(policy)))
            with self.assertRaises(FileExistsError):generate(out)
    def test_report_recomputes_without_copying_capture(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t);capture=root/'capture';capture.write_bytes(canonical(demo_capture('catalogue')).replace(b'\n',b'\r\n'))
            with patch.object(Path,'write_text',side_effect=AssertionError('no newline translation')):r=audit(capture,root/'report')
            self.assertEqual({p.name for p in (root/'report').iterdir()},{'report.json','review.md'});self.assertEqual(verify(root/'report',capture),r)
            self.assertEqual((root/'report/report.json').read_bytes(),canonical(r))
    def test_report_capture_tamper_extra(self):
        for name in ('report.json','review.md','extra','capture'):
            with tempfile.TemporaryDirectory() as t:
                root=Path(t);capture=root/'capture';capture.write_bytes(canonical(demo_capture('catalogue')));audit(capture,root/'report')
                p=capture if name=='capture' else root/'report'/name;p.write_bytes((p.read_bytes() if p.exists() else b'')+b'\n')
                with self.assertRaises(Invalid):verify(root/'report',capture)
    def test_preflight_leaves_no_folder(self):
        with tempfile.TemporaryDirectory() as t,patch('leak_rehearsal.core.OUTPUT_LIMIT',1):
            out=Path(t)/'out'
            with self.assertRaises(Invalid):generate(out)
            self.assertFalse(out.exists())
    def test_regular_read_bounds(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'f';p.write_bytes(b'x'*20);self.assertEqual(read(p,20),b'x'*20)
            with self.assertRaises(Invalid):read(p,19)
            with self.assertRaises(Invalid):read(Path(t))
    def test_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'link'
            try:p.symlink_to(ROOT/'README.md')
            except OSError:self.skipTest('OS disallows symlink creation')
            with self.assertRaises(Invalid):read(p)
    @unittest.skipUnless(hasattr(os,'mkfifo'),'POSIX FIFO unavailable')
    def test_fifo_cli_bounded_private_error(self):
        with tempfile.TemporaryDirectory() as t:
            p=Path(t)/'PRIVATE_SENTINEL';os.mkfifo(p)
            r=subprocess.run([sys.executable,'-m','leak_rehearsal','audit',str(p),'--out',str(Path(t)/'out')],cwd=ROOT,capture_output=True,text=True,timeout=2)
            self.assertEqual(r.returncode,2);self.assertNotIn('PRIVATE_SENTINEL',r.stderr);self.assertNotIn('Traceback',r.stderr)
    def test_cli_generate_audit_verify_gates(self):
        with tempfile.TemporaryDirectory() as t:
            root=Path(t)
            r=subprocess.run([sys.executable,'-m','leak_rehearsal','generate','--out',str(root/'fixture')],cwd=ROOT,capture_output=True,text=True);self.assertEqual(r.returncode,0,r.stderr)
            for policy,code in [('none',3),('literal',3),('chunkwise',3),('catalogue',0)]:
                capture=root/'fixture'/('capture-'+policy+'.json');out=root/policy
                for args in [['audit',str(capture),'--out',str(out)],['verify',str(out),str(capture)]]:
                    r=subprocess.run([sys.executable,'-m','leak_rehearsal',*args],cwd=ROOT,capture_output=True,text=True);self.assertEqual(r.returncode,code,r.stderr)
if __name__=='__main__':unittest.main()
