"""Fixed synthetic local authorization exercise. Not a security service."""
import argparse, hashlib, json, os, sqlite3, stat, subprocess, sys, tempfile, time
from pathlib import Path
from contextlib import closing
from . import core
Invalid=core.Invalid
TOKENS={'old':'PUBLIC_FAKE_RECOVERY_OLD_NOT_A_PROVIDER_KEY','replacement':'PUBLIC_FAKE_RECOVERY_READ_ONLY_NOT_A_PROVIDER_KEY'}
SCHEMA={
 'meta':'CREATE TABLE meta (version INTEGER NOT NULL, consumer TEXT NOT NULL)',
 'credentials':'CREATE TABLE credentials (alias TEXT PRIMARY KEY, digest TEXT NOT NULL, revoked INTEGER NOT NULL, scope TEXT NOT NULL)',
 'reports':'CREATE TABLE reports (id INTEGER PRIMARY KEY, body TEXT NOT NULL)',
 'events':'CREATE TABLE events (seq INTEGER PRIMARY KEY, action TEXT NOT NULL, result TEXT NOT NULL)'}
ACTIONS=('issue','switch-old','switch-replacement','revoke-old','app-read','old-read','replacement-read','replacement-write','replacement-delete')
def digest(alias):return hashlib.sha256(TOKENS[alias].encode()).hexdigest()
def initialize(path):
    p=Path(path)
    fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0),0o600);os.close(fd)
    try:
        # SQLite transaction contexts commit/rollback but do not close connections.
        with closing(sqlite3.connect(p)) as c:
            with c:
                for sql in SCHEMA.values():c.execute(sql)
                c.execute("INSERT INTO meta VALUES (1,'old')")
                c.execute('INSERT INTO credentials VALUES (?,?,0,?)',('old',digest('old'),'read,write,delete'))
                c.execute("INSERT INTO reports VALUES (1,'PUBLIC_SYNTHETIC_REPORT_v1')")
    except Exception:
        # Never delete an unknown or partially created file automatically.
        raise Invalid('Initialization incomplete.') from None
    return {'initialized':True}
def connect(path):
    p=Path(path)
    try:
        s=p.lstat()
        if not stat.S_ISREG(s.st_mode) or s.st_size>1024*1024:raise Invalid('Expected bounded regular exercise database.')
        if any(Path(str(p)+x).exists() or Path(str(p)+x).is_symlink() for x in ('-wal','-shm','-journal')):raise Invalid('Database sidecars unsupported.')
        c=sqlite3.connect(p.resolve().as_uri()+'?mode=rw',uri=True,timeout=1)
        c.execute('PRAGMA trusted_schema=OFF');c.execute('PRAGMA query_only=OFF')
        c.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,65536)
        c.set_progress_handler(lambda: int(time.monotonic()>deadline),1000)
        deadline=time.monotonic()+2
        c.execute('BEGIN IMMEDIATE')
        objects=c.execute("SELECT name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%'").fetchall()
        if dict(objects)!=SCHEMA or len(objects)!=4:raise Invalid('Not the fixed exercise schema.')
        m=c.execute('SELECT version,consumer FROM meta').fetchall()
        if len(m)!=1 or m[0][0]!=1 or type(m[0][0]) is not int or m[0][1] not in TOKENS:raise Invalid('Invalid exercise metadata.')
        rows=c.execute('SELECT alias,digest,revoked,scope FROM credentials').fetchall()
        if not 1<=len(rows)<=2 or not any(r[0]=='old' for r in rows):raise Invalid('Invalid exercise credentials.')
        for a,d,r,s in rows:
            if a not in TOKENS or d!=digest(a) or type(r)is not int or r not in (0,1) or s!=('read,write,delete' if a=='old' else 'read'):raise Invalid('Invalid exercise credentials.')
            if a=='replacement' and r!=0:raise Invalid('Invalid replacement state.')
        if c.execute('SELECT * FROM reports').fetchall()!=[(1,'PUBLIC_SYNTHETIC_REPORT_v1')]:raise Invalid('Synthetic business data changed.')
        events=c.execute('SELECT seq,action,result FROM events ORDER BY seq').fetchall()
        if len(events)>257:raise Invalid('Exercise event limit exceeded.')
        for i,(n,a,r) in enumerate(events,1):
            if n!=i or a not in ACTIONS or core.canonical(core.parse(r.encode())).decode()!=r:raise Invalid('Invalid exercise journal.')
        if len(events)==257:
            # One explicitly reserved containment entry, never a rolling/deleted log.
            if events[-1][1:] != ('revoke-old',core.canonical({'status':'revoked','audit':'reserved_containment_entry'}).decode()):
                raise Invalid('Invalid reserved containment entry.')
            if c.execute("SELECT revoked FROM credentials WHERE alias='old'").fetchone()!=(1,):
                raise Invalid('Containment entry contradicts credential state.')
        return c
    except (OSError,sqlite3.Error,Invalid):
        if 'c' in locals():c.close()
        raise Invalid('Cannot open fixed exercise database.') from None

def transact(path,action):
    if action not in ACTIONS:raise Invalid('Unsupported fixed action.')
    c=connect(path)
    try:
        count=c.execute('SELECT COUNT(*) FROM events').fetchone()[0]
        if count>=256:
            if action!='revoke-old':raise Invalid('Exercise event limit reached; only containment is available.')
            c.execute("UPDATE credentials SET revoked=1 WHERE alias='old'")
            result={'status':'revoked','audit':'reserved_containment_entry' if count==256 else 'existing_containment_entry'}
            if count==256:
                c.execute('INSERT INTO events(action,result) VALUES (?,?)',(action,core.canonical(result).decode()))
            c.commit()
            return result
        if action=='issue':
            c.execute('INSERT OR IGNORE INTO credentials VALUES (?,?,0,?)',('replacement',digest('replacement'),'read'))
            result={'status':'issued','scope':['read']}
        elif action.startswith('switch-'):
            alias=action[7:]
            if not c.execute('SELECT 1 FROM credentials WHERE alias=?',(alias,)).fetchone():result={'status':'not_issued'}
            else:
                c.execute('UPDATE meta SET consumer=?',(alias,));result={'status':'switched','consumer':alias}
        elif action=='revoke-old':
            c.execute("UPDATE credentials SET revoked=1 WHERE alias='old'");result={'status':'revoked'}
        else:
            alias=c.execute('SELECT consumer FROM meta').fetchone()[0] if action=='app-read' else action.split('-')[0]
            operation=action.split('-')[-1]
            # Client supplies the fixed fake credential, not an authorization decision.
            presented=TOKENS[alias]
            row=c.execute('SELECT revoked,scope FROM credentials WHERE digest=?',(hashlib.sha256(presented.encode()).hexdigest(),)).fetchone()
            if row is None:result={'status':'unauthorized','reason':'not_issued'}
            elif row[0]:result={'status':'unauthorized','reason':'revoked'}
            elif operation not in row[1].split(','):result={'status':'forbidden','reason':'scope'}
            elif operation=='read':
                body=c.execute('SELECT body FROM reports WHERE id=1').fetchone()[0]
                result={'status':'ok','report_sha256':hashlib.sha256(body.encode()).hexdigest()}
            else:raise Invalid('No mutating authorized probe is supported.')
        c.execute('INSERT INTO events(action,result) VALUES (?,?)',(action,core.canonical(result).decode()))
        c.commit();return result
    finally:c.close()

def client(path,action):
    """One fresh fixed Python worker per request; no supplied code or command."""
    if action not in ACTIONS:raise Invalid('Unsupported fixed action.')
    script="import sys;sys.path.insert(0,sys.argv[1]);from leak_rehearsal.recovery import worker;worker(sys.argv[2],sys.argv[3])"
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        p=subprocess.Popen([sys.executable,'-I','-c',script,str(Path(__file__).resolve().parent.parent),str(Path(path).absolute()),action],stdin=subprocess.DEVNULL,stdout=out,stderr=err,env={})
        deadline=time.monotonic()+5
        try:
            while p.poll() is None:
                if time.monotonic()>deadline or os.fstat(out.fileno()).st_size+os.fstat(err.fileno()).st_size>16384:raise Invalid('Fixed worker timeout/output limit.')
                time.sleep(.005)
            if p.returncode or os.fstat(out.fileno()).st_size>16384:raise Invalid('Fixed worker failed; no successful observation recorded.')
            out.seek(0);result=core.parse(out.read(16385))
            if not isinstance(result,dict):raise Invalid('Invalid worker result.')
            return result
        finally:
            if p.poll() is None:p.kill()
            p.wait(timeout=2)
def worker(path,action):
    try:sys.stdout.buffer.write(core.canonical(transact(path,action)))
    except (Invalid,sqlite3.Error,OSError):sys.exit(2)
def probe(path):
    actions=['app-read','old-read','replacement-read','replacement-write','replacement-delete']
    observations=[{'action':a,'result':client(path,a)} for a in actions]
    wanted=['ok','unauthorized','ok','forbidden','forbidden']
    return {'observations':observations,'recovery_ready':all(r['result']['status']==s for r,s in zip(observations,wanted)),'scope':'Fixed synthetic service only; not provider rotation or security certification.'}
SEQUENCES={
 'contain-first':['app-read','old-read','issue','revoke-old','app-read','switch-replacement','app-read','old-read','replacement-read','replacement-write','replacement-delete','switch-old','app-read','issue','revoke-old','old-read','switch-replacement','app-read'],
 'switch-first':['issue','replacement-read','switch-replacement','app-read','revoke-old','old-read','replacement-write','replacement-delete','app-read']}
EXPECTED={
 'contain-first':['ok','ok','issued','revoked','unauthorized','switched','ok','unauthorized','ok','forbidden','forbidden','switched','unauthorized','issued','revoked','unauthorized','switched','ok'],
 'switch-first':['issued','ok','switched','ok','revoked','unauthorized','forbidden','forbidden','ok']}
def score(receipt):
    core.fields(receipt,['schema','redaction_status','scenarios']);core.integer(receipt['schema'],1,1)
    if receipt['redaction_status']!='corpus_pass' or type(receipt['scenarios'])is not list or len(receipt['scenarios'])!=2:raise Invalid('Incomplete rehearsal receipt.')
    verdict=[]
    for scenario,(name,actions) in zip(receipt['scenarios'],SEQUENCES.items()):
        core.fields(scenario,['name','steps'])
        if scenario['name']!=name or type(scenario['steps'])is not list or len(scenario['steps'])!=len(actions):raise Invalid('Missing or reordered scenario.')
        for step,action,status in zip(scenario['steps'],actions,EXPECTED[name]):
            core.fields(step,['action','result'])
            if step['action']!=action:raise Invalid('Reordered action.')
            result=step['result']
            # Only the finite public protocol is admissible, including failures.
            possibilities=[{'status':'ok','report_sha256':hashlib.sha256(b'PUBLIC_SYNTHETIC_REPORT_v1').hexdigest()}, {'status':'issued','scope':['read']},{'status':'revoked'},{'status':'not_issued'},{'status':'unauthorized','reason':'not_issued'},{'status':'unauthorized','reason':'revoked'},{'status':'forbidden','reason':'scope'},*({'status':'switched','consumer':a} for a in TOKENS)]
            if not any(core.canonical(result)==core.canonical(p) for p in possibilities):raise Invalid('Invalid recorded result.')
        verdict.append({'scenario':name,'matched':all(x['result']['status']==s and (s!='unauthorized' or x['result'].get('reason')=='revoked') and (s!='switched' or x['result'].get('consumer')==x['action'][7:]) for x,s in zip(scenario['steps'],EXPECTED[name]))})
    return {'schema':1,'scenarios':verdict,'exercise_pass':all(x['matched'] for x in verdict),'receipt_sha256':hashlib.sha256(core.canonical(receipt)).hexdigest(),'scope':'Offline scoring of recorded results, not authentication of execution or production safety.'}
def review(report,receipt):
    lines=['# Synthetic recovery rehearsal','','Exercise pass: '+str(report['exercise_pass']),'',report['scope'],'','Catalogue redaction passed, but initial old-read succeeds: removing log text does not revoke service access.','']
    explanations={'issue':'Issue is idempotent; consumer is unchanged.','revoke-old':'Irreversible in supported commands; an old consumer may now fail.','switch-old':'Select old consumer; this never re-enables revoked access.','switch-replacement':'Consumer now selects read-only replacement.','replacement-write':'Least privilege refuses write; business data unchanged.','replacement-delete':'Least privilege refuses delete; business data unchanged.','old-read':'Replay of exposed fixed credential tests actual service authorization.','replacement-read':'Read uses the replacement against actual synthetic data.','app-read':'Actual application read: unauthorized means outage; ok means read available.'}
    for scenario in receipt['scenarios']:
        lines += ['## '+scenario['name'],'','| Step | Action | Actual | Expected | Explanation |','|---|---|---|---|---|']
        for i,(step,expected) in enumerate(zip(scenario['steps'],EXPECTED[scenario['name']]),1):
            result=step['result'];actual=result['status']+(' / '+result['reason'] if 'reason' in result else '')+(' / '+result['consumer'] if 'consumer' in result else '')
            lines.append('| '+' | '.join([str(i),step['action'],actual,expected,explanations[step['action']]])+' |')
    lines += ['','Contain-first intentionally demonstrates an outage. Switch-first is not advice to delay containment after exposure. Revoked credentials cannot be re-enabled by supported commands.','']
    return '\n'.join(lines).encode()
def demo(out):
    dest=Path(out)
    if dest.exists() or dest.is_symlink():raise Invalid('Output must not exist.')
    receipt={'schema':1,'redaction_status':core.analyze(core.canonical(core.demo_capture('catalogue')))['status'],'scenarios':[]}
    with tempfile.TemporaryDirectory() as td:
        for name,actions in SEQUENCES.items():
            db=Path(td)/(name+'.sqlite3');initialize(db)
            receipt['scenarios'].append({'name':name,'steps':[{'action':a,'result':client(db,a)} for a in actions]})
    report=score(receipt)
    core.new_files(dest,{'receipt.json':core.canonical(receipt),'report.json':core.canonical(report),'review.md':review(report,receipt)})
    return report
def verify(folder):
    p=Path(folder)
    if p.is_symlink() or not p.is_dir() or {x.name for x in p.iterdir()}!={'receipt.json','report.json','review.md'}:raise Invalid('Invalid evidence directory.')
    receipt=core.parse(core.read(p/'receipt.json'));r=score(receipt)
    if core.read(p/'receipt.json')!=core.canonical(receipt) or core.read(p/'report.json')!=core.canonical(r) or core.read(p/'review.md')!=review(r,receipt):raise Invalid('Evidence differs from rescoring.')
    return r
def main():
    p=argparse.ArgumentParser(description=__doc__);sub=p.add_subparsers(dest='cmd',required=True)
    for name in ('init','probe'):
        sub.add_parser(name).add_argument('--db',required=True)
    a=sub.add_parser('act');a.add_argument('--db',required=True);a.add_argument('action',choices=ACTIONS)
    sub.add_parser('demo').add_argument('--out',required=True)
    sub.add_parser('verify').add_argument('folder')
    args=p.parse_args()
    try:
        r=initialize(args.db) if args.cmd=='init' else probe(args.db) if args.cmd=='probe' else client(args.db,args.action) if args.cmd=='act' else demo(args.out) if args.cmd=='demo' else verify(args.folder)
        sys.stdout.buffer.write(core.canonical(r));return 3 if r.get('recovery_ready') is False or r.get('exercise_pass') is False else 0
    except (Invalid,OSError,sqlite3.Error,subprocess.SubprocessError):print('Recovery exercise failed: invalid input, bounded worker or filesystem error.',file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
