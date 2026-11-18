"""Offline synthetic-canary rehearsals, never credential discovery or verification."""
import hashlib,io,json,os,re,stat
from pathlib import Path
INPUT_LIMIT=1024*1024
OUTPUT_LIMIT=2*1024*1024
class Invalid(ValueError):pass

def read(path,limit=INPUT_LIMIT):
    try:
        if not stat.S_ISREG(Path(path).lstat().st_mode):raise Invalid('Regular non-symlink file required.')
        fd=os.open(path,os.O_RDONLY|getattr(os,'O_NONBLOCK',0)|getattr(os,'O_NOFOLLOW',0)|getattr(os,'O_BINARY',0))
        try:
            info=os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_size>limit:raise Invalid('File type or size limit exceeded.')
            with os.fdopen(fd,'rb') as f:fd=None;raw=f.read(limit+1)
        finally:
            if fd is not None:os.close(fd)
        if len(raw)>limit:raise Invalid('File size limit exceeded.')
        raw.decode('utf8');return raw
    except (OSError,UnicodeError):raise Invalid('Cannot safely read bounded UTF-8 file.') from None

def parse(raw):
    def pairs(items):
        result={}
        for k,v in items:
            if k in result:raise Invalid('Duplicate JSON keys.')
            k.encode('utf8');result[k]=v
        return result
    def bad(x):raise Invalid('Non-finite number.')
    try:
        if len(raw)>INPUT_LIMIT:raise Invalid('Input exceeds 1 MiB.')
        result=json.loads(raw.decode('utf8'),object_pairs_hook=pairs,parse_constant=bad)
        queue=[(result,0)]
        while queue:
            value,depth=queue.pop()
            if isinstance(value,(list,dict)):
                if depth>=16:raise Invalid('JSON depth exceeded.')
                queue.extend((v,depth+1) for v in (value.values() if isinstance(value,dict) else value))
            elif isinstance(value,str):value.encode('utf8')
            elif isinstance(value,float):raise Invalid('Floating-point metadata is unsupported.')
        return result
    except (ValueError,UnicodeError,RecursionError):raise Invalid('Invalid bounded JSON.') from None

def fields(item,names):
    if not isinstance(item,dict) or set(item)!=set(names):raise Invalid('Unexpected or missing fields.')
def integer(value,lo,hi):
    if type(value) is not int or not lo<=value<=hi:raise Invalid('Integer outside declared bounds.')
import base64
from urllib.parse import quote
CANARY='REHEARSAL_FAKE_KEY_v1_A7q9/B+2=Z'
CORPUS_VERSION='fixed-synthetic-v1'

def canonical(data):return (json.dumps(data,sort_keys=True,indent=2,ensure_ascii=False,allow_nan=False)+'\n').encode('utf8')
def representations():
    raw=CANARY.encode('ascii');url=quote(CANARY,safe='')
    return {'plain':CANARY,'url':url,'url_lower_percent':re.sub(r'%[0-9A-F]{2}',lambda m:m.group(0).lower(),url),'base64':base64.b64encode(raw).decode('ascii'),'base64_unpadded':base64.b64encode(raw).decode('ascii').rstrip('='),'hex':raw.hex(),'hex_upper':raw.hex().upper(),'unicode_escape':''.join('\\u%04x'%ord(c) for c in CANARY)}

def corpus():
    reps=representations();cases=[]
    def add(id,stage,payload,chunks=None,extra_controls=()):
        marker='PUBLIC_TRACE_'+id+'_v1';text='operation=complete '+marker+' '+payload
        # chunks are split from the full text, not silently joined by a fixture.
        if chunks is None:parts=[text]
        else:
            cut=text.index(CANARY)+chunks;parts=[text[:cut],text[cut:]]
        cases.append({'id':id,'stage':stage,'chunks':parts,'preserve':['operation=complete',marker,*extra_controls]})
    add('config_dump','config','API_KEY='+CANARY)
    add('authorization','log','Authorization: Bearer '+CANARY)
    add('exception','trace','failed request credential='+CANARY)
    add('url_export','export','https://example.invalid/?key='+reps['url'])
    add('url_lower','export','key='+reps['url_lower_percent'])
    add('base64_export','export','encoded='+reps['base64'])
    add('base64_unpadded','export','encoded='+reps['base64_unpadded'])
    add('hex_export','export','hex='+reps['hex'])
    add('hex_upper','export','hex='+reps['hex_upper'])
    add('unicode_export','export','escaped='+reps['unicode_escape'])
    add('split_write','log','API_KEY='+CANARY,chunks=len(CANARY)//2)
    near='REHEARSAL_FAKE_KEY_v1_PUBLIC_DOCUMENTATION'
    add('benign_near_match','control',near,extra_controls=[near])
    add('benign_payload','control','status=200 retry_count=3',extra_controls=['status=200 retry_count=3'])
    return {'schema':1,'corpus_version':CORPUS_VERSION,'synthetic_canary':CANARY,'cases':cases,'scope':'Fixed synthetic rehearsal, not a general secret scanner or proof of confidentiality.'}

def demo_capture(policy):
    if policy not in ('none','literal','chunkwise','catalogue'):raise Invalid('Unknown demonstration policy.')
    def redact(text,patterns):
        for pattern in sorted(set(patterns),key=lambda s:(-len(s),s)):text=text.replace(pattern,'[REDACTED_SYNTHETIC]')
        return text
    rows=[]
    for case in corpus()['cases']:
        if policy=='none':text=''.join(case['chunks'])
        elif policy=='chunkwise':text=''.join(redact(chunk,[CANARY]) for chunk in case['chunks'])
        elif policy=='literal':text=redact(''.join(case['chunks']),[CANARY])
        else:text=redact(''.join(case['chunks']),representations().values())
        rows.append({'case':case['id'],'text':text})
    return {'schema':1,'corpus_version':CORPUS_VERSION,'outputs':rows}

def load_capture(raw):
    d=parse(raw);fields(d,['schema','corpus_version','outputs'])
    integer(d['schema'],1,1)
    if d['corpus_version']!=CORPUS_VERSION or type(d['corpus_version']) is not str:raise Invalid('Unsupported corpus version.')
    if not isinstance(d['outputs'],list) or len(d['outputs'])>len(corpus()['cases']):raise Invalid('Too many capture records.')
    known={c['id'] for c in corpus()['cases']};seen=set()
    for item in d['outputs']:
        fields(item,['case','text'])
        if type(item['case']) is not str or item['case'] not in known or item['case'] in seen:raise Invalid('Unknown or duplicate capture case.')
        seen.add(item['case'])
        if type(item['text']) is not str or len(item['text'])>16384:raise Invalid('Capture text must be a bounded string.')
    return d

def analyze(raw):
    capture=load_capture(raw);texts={x['case']:x['text'] for x in capture['outputs']};rows=[]
    patterns=representations()
    # Variants can be identical (e.g. unpadded Base64 for some future corpus).
    # Report names of detected forms, never arbitrary output or excerpts.
    for c in corpus()['cases']:
        if c['id'] not in texts:
            rows.append({'case':c['id'],'stage':c['stage'],'status':'missing','detected_forms':[],'missing_control_indices':list(range(len(c['preserve'])))});continue
        text=texts[c['id']]
        forms=sorted(name for name,pattern in patterns.items() if pattern in text)
        missing=[i for i,control in enumerate(c['preserve']) if control not in text]
        rows.append({'case':c['id'],'stage':c['stage'],'status':'failed' if forms or missing else 'corpus_pass','detected_forms':forms,'missing_control_indices':missing})
    status='failed' if any(r['status']=='failed' for r in rows) else 'incomplete' if any(r['status']=='missing' for r in rows) else 'corpus_pass'
    return {'schema':1,'corpus_version':CORPUS_VERSION,'corpus_sha256':hashlib.sha256(canonical(corpus())).hexdigest(),'capture_sha256':hashlib.sha256(raw).hexdigest(),'status':status,'expected_cases':len(rows),'captured_cases':len(texts),'rows':rows,'scope':'Only exact full representations of the fixed synthetic canary and listed benign controls were checked. Not a credential scan, provenance proof or security certification.'}

def review(report):
    lines=['# Leak Rehearsal','','Status: '+report['status'],'',report['scope'],'','Captured cases: '+str(report['captured_cases'])+'/'+str(report['expected_cases']),'','| Case | Stage | Result | Detected forms | Lost control indices |','|---|---|---|---|---|']
    for r in report['rows']:lines.append('| '+' | '.join([r['case'],r['stage'],r['status'],', '.join(r['detected_forms']) or '-',', '.join(map(str,r['missing_control_indices'])) or '-'])+' |')
    lines+=['','No captured text is included. Retain your capture locally to recompute this report. Control indices refer to the fixed corpus preserve list. Passing all cases does not prove the tested application ran or that unknown secrets/encodings cannot leak.','']
    return '\n'.join(lines).encode('utf8')

def new_files(folder,files):
    if any(len(data)>OUTPUT_LIMIT for data in files.values()):raise Invalid('Generated file limit exceeded.')
    # Fixed leaf names only; serialize and validate before reserving any output.
    if any(not isinstance(name,str) or not name or name in ('.','..')
           or '/' in name or '\\' in name or ':' in name or '\0' in name
           for name in files):
        raise Invalid('Invalid generated filename.')
    root=Path(folder)
    root.mkdir(mode=0o700,exist_ok=False)
    for name,data in files.items():
        flags=os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,'O_NOFOLLOW',0)
        fd=os.open(root/name,flags,0o600)
        try:
            with os.fdopen(fd,'wb') as stream:
                fd=None
                stream.write(data)
        finally:
            if fd is not None:
                os.close(fd)
    # Do not remove partial outputs on failure or alter pre-existing permissions.


def generate(out):
    # No real token generation, environment access or arbitrary credential input.
    new_files(out,{'corpus.json':canonical(corpus()),**{'capture-'+p+'.json':canonical(demo_capture(p)) for p in ('none','literal','chunkwise','catalogue')}})
    return {'corpus_version':CORPUS_VERSION,'cases':len(corpus()['cases']),'note':'Only fixed public synthetic values generated; demo policies are not production redactors.'}
def audit(capture,out):
    report=analyze(read(capture));new_files(out,{'report.json':canonical(report),'review.md':review(report)});return report

def verify(folder,capture):
    root=Path(folder)
    if root.is_symlink() or not root.is_dir() or {p.name for p in root.iterdir()}!={'report.json','review.md'}:raise Invalid('Unexpected report structure.')
    report=analyze(read(capture))
    if read(root/'report.json',OUTPUT_LIMIT)!=canonical(report) or read(root/'review.md',OUTPUT_LIMIT)!=review(report):raise Invalid('Report differs from capture recomputation.')
    return report
