import argparse,json,sys
from .core import Invalid,generate,audit,verify

def main():
    p=argparse.ArgumentParser(description='Offline fixed-synthetic canary rehearsal; never scans for real credentials.')
    sub=p.add_subparsers(dest='command',required=True)
    g=sub.add_parser('generate');g.add_argument('--out',required=True)
    a=sub.add_parser('audit');a.add_argument('capture');a.add_argument('--out',required=True)
    v=sub.add_parser('verify');v.add_argument('report');v.add_argument('capture')
    args=p.parse_args()
    try:
        if args.command=='generate':print(json.dumps(generate(args.out)));return 0
        report=audit(args.capture,args.out) if args.command=='audit' else verify(args.report,args.capture)
        print(json.dumps({'status':report['status'],'captured_cases':report['captured_cases'],'expected_cases':report['expected_cases'],'scope':report['scope']}))
        return 0 if report['status']=='corpus_pass' else 3
    except (Invalid,OSError,ValueError,RecursionError):
        print('Cannot process bounded synthetic capture or report: malformed input, mismatch or filesystem failure. Captured contents are not echoed.',file=sys.stderr);return 2
if __name__=='__main__':sys.exit(main())
