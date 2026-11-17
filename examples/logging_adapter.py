"""Example integration with Python logging using ONLY the fixed synthetic corpus.
Not a production secret-redaction filter. Run from the repository directory:
    python -m examples.logging_adapter OUTPUT_DIRECTORY
"""
import io,json,logging,sys
from pathlib import Path
from leak_rehearsal.core import CANARY,corpus,canonical,new_files,representations

class SyntheticFilter(logging.Filter):
    def filter(self,record):
        text=record.getMessage()
        for pattern in sorted(set(representations().values()),key=lambda s:(-len(s),s)):
            text=text.replace(pattern,'[REDACTED_SYNTHETIC]')
        record.msg=text;record.args=()
        return True

def capture_logging():
    outputs=[]
    for case in corpus()['cases']:
        stream=io.StringIO();handler=logging.StreamHandler(stream);handler.addFilter(SyntheticFilter())
        # Standalone Logger, not root logging configuration or application logs.
        logger=logging.Logger('synthetic-rehearsal',level=logging.INFO);logger.propagate=False;logger.addHandler(handler)
        logger.info('fixture=%s',''.join(case['chunks']));handler.flush();handler.close()
        outputs.append({'case':case['id'],'text':stream.getvalue()})
    return {'schema':1,'corpus_version':corpus()['corpus_version'],'outputs':outputs}

if __name__=='__main__':
    if len(sys.argv)!=2:raise SystemExit('Usage: python -m examples.logging_adapter NEW_OUTPUT_DIRECTORY')
    new_files(sys.argv[1],{'capture.json':canonical(capture_logging())})
