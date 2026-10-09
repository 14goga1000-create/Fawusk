#!/usr/bin/env python3
"""CustomAV 0.5 - v0.4 plus an explainable signature layer.

The built-in EICAR rule detects the standard harmless anti-malware test string.
User signatures can be added in customav_signatures.json next to this file.
Nothing is executed.
"""
from __future__ import annotations
import argparse, base64, json, re, sys, zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, '/data')
from custom_av_engine_v4 import UniversalEngine as BaseUniversalEngine, MAX_MEMBER_READ

EICAR = b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'

class SignatureEngine(BaseUniversalEngine):
    def __init__(self,*args,signature_db=None,**kwargs):
        super().__init__(*args,**kwargs)
        self.meta['engine']='CustomAV'; self.meta['version']='0.5'; self.meta['signature_layer']='enabled'
        self.test_signature_points=0
        self.signatures=[{'id':'EICAR','type':'exact','pattern':EICAR,'classification':'test','description':'Standard EICAR anti-malware test file'}]
        self.load_signatures(signature_db)
    def load_signatures(self, path):
        if not path: path=Path(__file__).resolve().parent/'customav_signatures.json'
        p=Path(path)
        if not p.exists(): return
        try: obj=json.loads(p.read_text())
        except Exception as e:
            self.add('medium','SIGNATURE_DB_ERROR','[signature-db]',str(e),4,'review'); return
        for row in obj.get('signatures',[]):
            try:
                sid=str(row['id']); typ=str(row.get('type','contains')); classification=str(row.get('classification','malware')); desc=str(row.get('description',''))
                if typ=='exact' or typ=='contains':
                    if row.get('encoding')=='base64': pat=base64.b64decode(row['pattern'])
                    elif row.get('encoding')=='hex': pat=bytes.fromhex(row['pattern'])
                    else: pat=str(row['pattern']).encode('utf-8')
                    if not pat or len(pat)>1_000_000: continue
                    self.signatures.append({'id':sid,'type':typ,'pattern':pat,'classification':classification,'description':desc})
                elif typ=='regex':
                    self.signatures.append({'id':sid,'type':typ,'pattern':re.compile(str(row['pattern']),re.I|re.S),'classification':classification,'description':desc})
            except Exception: continue
    def scan_signatures(self, rel, data):
        # Exact EICAR with optional CR/LF is the canonical test and avoids matching
        # ordinary documentation that merely mentions the word EICAR.
        normalized=data.strip().replace(b'\r\n',b'\n').replace(b'\r',b'\n')
        for sig in self.signatures:
            hit=False
            if sig['id']=='EICAR': hit=normalized==sig['pattern']
            elif sig['type']=='exact': hit=data==sig['pattern'] or normalized==sig['pattern']
            elif sig['type']=='contains': hit=sig['pattern'] in data
            elif sig['type']=='regex':
                try: hit=bool(sig['pattern'].search(data.decode('utf-8','ignore')))
                except Exception: hit=False
            if not hit: continue
            if sig['classification']=='test':
                self.test_signature_points+=100
                self.add('high','KNOWN_TEST_SIGNATURE',str(rel),{'id':sig['id'],'name':sig['description']},100,'test')
            else:
                self.add('high','KNOWN_SIGNATURE',str(rel),{'id':sig['id'],'name':sig['description']},100,'malware')
    def jar_scan(self,p,rel):
        super().jar_scan(p,rel)
        try:
            with zipfile.ZipFile(p) as z:
                for i in z.infolist():
                    if i.is_dir() or i.file_size>MAX_MEMBER_READ: continue
                    self.scan_signatures(f'{rel}!/{i.filename}',z.read(i))
        except Exception: pass
    def scan_one(self,p,rel):
        try:
            data=p.read_bytes() if p.stat().st_size<=150_000_000 else p.open('rb').read(4*1024*1024)
            self.scan_signatures(rel,data)
        except Exception: pass
        return super().scan_one(p,rel)
    def finish(self):
        result=super().finish()
        test_points=sum(x['points'] for x in self.findings if x['category']=='test')
        malware_points=sum(x['points'] for x in self.findings if x['category']=='malware')
        review_points=sum(x['points'] for x in self.findings if x['category']=='review')
        result['test_signal_score']=test_points
        result['malware_signal_score']=malware_points
        result['review_signal_score']=review_points
        if test_points and not malware_points:
            result['verdict']='TEST SIGNATURE DETECTED'
            result['explanation']='Known harmless anti-malware test signature detected; this is not a real infection.'
        elif test_points:
            result['explanation']='A test signature and additional malware signals were detected.'
        return result

def main():
    ap=argparse.ArgumentParser(description='CustomAV 0.5 universal static scanner with signatures')
    ap.add_argument('input'); ap.add_argument('--report',default='/data/custom_av_report_v5.json'); ap.add_argument('--extracted'); ap.add_argument('--hash-db'); ap.add_argument('--signature-db'); ap.add_argument('--max-files',type=int,default=10000); ap.add_argument('--max-bytes',type=int,default=1_000_000_000)
    a=ap.parse_args(); src=Path(a.input)
    # Reuse v0.4's safe top-level preparation and CLI behavior by importing its helpers.
    from custom_av_engine_v4 import safe_extract_top
    root=Path(a.extracted) if a.extracted else Path(__import__('tempfile').mkdtemp(prefix='customav05_'))
    if not src.is_file() and not a.extracted: raise SystemExit('Input must be a file')
    if not a.extracted: safe_extract_top(src,src.read_bytes()[:4096],root,a.max_files,a.max_bytes)
    hdb=__import__('custom_av_engine_v4').load_hash_db(a.hash_db)
    result=SignatureEngine(src,root,max_files=a.max_files,max_bytes=a.max_bytes,hash_db=hdb,signature_db=a.signature_db).scan()
    Path(a.report).write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print('VERDICT:',result['verdict']); print('SCORE:',result['score'],'MALWARE_SIGNAL:',result['malware_signal_score'],'TEST_SIGNAL:',result.get('test_signal_score',0),'REVIEW_SIGNAL:',result['review_signal_score']); print('REPORT:',a.report)
    for f in result['findings']:
        if f['severity'] in ('high','medium'): print(f"- {f['severity']} {f['rule']} [{f['path']}] => {f['detail']}")
if __name__=='__main__': main()
