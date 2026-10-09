#!/usr/bin/env python3
"""CustomAV 0.3: bounded, recursive, explainable static scanner.

Never executes target files. Designed for game archives, but intentionally
conservative and format-agnostic. It reports malware signals separately from
packaging/modification signals.
"""
from __future__ import annotations
import argparse, base64, hashlib, json, math, os, re, shutil, struct, subprocess, sys, tempfile, unicodedata, zipfile
if '/data/pydeps' not in sys.path:
    sys.path.insert(0, '/data/pydeps')
from collections import Counter
from pathlib import Path

# High-signal strings. Generic Runtime/Socket APIs are deliberately excluded.
HIGH_BYTES = [
    b'cmd.exe', b'powershell', b'wscript', b'cscript', b'mshta', b'certutil',
    b'bitsadmin', b'encodedcommand', b'frombase64string', b'xmrig', b'monero',
    b'bitcoin', b'discord.com/api/webhooks', b'createremotethread',
    b'writeprocessmemory', b'urldownloadtofile', b'winhttpopen', b'internetopena',
]
RISKY_IMPORTS = {
    'process_injection': ['CreateRemoteThread','WriteProcessMemory','VirtualAllocEx','OpenProcess'],
    'download': ['URLDownloadToFileA','URLDownloadToFileW','WinHttpOpen','InternetOpenA','InternetOpenW','WinInet'],
    'shell': ['WinExec','ShellExecuteA','ShellExecuteW','CreateProcessA','CreateProcessW'],
    'persistence': ['RegSetValueExA','RegSetValueExW','CreateServiceA','CreateServiceW'],
}
EXPECTED_URL_HOSTS = {'minecraft.net','mojang.com','amazonaws.com','lwjgl.org','amd.com','nvidia.com'}
EXPECTED_NATIVE = {'jinput-dx8.dll','jinput-dx8_64.dll','jinput-raw.dll','jinput-raw_64.dll','jinput-wintab.dll','lwjgl.dll','lwjgl64.dll','openal32.dll','openal64.dll'}
SCRIPT_EXT = {'.bat','.cmd','.ps1','.vbs','.vbe','.js','.jse','.wsf','.hta','.sh'}
PE_EXT = {'.exe','.dll','.scr','.sys','.ocx','.cpl'}
ARCHIVE_EXT = {'.zip','.jar','.apk','.xpi','.docx','.xlsx','.pptx'}
INVISIBLE_CATEGORIES = {'Cf','Cc','Cs'}

class Engine:
    def __init__(self, archive: Path, root: Path, max_files=10000, max_bytes=1_000_000_000):
        self.archive=archive; self.root=root; self.max_files=max_files; self.max_bytes=max_bytes
        self.findings=[]; self.seen=set(); self.stats={'files':0,'bytes':0,'archives':0,'jar_entries':0,'pe_files':0,'scripts':0}
        self.meta={'engine':'CustomAV','version':'0.3','archive':str(archive),'archive_sha256':self.hash_file(archive),
                   'extracted_root':str(root),'preflight':{},'hash_checks':[],'jars':[],'pe':[]}
    def hash_file(self,p,algo='sha256'):
        h=hashlib.new(algo)
        with open(p,'rb') as f:
            for c in iter(lambda:f.read(1024*1024),b''): h.update(c)
        return h.hexdigest()
    def add(self,sev,rule,path,detail,points=0,category='review'):
        key=(sev,rule,str(path),json.dumps(detail,ensure_ascii=False,sort_keys=True,default=str))
        if key in self.seen: return
        self.seen.add(key); self.findings.append({'severity':sev,'rule':rule,'path':str(path),'detail':detail,'points':points,'category':category})
    def preflight_rar(self):
        try:
            import rarfile
            rf=rarfile.RarFile(str(self.archive)); infos=rf.infolist()
            total=sum(max(0,i.file_size) for i in infos); count=len([i for i in infos if not i.is_dir()])
            compressed=max(1,self.archive.stat().st_size)
            ratio=total/compressed
            self.meta['preflight']={'entries':len(infos),'files':count,'declared_uncompressed_bytes':total,'compression_ratio':round(ratio,2)}
            if count>self.max_files: self.add('high','ARCHIVE_BOMB_FILE_COUNT','[archive]',count,80,'malware')
            if total>self.max_bytes: self.add('high','ARCHIVE_BOMB_SIZE','[archive]',total,80,'malware')
            if ratio>200: self.add('medium','EXTREME_COMPRESSION_RATIO','[archive]',round(ratio,2),20,'review')
            for i in infos:
                n=i.filename
                if '..' in Path(n).parts or n.startswith(('/', '\\')): self.add('high','PATH_TRAVERSAL',n,'Unsafe archive path',80,'malware')
                if i.needs_password(): self.add('medium','ENCRYPTED_ENTRY',n,'Password-protected entry cannot be fully inspected',12,'review')
        except Exception as e:
            self.meta['preflight_error']=str(e)
            self.add('medium','PREFLIGHT_LIMITED','[archive]',str(e),3,'review')
    def name_signals(self, rel):
        s=str(rel); base=rel.name
        invisible_ranges=range(0x115F,0x1161)
        looks_invisible=any(unicodedata.category(c) in INVISIBLE_CATEGORIES or ord(c) in invisible_ranges for c in base)
        if looks_invisible:
            self.add('medium','UNICODE_HIDDEN_NAME',s,{'codepoints':[f'U+{ord(c):04X}' for c in base]},15 if rel.suffix.lower() in SCRIPT_EXT|PE_EXT else 4,'review')
        if any(ord(c)>127 for c in base) and rel.suffix.lower() in SCRIPT_EXT|PE_EXT:
            self.add('medium','NONASCII_EXECUTABLE_NAME',s,'Non-ASCII executable/script filename',8,'review')
        if '..' in rel.parts: self.add('high','PATH_TRAVERSAL',s,'Parent traversal in extracted path',80,'malware')
        # Double extension and right-to-left override are common camouflage signals.
        if re.search(r'\.(txt|pdf|jpg|png|doc|mp3)\.(exe|scr|bat|cmd|js|vbs|dll)$',base,re.I):
            self.add('high','DOUBLE_EXTENSION',s,'Looks like a disguised executable',55,'malware')
        if '\u202e' in base or '\u2066' in base or '\u2067' in base or '\u2068' in base:
            self.add('high','BIDI_FILENAME',s,'Bidirectional Unicode control in filename',55,'malware')
    def magic(self,data):
        if data.startswith(b'MZ'): return 'pe'
        if data.startswith(b'PK\x03\x04') or data.startswith(b'PK\x05\x06') or data.startswith(b'PK\x07\x08'): return 'zip'
        if data.startswith(b'Rar!\x1a\x07'): return 'rar5'
        if data.startswith(b'7z\xbc\xaf\x27\x1c'): return '7z'
        if data.startswith(b'\x7fELF'): return 'elf'
        if data.startswith(b'%PDF-'): return 'pdf'
        if data.startswith(b'OggS'): return 'ogg'
        if data.startswith(b'\x1f\x8b'): return 'gzip'
        return 'text' if b'\x00' not in data[:512] else 'data'
    def extension_mismatch(self,rel,kind):
        ext=rel.suffix.lower()
        expected={'pe':PE_EXT,'zip':ARCHIVE_EXT,'rar5':{'.rar'},'7z':{'.7z'},'pdf':{'.pdf'},'ogg':{'.ogg'},'gzip':{'.gz','.dat','.dat_old'}}
        backup_jar=(rel.name.lower().endswith('.jar.bak') or rel.name.lower().endswith('.zip.bak'))
        if kind in expected and ext and ext not in expected[kind] and not backup_jar and not (kind=='zip' and ext in {'.jar','.apk','.xpi','.docx','.xlsx','.pptx'}):
            self.add('medium','FORMAT_EXTENSION_MISMATCH',str(rel),{'extension':ext,'detected':kind},18,'review')
    def script_scan(self,rel,data):
        self.stats['scripts']+=1; low=data.lower(); hits=[]
        for term in [b'http://',b'https://',b'powershell',b'certutil',b'bitsadmin',b'schtasks',b'reg add',b'reg.exe',b'wmic',b'curl ',b'wget ',b'encodedcommand',b'frombase64string',b'runonce',b'\x00']:
            if term in low: hits.append(term.decode('latin1','replace'))
        long_b64=bool(re.search(rb'[A-Za-z0-9+/]{160,}={0,2}',data))
        minecraft_launcher=(rel.suffix.lower()=='.bat' and b'java ' in low and b'-cp ' in low and b'natives' in low and not any(x in low for x in [b'http',b'powershell',b'certutil',b'schtasks',b'reg add']))
        if hits or long_b64:
            self.add('high','SCRIPT_CAPABILITY',str(rel),sorted(set(hits+(['long_base64'] if long_b64 else []))),45,'malware')
        elif minecraft_launcher:
            self.add('info','MINECRAFT_LAUNCH_SCRIPT',str(rel),'Java + local classpath + local natives only',0,'review')
        else: self.add('medium','SCRIPT_FILE',str(rel),'Script file requires review',12,'review')
    def pe_scan(self,p,rel,data):
        self.stats['pe_files']+=1
        item={'path':str(rel),'sha256':self.hash_file(p),'size':p.stat().st_size,'imports':[],'sections':[]}
        try:
            cp=subprocess.run(['objdump','-p',str(p)],capture_output=True,text=True,timeout=10)
            txt=cp.stdout
            for cat,names in RISKY_IMPORTS.items():
                hits=[n for n in names if re.search(r'\b'+re.escape(n)+r'\b',txt,re.I)]
                if hits:
                    item['imports']+=hits; self.add('high','RISKY_PE_IMPORTS',str(rel),{'category':cat,'imports':hits},35,'malware')
            sec=subprocess.run(['objdump','-h',str(p)],capture_output=True,text=True,timeout=10)
            for line in sec.stdout.splitlines():
                m=re.match(r'\s*\d+\s+([^\s]+)\s+([0-9a-f]+)\s+([0-9a-f]+)',line,re.I)
                if m: item['sections'].append({'name':m.group(1),'size_hex':m.group(2),'vma':m.group(3)})
            packed_sections=[s['name'] for s in item['sections'] if s['name'].upper().startswith(('UPX','ASPACK','MPRESS'))]
            if packed_sections:
                item['packer_hint']=packed_sections
                sev='info' if p.name.lower() in EXPECTED_NATIVE else 'low'
                self.add(sev,'PACKER_SECTION_NAMES',str(rel),packed_sections,0 if sev=='info' else 3,'review')
        except Exception as e: item['objdump_error']=str(e)
        self.meta['pe'].append(item)
        high=[x.decode() for x in HIGH_BYTES if x in data.lower()]
        if high: self.add('high','PE_HIGH_RISK_STRING',str(rel),high,40,'malware')
        # High entropy alone is not malware, so only report as a review hint.
        ent=entropy(data[:min(len(data),2*1024*1024)])
        item['sample_entropy']=round(ent,3)
        is_known_packed=bool(item.get('packer_hint')) and p.name.lower() in EXPECTED_NATIVE
        if ent>7.6 and p.stat().st_size>50_000 and not is_known_packed: self.add('low','HIGH_ENTROPY_PE',str(rel),round(ent,3),3,'review')
    def jar_class_strings(self,b):
        if len(b)<12 or b[:4]!=b'\xca\xfe\xba\xbe': return []
        try:
            pos=8; cp=struct.unpack('>H',b[pos:pos+2])[0]; pos+=2; out=[]; i=1
            while i<cp:
                tag=b[pos]; pos+=1
                if tag==1:
                    n=struct.unpack('>H',b[pos:pos+2])[0]; pos+=2; out.append(b[pos:pos+n].decode('utf-8','replace')); pos+=n
                elif tag in (3,4): pos+=4
                elif tag in (5,6): pos+=8; i+=1
                elif tag in (7,8,16,19,20): pos+=2
                elif tag in (9,10,11,12,17,18): pos+=4
                elif tag==15: pos+=3
                else: return []
                i+=1
            return out
        except Exception: return []
    def zip_bytes_scan(self,origin,blob,depth=0):
        if depth>3 or len(blob)>150_000_000: return
        try: z=zipfile.ZipFile(__import__('io').BytesIO(blob))
        except Exception: return
        for i in z.infolist():
            if i.file_size>self.max_bytes: self.add('high','NESTED_SIZE_LIMIT',f'{origin}!/{i.filename}',i.file_size,80,'malware'); continue
            if '..' in Path(i.filename).parts or i.filename.startswith(('/', '\\')): self.add('high','PATH_TRAVERSAL',f'{origin}!/{i.filename}','Unsafe nested path',80,'malware')
            if Path(i.filename).suffix.lower() in PE_EXT|SCRIPT_EXT: self.add('medium','NESTED_EXECUTABLE',f'{origin}!/{i.filename}',i.file_size,18,'review')
    def jar_scan(self,p,rel):
        self.stats['archives']+=1; meta={'path':str(rel),'sha1':self.hash_file(p,'sha1'),'sha256':self.hash_file(p),'entries':0}
        try:
            with zipfile.ZipFile(p) as z:
                bad=z.testzip(); names=z.namelist(); meta['entries']=len(names); self.stats['jar_entries']+=len(names)
                if bad: self.add('high','ZIP_CRC_ERROR',str(rel),bad,60,'malware')
                exec_members=[n for n in names if Path(n).suffix.lower() in PE_EXT|SCRIPT_EXT]
                if exec_members: self.add('high','NESTED_EXECUTABLE',str(rel),exec_members[:50],40,'malware')
                mf='META-INF/MANIFEST.MF'
                manifest=z.read(mf).decode('latin1','replace') if mf in names else ''
                main=re.search(r'(?im)^Main-Class:\s*(.+)$',manifest)
                meta['main_class']=main.group(1).strip() if main else None
                meta['has_mojang_sf']='META-INF/MOJANG_C.SF' in names; meta['has_mojang_dsa']='META-INF/MOJANG_C.DSA' in names
                if meta['main_class']: self.add('medium','CUSTOM_JAR_ENTRYPOINT',str(rel),meta['main_class'],5,'review')
                if meta['has_mojang_dsa'] and not meta['has_mojang_sf']: self.add('medium','INCOMPLETE_JAR_SIGNATURE',str(rel),'MOJANG_C.DSA exists but MOJANG_C.SF is absent',8,'review')
                for n in names:
                    if not n.endswith(('.class','.json','.txt','.properties','.xml','.cfg')): continue
                    try: b=z.read(n)
                    except Exception: continue
                    low=b.lower(); hits=[x.decode() for x in HIGH_BYTES if x in low]
                    # For Java, only explicit high-signal strings count; Runtime/Socket are normal.
                    if hits: self.add('high','JAR_HIGH_RISK_STRING',f'{rel}!/{n}',hits,40,'malware')
                    if n.endswith('.class'):
                        ss=' '.join(self.jar_class_strings(b)).lower()
                        explicit=[x.decode() for x in HIGH_BYTES if x in ss.encode()]
                        if explicit: self.add('high','JAVA_HIGH_RISK_CONSTANT',f'{rel}!/{n}',explicit,45,'malware')
                    if re.search(r'\.(jar|zip|7z|rar|exe|dll|bat|cmd|ps1|vbs|js)$',n,re.I):
                        self.add('medium','NESTED_EXECUTABLE',f'{rel}!/{n}',n,18,'review')
                    for u in re.findall(rb'https?://[^\s"<>]+',b):
                        host=url_host(u)
                        if host and not any(host==x or host.endswith('.'+x) for x in EXPECTED_URL_HOSTS): self.add('medium','UNEXPECTED_URL',f'{rel}!/{n}',host,12,'review')
        except zipfile.BadZipFile as e: self.add('high','BAD_ZIP_OR_JAR',str(rel),str(e),60,'malware')
        self.meta['jars'].append(meta)
    def hash_manifest_checks(self):
        for j in self.root.rglob('*.json'):
            try: obj=json.loads(j.read_text(errors='replace'))
            except Exception: continue
            declared=((obj.get('downloads') or {}).get('client') or {}).get('sha1')
            if not declared: continue
            for jar in j.parent.glob('*.jar'):
                actual=self.hash_file(jar,'sha1'); row={'json':str(j.relative_to(self.root)),'jar':str(jar.relative_to(self.root)),'declared':declared,'actual':actual,'match':declared.lower()==actual.lower()}; self.meta['hash_checks'].append(row)
                if not row['match']: self.add('medium','MANIFEST_HASH_MISMATCH',str(jar),row,18,'review')
    def scan(self):
        self.preflight_rar()
        files=[p for p in self.root.rglob('*') if p.is_file()]
        self.stats['files']=len(files); self.stats['bytes']=sum(p.stat().st_size for p in files)
        if len(files)>self.max_files: self.add('high','EXTRACTED_FILE_LIMIT','[tree]',len(files),80,'malware')
        if self.stats['bytes']>self.max_bytes: self.add('high','EXTRACTED_SIZE_LIMIT','[tree]',self.stats['bytes'],80,'malware')
        for p in files:
            rel=p.relative_to(self.root); self.name_signals(rel)
            try: data=p.read_bytes() if p.stat().st_size<=150_000_000 else p.open('rb').read(1024*1024)
            except Exception as e: self.add('medium','READ_ERROR',str(rel),str(e),5,'review'); continue
            kind=self.magic(data[:4096]); self.extension_mismatch(rel,kind)
            ext=rel.suffix.lower()
            if kind=='pe': self.pe_scan(p,rel,data)
            if ext in SCRIPT_EXT: self.script_scan(rel,data[:2_000_000])
            if kind=='zip' and ext in ARCHIVE_EXT: self.jar_scan(p,rel)
            # Text/config URLs and high-risk markers, but do not treat normal binary/media as text.
            if kind=='text' and len(data)<=10_000_000:
                low=data.lower(); hits=[x.decode() for x in HIGH_BYTES if x in low]
                if hits: self.add('high','HIGH_RISK_TEXT',str(rel),hits,45,'malware')
                for u in re.findall(rb'https?://[^\s"<>]+',data):
                    host=url_host(u)
                    if host and not any(host==x or host.endswith('.'+x) for x in EXPECTED_URL_HOSTS): self.add('medium','UNEXPECTED_URL',str(rel),host,12,'review')
        self.hash_manifest_checks()
        return self.finish()
    def finish(self):
        score=sum(x['points'] for x in self.findings); malware=sum(x['points'] for x in self.findings if x['category']=='malware'); high=[x for x in self.findings if x['severity']=='high']
        if malware>=45 or high: verdict='SUSPICIOUS / DO NOT RUN'
        elif score>=15: verdict='MODIFIED OR UNTRUSTED / MANUAL REVIEW'
        else: verdict='NO POSITIVE MALWARE INDICATORS'
        return {'verdict':verdict,'score':score,'malware_signal_score':malware,'review_signal_score':score-malware,'findings':self.findings,'statistics':self.stats,'metadata':self.meta,'limitations':['Static analysis only; nothing from the target was executed.','No commercial AV or cloud reputation lookup was used.','Unknown or targeted threats can evade heuristic rules.']}

def entropy(b):
    if not b: return 0.0
    c=Counter(b); n=len(b)
    return -sum((v/n)*math.log2(v/n) for v in c.values())
def ascii_strings(b,minlen=5): return re.findall(rb'[\x20-\x7e]{%d,}'%minlen,b)
def url_host(u):
    raw=re.sub(rb'^https?://',b'',u).split(b'/')[0].split(b':')[0]
    m=re.match(rb'([A-Za-z0-9.-]+)',raw)
    return m.group(1).decode('ascii','ignore').lower() if m else ''

def main():
    ap=argparse.ArgumentParser(description='CustomAV 0.3')
    ap.add_argument('archive'); ap.add_argument('--extracted'); ap.add_argument('--report',default='/data/custom_av_report_v3.json'); ap.add_argument('--max-files',type=int,default=10000); ap.add_argument('--max-bytes',type=int,default=1_000_000_000)
    a=ap.parse_args(); archive=Path(a.archive); root=Path(a.extracted) if a.extracted else Path(tempfile.mkdtemp(prefix='customav03_'))
    if not a.extracted:
        helper=Path('/data/libarchive_extract.py'); cp=subprocess.run([sys.executable,str(helper),str(archive),str(root)],capture_output=True,text=True,timeout=300)
        if cp.returncode: raise SystemExit('Safe extraction failed: '+cp.stderr[-1200:])
    result=Engine(archive,root,a.max_files,a.max_bytes).scan(); Path(a.report).write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print('VERDICT:',result['verdict']); print('SCORE:',result['score'],'MALWARE_SIGNAL:',result['malware_signal_score'],'REVIEW_SIGNAL:',result['review_signal_score']); print('STATISTICS:',result['statistics']); print('ARCHIVE_SHA256:',result['metadata']['archive_sha256']); print('REPORT:',a.report)
    for f in result['findings']:
        if f['severity'] in ('high','medium'): print(f"- {f['severity']} {f['rule']} [{f['path']}] => {f['detail']}")
    if result['metadata'].get('hash_checks'): print('HASH_CHECKS:',result['metadata']['hash_checks'])
if __name__=='__main__': main()
