#!/usr/bin/env python3
"""CustomAV 0.4 - universal bounded static scanner.

Scans ordinary files and common containers without executing them. It is a
heuristic engine, not a replacement for a commercial AV or a sandbox.
Requires custom_av_engine_v3.py in the same /data directory for shared PE/JAR
parsers and conservative scoring primitives.
"""
from __future__ import annotations
import argparse, io, json, os, re, shutil, struct, subprocess, sys, tarfile, tempfile, zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, '/data')
from custom_av_engine_v3 import (Engine as BaseEngine, EXPECTED_NATIVE, EXPECTED_URL_HOSTS,
    SCRIPT_EXT, PE_EXT, ARCHIVE_EXT, HIGH_BYTES, RISKY_IMPORTS, entropy, url_host)

MAX_MEMBER_READ = 64 * 1024 * 1024
CONTAINER_EXTS = ARCHIVE_EXT | {'.rar','.7z','.tar','.gz','.bz2','.xz','.tgz','.tbz2','.docm','.xlsm','.pptm'}
OFFICE_EXTS = {'.docm','.dotm','.xlsm','.xltm','.pptm','.potm','.ppsm','.sldm'}


def is_safe_member(name: str, root: Path) -> Path | None:
    # Resolve before writing, preventing ../ and absolute-path escapes.
    if not name or name.startswith(('/', '\\')): return None
    p = (root / name).resolve(); r = root.resolve()
    if p != r and r not in p.parents: return None
    return p


def safe_extract_zip(src: Path, out: Path, max_files: int, max_bytes: int):
    count = total = 0
    with zipfile.ZipFile(src) as z:
        for info in z.infolist():
            dest=is_safe_member(info.filename,out)
            if dest is None: raise RuntimeError(f'unsafe ZIP path: {info.filename}')
            if len(z.infolist()) > max_files: raise RuntimeError('ZIP file-count limit exceeded')
            if info.file_size > max_bytes-total: raise RuntimeError('ZIP unpacked-size limit exceeded')
            if info.is_dir() or info.filename.endswith('/'):
                dest.mkdir(parents=True,exist_ok=True); continue
            dest.parent.mkdir(parents=True,exist_ok=True)
            with z.open(info) as f, open(dest,'wb') as o:
                remaining=info.file_size
                while remaining:
                    b=f.read(min(1024*1024,remaining));
                    if not b: break
                    o.write(b); remaining-=len(b); total+=len(b)
            count+=1


def safe_extract_tar(src: Path, out: Path, max_files: int, max_bytes: int):
    count=total=0
    mode='r:*'
    with tarfile.open(src,mode) as t:
        members=t.getmembers()
        if len(members)>max_files: raise RuntimeError('TAR file-count limit exceeded')
        for m in members:
            dest=is_safe_member(m.name,out)
            if dest is None: raise RuntimeError(f'unsafe TAR path: {m.name}')
            if m.issym() or m.islnk():
                raise RuntimeError(f'links are not extracted: {m.name}')
            if m.isdir(): dest.mkdir(parents=True,exist_ok=True); continue
            if not m.isfile() or m.size>max_bytes-total: raise RuntimeError('TAR size/type limit exceeded')
            dest.parent.mkdir(parents=True,exist_ok=True)
            f=t.extractfile(m)
            if f is None: continue
            with f,open(dest,'wb') as o:
                while True:
                    b=f.read(1024*1024)
                    if not b: break
                    o.write(b); total+=len(b)
            count+=1


def safe_extract_top(src: Path, raw: bytes, out: Path, max_files: int, max_bytes: int):
    magic=raw[:16]
    if magic.startswith(b'Rar!\x1a\x07'):
        helper=Path(__file__).resolve().parent/'libarchive_extract.py'
        if not helper.exists(): helper=Path('/data/libarchive_extract.py')
        cp=subprocess.run([sys.executable,str(helper),str(src),str(out)],capture_output=True,text=True,timeout=300)
        if cp.returncode: raise RuntimeError(cp.stderr[-1000:] or 'RAR extraction failed')
        return 'rar5'
    if magic.startswith((b'PK\x03\x04',b'PK\x05\x06',b'PK\x07\x08')):
        safe_extract_zip(src,out,max_files,max_bytes); return 'zip'
    if magic.startswith(b'7z\xbc\xaf\x27\x1c'):
        out.mkdir(parents=True,exist_ok=True)
        cp=subprocess.run(['/usr/bin/7za','x','-y',f'-o{out}',str(src)],capture_output=True,text=True,timeout=300)
        if cp.returncode: raise RuntimeError(cp.stderr[-1000:] or '7z extraction failed')
        files=[p for p in out.rglob('*') if p.is_file()]
        if len(files)>max_files or sum(p.stat().st_size for p in files)>max_bytes: raise RuntimeError('7z extracted limits exceeded')
        return '7z'
    if magic.startswith((b'ustar',)) or len(raw)>262 and raw[257:262]==b'ustar':
        safe_extract_tar(src,out,max_files,max_bytes); return 'tar'
    if magic.startswith(b'\x1f\x8b') or magic.startswith(b'BZh') or magic.startswith(b'\xfd7zXZ'):
        # Compressed single-stream files are scanned as-is; tar.gz is handled by tarfile when possible.
        try:
            safe_extract_tar(src,out,max_files,max_bytes); return 'tar-compressed'
        except Exception:
            pass
    out.mkdir(parents=True,exist_ok=True)
    shutil.copy2(src,out/src.name)
    return 'single'


class UniversalEngine(BaseEngine):
    def __init__(self,*args,hash_db=None,**kwargs):
        super().__init__(*args,**kwargs)
        self.meta['engine']='CustomAV'; self.meta['version']='0.4'; self.meta['input_mode']='universal'
        self.meta['hash_reputation']={'allowlist':0,'blocklist':0}
        self.hash_db=hash_db or {'allowlist':set(),'blocklist':set()}
        self.format_counts={}
    def preflight_rar(self):
        # v3's RAR preflight is valuable, but not applicable to every input type.
        try:
            raw=self.archive.open('rb').read(16)
            if raw.startswith(b'Rar!\x1a\x07') or self.archive.suffix.lower()=='.rar':
                return super().preflight_rar()
        except Exception: pass
        self.meta['preflight']={'type':self.magic(self.archive.read_bytes()[:4096]) if self.archive.is_file() else 'unknown'}
    def hash_reputation(self,p,rel):
        h=self.hash_file(p)
        if h in self.hash_db.get('blocklist',set()):
            self.meta['hash_reputation']['blocklist']+=1; self.add('high','LOCAL_BLOCKLIST_HASH',str(rel),h,100,'malware')
        if h in self.hash_db.get('allowlist',set()):
            self.meta['hash_reputation']['allowlist']+=1; self.add('info','LOCAL_ALLOWLIST_HASH',str(rel),h,0,'review')
    def scan_pdf(self,p,rel,data):
        low=data.lower(); active=[]
        for term in [b'/javascript',b'/js',b'/openaction',b'/aa ',b'/launch',b'/embeddedfile',b'/submitform']:
            if term in low: active.append(term.decode())
        if active: self.add('medium','PDF_ACTIVE_CONTENT',str(rel),sorted(set(active)),15,'review')
        urls=re.findall(rb'https?://[^\s()<>"\']+',data)
        bad=sorted({url_host(u) for u in urls if url_host(u) and not any(url_host(u)==h or url_host(u).endswith('.'+h) for h in EXPECTED_URL_HOSTS)})
        if bad: self.add('medium','PDF_EXTERNAL_URL',str(rel),bad,12,'review')
        if any(x in low for x in HIGH_BYTES): self.add('high','PDF_HIGH_RISK_STRING',str(rel),'High-risk command/download marker',45,'malware')
    def scan_elf(self,p,rel,data):
        low=data.lower(); hits=[]
        for term in [b'curl ',b'wget ',b'bash -c',b'/dev/tcp/',b'ld_preload',b'ptrace',b'crontab',b'xmrig',b'monero']:
            if term in low: hits.append(term.decode())
        if hits: self.add('medium','ELF_SHELL_OR_PERSISTENCE',str(rel),sorted(set(hits)),20,'review')
    def scan_office_container(self,p,rel):
        try:
            with zipfile.ZipFile(p) as z:
                names=z.namelist(); low='\n'.join(names).lower()
                macro=[n for n in names if 'vbaproject.bin' in n.lower() or n.lower().endswith(('.vbs','.js','.ps1','.hta','.exe','.dll'))]
                if macro: self.add('medium','OFFICE_ACTIVE_CONTENT',str(rel),macro[:50],25,'review')
                external=[]
                for n in names:
                    if n.lower().endswith(('.rels','.xml')) and z.getinfo(n).file_size<MAX_MEMBER_READ:
                        b=z.read(n)
                        for u in re.findall(rb'https?://[^\s"<>]+',b):
                            host=url_host(u)
                            if host and not any(host==h or host.endswith('.'+h) for h in EXPECTED_URL_HOSTS): external.append(host)
                if external: self.add('medium','OFFICE_EXTERNAL_URL',str(rel),sorted(set(external)),12,'review')
        except Exception: pass
    def scan_generic_archive_signatures(self,p,rel,data):
        # Detect genuine embedded payloads, not coincidental bytes in compressed media.
        pos=data.find(b'MZ',1)
        if pos>=0 and pos+0x40<=len(data):
            try:
                pe_off=struct.unpack_from('<I',data,pos+0x3c)[0]
                valid=0 < pe_off < 4*1024*1024 and pos+pe_off+4<=len(data) and data[pos+pe_off:pos+pe_off+4]==b'PE\\x00\\x00'
            except Exception: valid=False
            if valid: self.add('medium','EMBEDDED_PE_SIGNATURE',str(rel),{'offset':pos},25,'review')
        pos=data.find(b'\\x7fELF',1)
        if pos>=0 and pos+20<=len(data) and data[pos+4] in (1,2) and data[pos+5] in (1,2):
            self.add('medium','EMBEDDED_ELF_SIGNATURE',str(rel),{'offset':pos},18,'review')
        pos=data.find(b'PK\\x03\\x04',1)
        if pos>=0:
            try:
                with zipfile.ZipFile(io.BytesIO(data[pos:])) as z:
                    names=z.namelist()
                    if names: self.add('medium','EMBEDDED_ZIP_SIGNATURE',str(rel),{'offset':pos,'entries':len(names)},18,'review')
            except Exception: pass
    def scan_one(self,p,rel):
        self.name_signals(rel); size=p.stat().st_size
        try: data=p.read_bytes() if size<=150_000_000 else p.open('rb').read(4*1024*1024)
        except Exception as e: self.add('medium','READ_ERROR',str(rel),str(e),5,'review'); return
        kind=self.magic(data[:4096]); self.format_counts[kind]=self.format_counts.get(kind,0)+1
        self.extension_mismatch(rel,kind); self.hash_reputation(p,rel)
        if kind not in {'pe','zip','rar5','7z','text'}: self.scan_generic_archive_signatures(p,rel,data)
        if kind=='pe': self.pe_scan(p,rel,data)
        if kind=='zip':
            self.jar_scan(p,rel); self.scan_office_container(p,rel)
        if kind=='rar5' and p != self.archive: self.add('medium','NESTED_RAR_NOT_EXTRACTED',str(rel),'Nested RAR detected; metadata-only unless separately supplied',8,'review')
        if kind=='7z' and p != self.archive: self.add('medium','NESTED_7Z_NOT_EXTRACTED',str(rel),'Nested 7z detected; metadata-only unless separately supplied',8,'review')
        if kind=='pdf': self.scan_pdf(p,rel,data)
        if kind=='elf': self.scan_elf(p,rel,data)
        if p.suffix.lower() in SCRIPT_EXT: self.script_scan(rel,data[:2_000_000])
        # Generic text and config scan, excluding already handled binary formats.
        if kind=='text' and size<=10_000_000:
            low=data.lower(); hits=[x.decode() for x in HIGH_BYTES if x in low]
            if hits: self.add('high','HIGH_RISK_TEXT',str(rel),hits,45,'malware')
            for u in re.findall(rb'https?://[^\s"<>]+',data):
                host=url_host(u)
                if host and not any(host==h or host.endswith('.'+h) for h in EXPECTED_URL_HOSTS): self.add('medium','UNEXPECTED_URL',str(rel),host,12,'review')
        self.meta.setdefault('files',[]).append({'path':str(rel),'size':size,'sha256':self.hash_file(p),'magic':kind,'extension':p.suffix.lower()})
    def scan(self):
        self.preflight_rar()
        files=[p for p in self.root.rglob('*') if p.is_file()]
        self.stats['files']=len(files); self.stats['bytes']=sum(p.stat().st_size for p in files)
        if len(files)>self.max_files: self.add('high','EXTRACTED_FILE_LIMIT','[tree]',len(files),80,'malware')
        if self.stats['bytes']>self.max_bytes: self.add('high','EXTRACTED_SIZE_LIMIT','[tree]',self.stats['bytes'],80,'malware')
        for p in files: self.scan_one(p,p.relative_to(self.root))
        self.hash_manifest_checks(); self.meta['format_counts']=self.format_counts
        result=self.finish(); result['statistics']['format_counts']=self.format_counts
        return result


def load_hash_db(path):
    if not path: return {'allowlist':set(),'blocklist':set()}
    obj=json.loads(Path(path).read_text())
    return {'allowlist':set(x.lower() for x in obj.get('allowlist',[])), 'blocklist':set(x.lower() for x in obj.get('blocklist',[]))}


def main():
    ap=argparse.ArgumentParser(description='CustomAV 0.4 universal static scanner')
    ap.add_argument('input',help='Any file, or a supported top-level archive')
    ap.add_argument('--report',default='/data/custom_av_report_v4.json')
    ap.add_argument('--extracted',help='Use an already safely extracted directory')
    ap.add_argument('--hash-db',help='Optional JSON with allowlist/blocklist SHA-256 arrays')
    ap.add_argument('--max-files',type=int,default=10000); ap.add_argument('--max-bytes',type=int,default=1_000_000_000)
    a=ap.parse_args(); src=Path(a.input); root=Path(a.extracted) if a.extracted else Path(tempfile.mkdtemp(prefix='customav04_'))
    if not src.is_file() and not a.extracted: raise SystemExit('Input must be a file')
    if not a.extracted:
        try: raw=src.read_bytes()[:4096]; safe_extract_top(src,raw,root,a.max_files,a.max_bytes)
        except Exception as e: raise SystemExit(f'Safe preparation failed: {e}')
    result=UniversalEngine(src,root,max_files=a.max_files,max_bytes=a.max_bytes,hash_db=load_hash_db(a.hash_db)).scan()
    Path(a.report).write_text(json.dumps(result,ensure_ascii=False,indent=2))
    print('VERDICT:',result['verdict']); print('SCORE:',result['score'],'MALWARE_SIGNAL:',result['malware_signal_score'],'REVIEW_SIGNAL:',result['review_signal_score']); print('STATISTICS:',result['statistics']); print('REPORT:',a.report)
    for f in result['findings']:
        if f['severity'] in ('high','medium'): print(f"- {f['severity']} {f['rule']} [{f['path']}] => {f['detail']}")

if __name__=='__main__': main()
