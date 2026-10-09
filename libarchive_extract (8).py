import ctypes, ctypes.util, os, sys
from pathlib import Path
lib=ctypes.CDLL(ctypes.util.find_library('archive') or 'libarchive.so.13')
P=ctypes.c_void_p
lib.archive_read_new.restype=P
for fn in ['archive_read_support_filter_all','archive_read_support_format_all','archive_read_support_format_rar5']:
 getattr(lib,fn).argtypes=[P]; getattr(lib,fn).restype=ctypes.c_int
lib.archive_read_open_filename.argtypes=[P,ctypes.c_char_p,ctypes.c_size_t]; lib.archive_read_open_filename.restype=ctypes.c_int
lib.archive_read_next_header.argtypes=[P,ctypes.POINTER(P)]; lib.archive_read_next_header.restype=ctypes.c_int
lib.archive_entry_pathname.argtypes=[P]; lib.archive_entry_pathname.restype=ctypes.c_char_p
lib.archive_entry_size.argtypes=[P]; lib.archive_entry_size.restype=ctypes.c_longlong
lib.archive_entry_filetype.argtypes=[P]; lib.archive_entry_filetype.restype=ctypes.c_uint
lib.archive_read_data.argtypes=[P,ctypes.c_void_p,ctypes.c_size_t]; lib.archive_read_data.restype=ctypes.c_longlong
lib.archive_read_data_skip.argtypes=[P]; lib.archive_read_data_skip.restype=ctypes.c_int
lib.archive_error_string.argtypes=[P]; lib.archive_error_string.restype=ctypes.c_char_p
lib.archive_read_free.argtypes=[P]; lib.archive_read_free.restype=ctypes.c_int

def err(a):
 x=lib.archive_error_string(a); return x.decode('utf-8','replace') if x else ''

def main(src,out):
 a=lib.archive_read_new()
 lib.archive_read_support_filter_all(a)
 # explicitly request rar5; all also includes it but this is harmless
 lib.archive_read_support_format_rar5(a)
 r=lib.archive_read_open_filename(a,os.fsencode(src),10240)
 if r != 0: raise RuntimeError('open: '+err(a))
 os.makedirs(out,exist_ok=True)
 infos=[]
 while True:
  e=P(); r=lib.archive_read_next_header(a,ctypes.byref(e))
  if r==1: break # ARCHIVE_EOF
  if r!=0: raise RuntimeError('header: '+err(a))
  n=lib.archive_entry_pathname(e).decode('utf-8','replace')
  size=lib.archive_entry_size(e)
  # RAR5 dir type is 0x4000; robustly use trailing slash
  safe=Path(n)
  dest=(Path(out)/safe).resolve()
  root=Path(out).resolve()
  if root not in dest.parents and dest != root: raise RuntimeError('unsafe path '+n)
  isdir=n.endswith('/') or ((lib.archive_entry_filetype(e) & 0o170000) == 0o040000)
  infos.append((n,size,isdir))
  if isdir: dest.mkdir(parents=True,exist_ok=True); lib.archive_read_data_skip(a); continue
  dest.parent.mkdir(parents=True,exist_ok=True)
  with open(dest,'wb') as f:
   buf=ctypes.create_string_buffer(1024*1024)
   total=0
   while True:
    got=lib.archive_read_data(a,buf,len(buf))
    if got==0: break
    if got<0: raise RuntimeError('data '+n+': '+err(a))
    f.write(buf.raw[:got]); total += got
   if size>=0 and total != size: raise RuntimeError(f'size mismatch {n}: {total}!={size}')
 lib.archive_read_free(a)
 for n,s,d in infos: print(f'{s}\t{n}')

if __name__=='__main__': main(sys.argv[1],sys.argv[2])
