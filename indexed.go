package main

// FAW 3, flags=1: independently compressed solid groups and a bounded integrity-checked
// catalogue. SHA-256 detects corruption, not malicious authors or viruses.
import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/klauspost/compress/zstd"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const indexLimit = 32 << 20

type groupDesc struct {
	Offset, Stored, Raw uint64
	Codec               byte
	Hash                [32]byte
}
type indexedEntry struct {
	archiveEntry
	Stamp int64
	Hash  [32]byte
	Start uint64
}
type catalogue struct {
	Groups  []groupDesc
	Entries []indexedEntry
	Total   uint64
}

func indexed(p string) bool {
	f, e := os.Open(p)
	if e != nil {
		return false
	}
	defer f.Close()
	var h [12]byte
	_, e = f.ReadAt(h[:], 0)
	return e == nil && equalBytes(h[:8], fawMagic[:]) && binary.LittleEndian.Uint16(h[8:10]) == 3 && binary.LittleEndian.Uint16(h[10:12]) == 1
}
func packFAW3(ctx context.Context, inputs []string, output string, level int, progress report) (err error) {
	if progress == nil {
		progress = func(int, string) {}
	}
	if !strings.EqualFold(filepath.Ext(output), ".faw") {
		return errors.New(tr("Нужно расширение .faw"))
	}
	if _, e := os.Lstat(output); !os.IsNotExist(e) {
		return errors.New(tr("Файл назначения уже существует или недоступен"))
	}
	if e := ensureParents(filepath.Dir(output)); e != nil {
		return e
	}
	items, total, e := plan(ctx, inputs, output)
	if e != nil {
		return e
	}
	quality := zstd.SpeedFastest
	if level == 6 {
		quality = zstd.SpeedDefault
	}
	if level == 9 {
		quality = zstd.SpeedBestCompression
	}
	workers := archiveWorkers(uint64(total))
	enc, e := zstd.NewWriter(nil, zstd.WithEncoderConcurrency(workers), zstd.WithEncoderLevel(quality), zstd.WithWindowSize(faw3Window), zstd.WithLowerEncoderMem(true))
	if e != nil {
		return e
	}
	defer enc.Close()
	f, e := os.CreateTemp(filepath.Dir(output), ".fawusk-*.tmp")
	if e != nil {
		return e
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	header := faw3Header(uint64(total), len(items))
	binary.LittleEndian.PutUint16(header[10:12], 1)
	binary.LittleEndian.PutUint32(header[28:], crc32.ChecksumIEEE(header[:28]))
	if _, e = f.Write(header); e != nil {
		return e
	}
	cat := catalogue{Total: uint64(total)}
	raw := make([]byte, 0, faw3Window)

	type result struct {
		raw, data, encoded []byte
		hash               [32]byte
		codec              byte
	}
	type buffers struct{ raw, encoded []byte }
	pending := make([]chan result, 0, workers)
	pool := make(chan buffers, workers)
	var scratch []byte
	offset := uint64(32)
	cursor := uint64(0)
	names := 0
	consume := func() error {
		ch := pending[0]
		pending = pending[1:]
		r := <-ch
		defer func() {
			select {
			case pool <- buffers{r.raw[:0], r.encoded[:0]}:
			default:
			}
		}()
		if e := check(ctx); e != nil {
			return e
		}
		g := groupDesc{Offset: offset, Stored: uint64(len(r.data)), Raw: uint64(len(r.raw)), Codec: r.codec, Hash: r.hash}
		if _, e := f.Write(r.data); e != nil {
			return e
		}
		cat.Groups = append(cat.Groups, g)
		offset += g.Stored
		return nil
	}
	defer func() {
		for _, ch := range pending {
			<-ch
		}
	}()
	flush := func() error {
		if len(raw) == 0 {
			return nil
		}
		if e := check(ctx); e != nil {
			return e
		}
		if len(pending) == workers {
			if e := consume(); e != nil {
				return e
			}
		}
		block, encoded := raw, scratch
		ch := make(chan result, 1)
		pending = append(pending, ch)
		go func() {
			encoded = enc.EncodeAll(block, encoded[:0])
			data := encoded
			codec := byte(1)
			if len(data) >= len(block) {
				data = block
				codec = 0
			}
			ch <- result{raw: block, data: data, encoded: encoded, hash: sha256.Sum256(data), codec: codec}
		}()
		select {
		case b := <-pool:
			raw, scratch = b.raw, b.encoded
		default:
			raw = make([]byte, 0, faw3Window)
			scratch = nil
		}
		return nil
	}
	counter := &copying{ctx: ctx, total: total, report: progress}
	for _, it := range items {
		if e = check(ctx); e != nil {
			return e
		}
		name := strings.TrimSuffix(it.name, "/")
		names += len(name)
		if names > fawMaxNames {
			return errors.New(tr("Слишком много имён"))
		}
		entry := indexedEntry{archiveEntry: archiveEntry{Name: name, Directory: it.info.IsDir()}, Stamp: it.info.ModTime().Unix(), Start: cursor}
		if !entry.Directory {
			entry.Size = uint64(it.info.Size())
			src, e := os.Open(it.path)
			if e != nil {
				return e
			}
			hash := sha256.New()
			counter.label = tr("Упаковка: ") + name
			e = func() error {
				defer src.Close()
				st, e := src.Stat()
				if e != nil {
					return e
				}
				if !os.SameFile(st, it.info) || st.Size() != it.info.Size() || !st.ModTime().Equal(it.info.ModTime()) || !st.Mode().IsRegular() {
					return errors.New(tr("Исходный файл изменился"))
				}
				left := entry.Size
				for left > 0 {
					if e := check(ctx); e != nil {
						return e
					}
					n := uint64(faw3Window - len(raw))
					if n > left {
						n = left
					}
					old := len(raw)
					raw = raw[:old+int(n)]
					if _, e := io.ReadFull(src, raw[old:]); e != nil {
						return e
					}
					hash.Write(raw[old:])
					if _, e := counter.Write(raw[old:]); e != nil {
						return e
					}
					left -= n
					cursor += n
					if len(raw) == faw3Window {
						if e := flush(); e != nil {
							return e
						}
					}
				}
				var extra [1]byte
				n, _ := src.Read(extra[:])
				after, e := src.Stat()
				if e != nil {
					return e
				}
				if n != 0 || after.Size() != st.Size() || !after.ModTime().Equal(st.ModTime()) {
					return errors.New(tr("Исходный файл изменился"))
				}
				return nil
			}()
			if e != nil {
				return e
			}
			copy(entry.Hash[:], hash.Sum(nil))
		}
		cat.Entries = append(cat.Entries, entry)
	}
	if e = flush(); e != nil {
		return e
	}
	for len(pending) > 0 {
		if e = consume(); e != nil {
			return e
		}
	}
	var ix bytes.Buffer
	ix.WriteString("FWIX0001")
	putU(&ix, uint64(len(cat.Groups)))
	for _, g := range cat.Groups {
		putU(&ix, g.Stored)
		putU(&ix, g.Raw)
		ix.WriteByte(g.Codec)
		ix.Write(g.Hash[:])
	}
	putU(&ix, uint64(len(cat.Entries)))
	for _, a := range cat.Entries {
		k := byte(2)
		if a.Directory {
			k = 1
		}
		ix.WriteByte(k)
		putU(&ix, uint64(len(a.Name)))
		putU(&ix, a.Size)
		putU(&ix, uint64(a.Stamp<<1)^uint64(a.Stamp>>63))
		ix.WriteString(a.Name)
		if !a.Directory {
			ix.Write(a.Hash[:])
		}
	}
	if ix.Len() > indexLimit {
		return errors.New(tr("Каталог слишком велик"))
	}
	data := enc.EncodeAll(ix.Bytes(), nil)
	codec := uint32(1)
	if len(data) >= ix.Len() {
		data = ix.Bytes()
		codec = 0
	}
	trailer := make([]byte, 72)
	copy(trailer, "FAWIDX04")
	binary.LittleEndian.PutUint64(trailer[8:], offset)
	binary.LittleEndian.PutUint64(trailer[16:], uint64(len(data)))
	binary.LittleEndian.PutUint64(trailer[24:], uint64(ix.Len()))
	binary.LittleEndian.PutUint32(trailer[32:], codec)
	digest := sha256.New()
	digest.Write(header)
	digest.Write(data)
	digest.Write(trailer[:40])
	copy(trailer[40:], digest.Sum(nil))
	if _, e = f.Write(data); e != nil {
		return e
	}
	if _, e = f.Write(trailer); e != nil {
		return e
	}
	if e = f.Sync(); e != nil {
		return e
	}
	if e = f.Close(); e != nil {
		return e
	}
	if e = check(ctx); e != nil {
		return e
	}
	if e = beforeArchivePublish(ctx, f.Name()); e != nil {
		return e
	}
	if e = publishFile(f.Name(), output); e != nil {
		return e
	}
	progress(100, tr("Готово"))
	return nil
}
func readCatalogue(ctx context.Context, p string) (cat catalogue, err error) {
	bad := errors.New(tr("Повреждён каталог FAW 3"))
	f, e := os.Open(p)
	if e != nil {
		return cat, e
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil {
		return cat, e
	}
	if st.Size() < 104 || uint64(st.Size()) > maxTotal+(1<<30) {
		return cat, bad
	}
	h := make([]byte, 32)
	t := make([]byte, 72)
	if _, e = f.ReadAt(h, 0); e != nil {
		return cat, e
	}
	if _, e = f.ReadAt(t, st.Size()-72); e != nil {
		return cat, e
	}
	if !equalBytes(h[:8], fawMagic[:]) || binary.LittleEndian.Uint16(h[8:10]) != 3 || binary.LittleEndian.Uint16(h[10:12]) != 1 || binary.LittleEndian.Uint32(h[12:]) != faw3Window || binary.LittleEndian.Uint32(h[28:]) != crc32.ChecksumIEEE(h[:28]) || string(t[:8]) != "FAWIDX04" || binary.LittleEndian.Uint32(t[36:]) != 0 {
		return cat, bad
	}
	cat.Total = binary.LittleEndian.Uint64(h[16:])
	count := binary.LittleEndian.Uint32(h[24:])
	if cat.Total > maxTotal || count > maxFiles {
		return cat, bad
	}
	off := binary.LittleEndian.Uint64(t[8:])
	stored := binary.LittleEndian.Uint64(t[16:])
	rawlen := binary.LittleEndian.Uint64(t[24:])
	codec := binary.LittleEndian.Uint32(t[32:])
	if off < 32 || off > uint64(st.Size()-72) || stored == 0 || stored > indexLimit || rawlen == 0 || rawlen > indexLimit || stored != uint64(st.Size()-72)-off || codec > 1 {
		return cat, bad
	}
	data := make([]byte, int(stored))
	if _, e = f.ReadAt(data, int64(off)); e != nil {
		return cat, e
	}
	d := sha256.New()
	d.Write(h)
	d.Write(data)
	d.Write(t[:40])
	if !equalBytes(d.Sum(nil), t[40:]) {
		return cat, bad
	}
	if codec == 1 {
		dec, e := newGroupDecoder()
		if e != nil {
			return cat, e
		}
		decoded, e := dec.DecodeAll(data, make([]byte, 0, int(rawlen)))
		dec.Close()
		if e != nil {
			return cat, e
		}
		data = decoded
	}
	if uint64(len(data)) != rawlen {
		return cat, bad
	}
	r := bytes.NewReader(data)
	tag := make([]byte, 8)
	io.ReadFull(r, tag)
	if string(tag) != "FWIX0001" {
		return cat, bad
	}
	ng, e := binary.ReadUvarint(r)
	if e != nil || ng != (cat.Total+faw3Window-1)/faw3Window {
		return cat, bad
	}
	position := uint64(32)
	sum := uint64(0)
	for i := uint64(0); i < ng; i++ {
		if e = check(ctx); e != nil {
			return cat, e
		}
		gs, e := binary.ReadUvarint(r)
		if e != nil {
			return cat, bad
		}
		gr, e := binary.ReadUvarint(r)
		if e != nil {
			return cat, bad
		}
		gc, e := r.ReadByte()
		if e != nil || gc > 1 || gr == 0 || gr > faw3Window || gs == 0 || gs > gr || gc == 0 && gs != gr || i+1 < ng && gr != faw3Window || position > off || gs > off-position {
			return cat, bad
		}
		g := groupDesc{Offset: position, Stored: gs, Raw: gr, Codec: gc}
		if _, e = io.ReadFull(r, g.Hash[:]); e != nil {
			return cat, bad
		}
		cat.Groups = append(cat.Groups, g)
		position += gs
		sum += gr
	}
	if position != off || sum != cat.Total {
		return cat, bad
	}
	ne, e := binary.ReadUvarint(r)
	if e != nil || ne != uint64(count) {
		return cat, bad
	}
	guard := newNameGuard()
	cursor := uint64(0)
	for i := uint64(0); i < ne; i++ {
		if e = check(ctx); e != nil {
			return cat, e
		}
		k, e := r.ReadByte()
		if e != nil || k < 1 || k > 2 {
			return cat, bad
		}
		nl, e := binary.ReadUvarint(r)
		if e != nil || nl == 0 || nl > 3000 {
			return cat, bad
		}
		sz, e := binary.ReadUvarint(r)
		if e != nil || sz > maxSingle || sz > cat.Total-cursor || k == 1 && sz != 0 {
			return cat, bad
		}
		stamp, e := binary.ReadUvarint(r)
		if e != nil {
			return cat, bad
		}
		name := make([]byte, int(nl))
		if _, e = io.ReadFull(r, name); e != nil {
			return cat, bad
		}
		a := indexedEntry{archiveEntry: archiveEntry{Name: string(name), Size: sz, Directory: k == 1}, Stamp: int64(stamp>>1) ^ -int64(stamp&1), Start: cursor}
		if e = guard.validate(a.Name, a.Directory); e != nil {
			return cat, e
		}
		if k == 2 {
			if _, e = io.ReadFull(r, a.Hash[:]); e != nil {
				return cat, bad
			}
			cursor += sz
		}
		a.SizeKnown = !a.Directory
		a.Modified = a.Stamp
		a.DateKnown = true
		cat.Entries = append(cat.Entries, a)
	}
	if cursor != cat.Total || r.Len() != 0 {
		return cat, bad
	}
	return cat, nil
}
func newGroupDecoder() (*zstd.Decoder, error) {
	return zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxWindow(faw3Window), zstd.WithDecoderMaxMemory(indexLimit), zstd.WithDecodeAllCapLimit(true))
}
func walkIndexed(ctx context.Context, p, dest string, progress report, visit entryVisitor) error {
	if progress == nil {
		progress = func(int, string) {}
	}
	cat, e := readCatalogue(ctx, p)
	if e != nil {
		return e
	}
	if avFromContext(ctx) != nil || entryFactory(ctx) != nil {
		entries := make([]archiveEntry, 0, len(cat.Entries))
		for _, entry := range cat.Entries {
			entries = append(entries, entry.archiveEntry)
		}
		if e := validateEditionMetadata(entries); e != nil {
			return e
		}
	}
	if visit != nil {
		for _, a := range cat.Entries {
			visit(a.archiveEntry)
		}
	}
	if dest == "" && avFromContext(ctx) == nil && entryFactory(ctx) == nil {
		return nil
	}
	sink, e := newExtractionSink(ctx, dest)
	if e != nil {
		return e
	}
	sink.selected = selectedName(ctx)
	defer sink.cleanup()
	f, e := os.Open(p)
	if e != nil {
		return e
	}
	defer f.Close()

	first, last := 0, len(cat.Groups)
	if sink.selected != "" {
		first, last = 0, 0
		for _, a := range cat.Entries {
			if a.Name == sink.selected && !a.Directory && a.Size > 0 {
				first = int(a.Start / faw3Window)
				last = int((a.Start + a.Size + faw3Window - 1) / faw3Window)
			}
		}
	}
	reader := newGroupReader(ctx, f, cat.Groups, first, last)
	defer reader.close()
	cached := -1
	var raw []byte
	var done uint64
	found := sink.selected == ""
	for _, a := range cat.Entries {
		if e = check(ctx); e != nil {
			return e
		}
		if sink.selected != "" && a.Name != sink.selected {
			continue
		}
		found = true
		if a.Directory {
			if e = sink.directory(a.Name); e != nil {
				return e
			}
			sink.directoryTimestamp(a.Name, time.Unix(a.Stamp, 0))
			continue
		}
		w, e := sink.file(a.Name)
		if e != nil {
			return e
		}
		hash := sha256.New()
		e = func() error {
			defer w.Close()
			cursor, left := a.Start, a.Size
			for left > 0 {
				if e = check(ctx); e != nil {
					return e
				}
				gi := int(cursor / faw3Window)
				g := cat.Groups[gi]
				if cached != gi {
					raw, e = reader.load(gi)
					if e != nil {
						return e
					}
					cached = gi
				}

				offset := cursor % faw3Window
				n := g.Raw - offset
				if n > left {
					n = left
				}
				b := raw[offset : offset+n]
				if _, e = w.Write(b); e != nil {
					return e
				}
				hash.Write(b)
				cursor += n
				left -= n
				done += n
				progress(int(done*99/max(1, cat.Total)), tr("Распаковка: ")+a.Name)
			}
			if !equalBytes(hash.Sum(nil), a.Hash[:]) {
				return errors.New(tr("SHA-256 файла не совпадает"))
			}
			return nil
		}()
		if e != nil {
			return e
		}
		sink.timestamp(a.Name, time.Unix(a.Stamp, 0))
	}
	if !found {
		return errors.New(tr("Файл отсутствует в архиве"))
	}
	return sink.publish(ctx)
}
