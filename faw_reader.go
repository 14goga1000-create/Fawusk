package main

// FawReader is a read-only format adapter, not another antivirus.
// Existing FAW decoders validate headers, catalogue/path/size quotas and checksums.
// Entry streams are delivered to CustomAV via callbacks; no target is executed.
import (
	"context"
	"errors"
	"io"
)

type FawReader struct {
	Path    string
	Version int
}

func NewFawReader(p string) (*FawReader, error) {
	v, e := archiveVersion(p)
	if e != nil {
		return nil, e
	}
	if v < 1 || v > 3 {
		return nil, errors.New(tr("Неверная сигнатура или неподдерживаемая версия FAW"))
	}
	return &FawReader{p, v}, nil
}

type entryStreamFactoryKey struct{}
type entryStreamFactory func(string) (io.WriteCloser, error)

func entryFactory(ctx context.Context) entryStreamFactory {
	f, _ := ctx.Value(entryStreamFactoryKey{}).(entryStreamFactory)
	return f
}
func (r *FawReader) List(ctx context.Context) ([]archiveEntry, error) {
	ctx = context.WithValue(ctx, avContextKey{}, (*avRun)(nil))
	ctx = context.WithValue(ctx, entryStreamFactoryKey{}, entryStreamFactory(nil))
	ctx = context.WithValue(ctx, selectionKey{}, "")
	return scanArchive(ctx, r.Path, nil)
}
func (r *FawReader) ReadAll(ctx context.Context, consumer func(archiveEntry) (io.WriteCloser, error), progress report) error {
	entries, e := r.List(ctx)
	if e != nil {
		return e
	}
	if e := validateEditionMetadata(entries); e != nil {
		return e
	}
	metadata := make(map[string]archiveEntry, len(entries))
	for _, entry := range entries {
		metadata[entry.Name] = entry
		avVisitMetadata(ctx, entry)
	}
	factory := entryStreamFactory(func(name string) (io.WriteCloser, error) {
		entry, ok := metadata[name]
		if !ok || entry.Directory {
			return nil, errors.New(tr("Поток отсутствует в каталоге FAW"))
		}
		return consumer(entry)
	})
	ctx = context.WithValue(ctx, avContextKey{}, (*avRun)(nil))
	ctx = context.WithValue(ctx, entryStreamFactoryKey{}, factory)
	return unpack(ctx, r.Path, "", progress)
}

type fawEntryStream struct {
	*io.PipeReader
	cancel context.CancelFunc
}

func (s *fawEntryStream) Close() error { s.cancel(); return s.PipeReader.Close() }

type pipeEntryWriter struct{ *io.PipeWriter }

func (*pipeEntryWriter) Close() error { return nil } // decoder must verify checksum first
func (r *FawReader) OpenEntry(ctx context.Context, name string) (io.ReadCloser, error) {
	entries, e := r.List(ctx)
	if e != nil {
		return nil, e
	}
	found := false
	for _, a := range entries {
		if a.Name == name && !a.Directory {
			found = true
		}
	}
	if !found {
		return nil, errors.New(tr("Entry отсутствует в FAW"))
	}
	ctx, cancel := context.WithCancel(ctx)
	ctx = context.WithValue(ctx, selectionKey{}, name)
	pr, pw := io.Pipe()
	go func() {
		e := r.ReadAll(ctx, func(a archiveEntry) (io.WriteCloser, error) {
			if a.Name != name {
				return discardCloser{io.Discard}, nil
			}
			return &pipeEntryWriter{pw}, nil
		}, nil)
		pw.CloseWithError(e)
	}()
	return &fawEntryStream{pr, cancel}, nil
}

type avMetadataVisitorKey struct{}

func avVisitMetadata(ctx context.Context, entry archiveEntry) {
	if visit, ok := ctx.Value(avMetadataVisitorKey{}).(entryVisitor); ok {
		visit(entry)
	}
}
