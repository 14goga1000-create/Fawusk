package fawsecurity

import (
	"context"
	"io"
)

type Entry struct {
	Path           string
	Size           int64
	CompressedSize int64
	Encrypted      bool
	Directory      bool
	Open           func(context.Context) (io.ReadCloser, error) `json:"-"`
	SHA256         string                                       `json:"sha256,omitempty"`
	Link           bool                                         `json:"is_link"`
}

type FawReader interface {
	Entries(context.Context) ([]Entry, error)
}

type EntryScanner interface {
	ScanReader(context.Context, string, io.Reader) (ScanResult, error)
}

type ScanResult struct {
	Verdict       string    `json:"verdict"`
	MalwareSignal int       `json:"malware_signal_score"`
	TestSignal    int       `json:"test_signal_score"`
	ReviewSignal  int       `json:"review_signal_score"`
	Incomplete    bool      `json:"incomplete"`
	Findings      []Finding `json:"findings"`
}

type Finding struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Path     string `json:"path"`
	Detail   any    `json:"detail"`
	Points   int    `json:"points"`
	Category string `json:"category"`
}

type EntryReport struct {
	Entry  Entry
	Result *ScanResult
	Status string // clean, review, blocked, incomplete
	Error  string
}

type Report struct {
	Format     string
	Entries    []EntryReport
	Verdict    string
	Status     string
	Scanned    int
	Blocked    int
	Review     int
	Incomplete int
	Errors     []string
}

type Config struct {
	EntryScanner     EntryScanner
	MaxEntries       int
	MaxUnpackedBytes int64
	MaxEntryBytes    int64
}
