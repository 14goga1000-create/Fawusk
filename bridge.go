package customav

import (
    "context"
    "io"

    "example.com/customav-faw-edition/go/fawsecurity"
)

// FawEntryScanner adapts the Python-reference CustomAV client to Faw Edition.
type FawEntryScanner struct { Client Client }

func (a FawEntryScanner) ScanReader(ctx context.Context, name string, r io.Reader) (fawsecurity.ScanResult, error) {
    result, err := a.Client.ScanReader(ctx, name, r)
    if err != nil { return fawsecurity.ScanResult{}, err }
    out := fawsecurity.ScanResult{Verdict: result.Verdict, MalwareSignal: result.MalwareSignal, TestSignal: result.TestSignal, ReviewSignal: result.ReviewSignal}
    for _, f := range result.Findings {
        out.Findings = append(out.Findings, fawsecurity.Finding{Severity:f.Severity, Rule:f.Rule, Path:f.Path, Detail:f.Detail, Points:f.Points, Category:f.Category})
    }
    return out, nil
}
