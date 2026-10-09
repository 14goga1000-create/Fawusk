package customav

// Integration sketch for a Go archiver. Keep this code as a guide; adapt the
// UI and archive library to the host application.
//
// result, err := scanner.ScanPath(ctx, archivePath)
// if err != nil { return err }
// switch {
// case result.IsMalware():
//     return fmt.Errorf("archive blocked: %s", result.Verdict)
// case result.IsTestSignature():
//     // In a test build, mark the detection. In production, do not call it a virus.
// case result.NeedsReview():
//     // Ask the user or follow the configured policy.
// default:
//     // Continue only after archive path and extraction limits are validated.
// }
