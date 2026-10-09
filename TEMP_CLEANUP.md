# Owned preview Temp lifecycle — alpha 0.5

Each permitted preview creates a random direct child of the current user's Temp directory: `Fawusk-preview-<128-bit random token>-<random suffix>`. A small `.fawusk-owned-preview` marker contains version magic, owning PID and token in a bounded plain-text record. The selected file is under `content/`; no other archived file is written. Ownership is a housekeeping measure, not a security boundary against a malicious process already running as the same user.

Before removal, the cleaner verifies the exact Temp parent, ordinary non-reparse root, regular bounded marker, positive PID, token length and matching root prefix. It never scans arbitrary filesystem trees or deletes directories only because their names look similar. Symlink/reparse roots and unrelated Temp directories are rejected. Marker data is retained if a child is locked, so retries remain possible.

- Next preview: attempt cleanup of previous roots owned by this window.
- Normal window destruction: remove all roots owned by this window.
- If removal fails: start a separate windowless copy of Fawusk with `--cleanup-preview`, passing only those roots; it revalidates ownership, waits for the owner process to exit and retries every 500 ms for up to two minutes.
- Next application start: attempt cleanup of up to 256 valid marked orphan roots whose owning process is no longer alive. Live-owner roots are left alone. A reused PID can postpone cleanup safely.

No forced termination of viewers, global Temp purge, security-policy changes, administrator requirement or permanent background service. Long-held deletion locks, permissions, power loss, crashes, moved EXE or helper-start failure can leave directories. Automatic cleanup is best-effort, not guaranteed immediate erasure or forensic secure deletion. Old unmarked `Fawusk-view-*` folders are not eligible; remove your old folders manually after closing viewers.
