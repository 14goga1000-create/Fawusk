# Third-party notices

The executable statically includes portions of the Go runtime and standard library. Their license follows.

```text
Copyright 2009 The Go Authors.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google LLC nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

```

Resource generation uses go-winres v0.3.3 / winres v0.2.1 at build time. Those tools are not bundled with or required to run the EXE. Icons in this repository are original project assets.

## Zstandard implementation

The executable includes `github.com/klauspost/compress v1.20.1` (BSD-3-Clause). Its full license is in [docs/licenses/klauspost-compress.txt](docs/licenses/klauspost-compress.txt). Zstandard is an existing compression algorithm; it is not claimed as an invention of this project.

The linked Zstandard implementation also includes xxhash; see [its license](docs/licenses/xxhash.txt).


## CustomAV Faw Edition / CustomAV 0.5 reference
The owner supplied the licensed CustomAV Faw Edition v0.5 package, including LICENSE (MIT, Copyright (c) 2026 CustomAV Project) and NOTICE.md. The supplied licence explicitly permits Fawusk Contributors to include, modify and redistribute the CustomAV code while retaining the copyright and permission notice. The full unchanged licence is included in [docs/licenses/CustomAV-MIT.txt](docs/licenses/CustomAV-MIT.txt), reference/customav_faw_edition/LICENSE and security/fawsecurity/LICENSE. Upstream notice is retained in reference/customav_faw_edition/NOTICE.md and docs/licenses/CustomAV-NOTICE.md.

The supplied Faw Edition branch includes the unchanged base_v05 reference engine. The duplicated earlier reference branch was removed in 0.8 after verifying identical engine bytes. Its base instruction is retained under reference/customav_faw_edition/provenance, and the report schema under protocol/base_scan_result.schema.json. The Go policy/envelope layer is adapted in security/fawsecurity, with adapter in customav_faw_edition.go and native static rules in customav*.go; modifications and limits are documented in docs/CUSTOMAV.md. Runtime does not execute the reference Python bridge or extraction tools. Third-party runtime/library rights remain under their respective licences.

Only the garbled ZIP instruction filename was normalised to BEFORE_INTEGRATION_RU.md. This licensed package adds LICENSE, NOTICE.md and licence statements to README/instruction; its functional source files match the previously supplied Faw Edition package. The licence-only update retained alpha 0.7.1. Alpha 0.8 adds resource settings and localisation without changing archive format or detector rules. The memorandum is cooperation documentation, not a replacement for the now-supplied MIT licence. Fawusk's code, format and project materials retain their own rights.
