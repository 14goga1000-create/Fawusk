$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    New-Item -ItemType Directory -Force dist | Out-Null
    go run github.com/tc-hib/go-winres@v0.3.3 make --arch amd64
    if ($LASTEXITCODE -ne 0) { throw 'Resource generation failed.' }
    $oldOS = $env:GOOS; $oldArch = $env:GOARCH; $oldCGO = $env:CGO_ENABLED
    try {
        $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
        go build -trimpath -ldflags='-s -w -H=windowsgui' -o dist/Fawusk-alpha-0.4.exe .
        if ($LASTEXITCODE -ne 0) { throw 'Build failed.' }
    } finally { $env:GOOS = $oldOS; $env:GOARCH = $oldArch; $env:CGO_ENABLED = $oldCGO }
    $hash = (Get-FileHash dist/Fawusk-alpha-0.4.exe -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  Fawusk-alpha-0.4.exe" | Set-Content -Encoding ascii dist/SHA256SUMS.txt
    Write-Host 'Built dist/Fawusk-alpha-0.4.exe (unsigned alpha).'
} finally { Pop-Location }
