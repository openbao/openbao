# cross-compile-binary.ps1, Build Bao for the specified GOOS/GOARCH
# Expects GOOS/GOARCH (and optional GOARM) in the environment.
$ErrorActionPreference = "Stop"

if (-not $env:GOOS -or -not $env:GOARCH) {
    Write-Error "GOOS/GOARCH must be set"
    exit 1
}

# Determine output filename
$EXT = ""
if ($env:GOOS -eq "windows") {
    $EXT = ".exe"
}
$BIN = "bao-$env:GOOS-$env:GOARCH$EXT"

# Clear any previous build artifacts for cleanliness
if (Test-Path $BIN) {
    Remove-Item $BIN -Force
}

# Disable CGO for cross-compilation unless explicitly enabled
if (-not $env:CGO_ENABLED) {
    $env:CGO_ENABLED = "0"
}

# Respect BUILD_TAGS if the workflow/front-end set them; default to empty
if (-not $env:BUILD_TAGS) {
    $env:BUILD_TAGS = ""
}

$PKG = "github.com/openbao/openbao"
try {
    $GIT_COMMIT = git rev-parse --short=12 HEAD
} catch {
    $GIT_COMMIT = "unknown"
}
$BUILD_DATE = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
$LD_FLAGS = "-s -w -X $PKG/version.GitCommit=$GIT_COMMIT -X $PKG/version.BuildDate=$BUILD_DATE"

Write-Host "Cross-compiling bao for $env:GOOS/$env:GOARCH (CGO_ENABLED=$env:CGO_ENABLED)"

$buildArgs = @(
    "build",
    "-trimpath",
    "-ldflags=$LD_FLAGS",
    "-tags"
)

if ($env:BUILD_TAGS) {
    $buildArgs += $env:BUILD_TAGS
} else {
    $buildArgs += "openbao"
}

$buildArgs += @("-o", $BIN, ".")

& go @buildArgs

if ($LASTEXITCODE -ne 0) {
    Write-Error "Go build failed"
    exit 1
}

Write-Host "Built $BIN"

if ($env:GITHUB_OUTPUT) {
    Add-Content -Path $env:GITHUB_OUTPUT -Value "out=$BIN"
} 