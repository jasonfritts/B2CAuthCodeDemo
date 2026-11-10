[CmdletBinding()]
param(
    [ValidateRange(1024, 65535)]
    [int]$Port = 8400,

    [switch]$NoBrowser
)

$ErrorActionPreference = 'Stop'
$root = [System.IO.Path]::GetFullPath((Split-Path -Parent $MyInvocation.MyCommand.Path))
$prefix = "http://localhost:$Port/"
$listener = [System.Net.HttpListener]::new()
$listener.Prefixes.Add($prefix)

try {
    $listener.Start()
    Write-Host "B2C PKCE demo is running at ${prefix}index.html" -ForegroundColor Green
    Write-Host 'Press Ctrl+C to stop.' -ForegroundColor Gray
    if (-not $NoBrowser) {
        Start-Process "${prefix}index.html"
    }

    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $relativePath = [uri]::UnescapeDataString($context.Request.Url.AbsolutePath.TrimStart('/'))
        if (-not $relativePath) { $relativePath = 'index.html' }
        $filePath = [System.IO.Path]::GetFullPath((Join-Path $root $relativePath))

        if (-not $filePath.StartsWith($root, [System.StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path $filePath -PathType Leaf)) {
            $context.Response.StatusCode = 404
            $bytes = [System.Text.Encoding]::UTF8.GetBytes('Not found')
        } else {
            $extension = [System.IO.Path]::GetExtension($filePath).ToLowerInvariant()
            $context.Response.ContentType = switch ($extension) {
                '.html' { 'text/html; charset=utf-8' }
                '.js'   { 'text/javascript; charset=utf-8' }
                '.json' { 'application/json; charset=utf-8' }
                default { 'application/octet-stream' }
            }
            $context.Response.Headers.Add('Cache-Control', 'no-store')
            $bytes = [System.IO.File]::ReadAllBytes($filePath)
        }

        $context.Response.ContentLength64 = $bytes.Length
        $context.Response.OutputStream.Write($bytes, 0, $bytes.Length)
        $context.Response.Close()
    }
} finally {
    $listener.Stop()
    $listener.Close()
}