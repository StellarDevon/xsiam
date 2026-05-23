$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')
$scriptPath = Join-Path $repoRoot 'initdb\validate_xsiamdb.js'
$wslScriptPath = '/mnt/d/src/xsiam/initdb/validate_xsiamdb.js'

if (!(Test-Path $scriptPath)) {
    throw "Validation script not found: $scriptPath"
}

wsl -d Ubuntu-24.04 -- bash -lc "systemctl start arangodb3 && arangosh --server.endpoint tcp://127.0.0.1:8529 --server.username root --server.password changeme --javascript.execute $wslScriptPath"
