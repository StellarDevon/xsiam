$ErrorActionPreference = 'Stop'

$manifestPath = Join-Path $PSScriptRoot 'data\manifest.json'
if (-not (Test-Path $manifestPath)) {
  throw "Manifest not found: $manifestPath"
}
$manifest = Get-Content -Raw $manifestPath | ConvertFrom-Json

$script = @'
db._useDatabase("xsiamdb");
const collections = [
  "tenants","rbac_roles","users","agent_policies","assets","devices",
  "vulnerabilities","iocs","intel_feeds","datasources","detection_rules",
  "alerts","incidents","actions","playbooks","reports","identity_risks",
  "privilege_restrictions","exposure_scores","causality_nodes",
  "causality_edges","audit_logs"
];
const counts = {};
let total = 0;
for (const name of collections) {
  counts[name] = db._collection(name).count();
  total += counts[name];
}
print(JSON.stringify({ total, counts }));
'@

$encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script))
$output = wsl -d Ubuntu-24.04 -- bash -lc "echo $encoded | base64 -d > /tmp/validate-xsiamdb-mock.js && arangosh --server.endpoint tcp://127.0.0.1:8529 --server.username root --server.password changeme --javascript.execute /tmp/validate-xsiamdb-mock.js"
$jsonLine = $output | Where-Object { $_ -match '^\{"total":' } | Select-Object -Last 1
if (-not $jsonLine) {
  $output | ForEach-Object { Write-Host $_ }
  throw 'Could not parse mock count validation output.'
}

$actual = $jsonLine | ConvertFrom-Json
$errors = [System.Collections.Generic.List[string]]::new()

if ([int64]$actual.total -ne [int64]$manifest.actual_total) {
  $errors.Add("total expected $($manifest.actual_total), actual $($actual.total)")
}
foreach ($collection in $manifest.collections.PSObject.Properties.Name) {
  $expected = [int64]$manifest.collections.$collection
  $actualCount = [int64]$actual.counts.$collection
  if ($actualCount -ne $expected) {
    $errors.Add("$collection expected $expected, actual $actualCount")
  }
}

if ($errors.Count -gt 0) {
  $errors | ForEach-Object { Write-Error $_ }
  throw "Mock data counts do not match $manifestPath"
}

$actual | ConvertTo-Json -Depth 4
