param(
    [int]$Total = 1000000,
    [switch]$Generate
)

$ErrorActionPreference = 'Stop'

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..\..')
$mockDir = Join-Path $repoRoot 'initdb\mock'
$dataDir = Join-Path $mockDir 'data'
$generator = Join-Path $mockDir 'generate_mock_data.py'

$collections = @(
    'tenants',
    'rbac_roles',
    'users',
    'agent_policies',
    'assets',
    'devices',
    'vulnerabilities',
    'iocs',
    'intel_feeds',
    'datasources',
    'detection_rules',
    'alerts',
    'incidents',
    'actions',
    'playbooks',
    'reports',
    'identity_risks',
    'privilege_restrictions',
    'exposure_scores',
    'causality_nodes',
    'causality_edges',
    'audit_logs'
)

if ($Generate -or !(Test-Path (Join-Path $dataDir 'manifest.json'))) {
    python $generator --out $dataDir --total $Total
}

.\initdb\run_init_xsiamdb.ps1

$wslDataDir = '/mnt/d/src/xsiam/initdb/mock/data'

$truncateScript = @'
db._useDatabase("xsiamdb");
const collections = [
  "tenants","rbac_roles","users","agent_policies","assets","devices",
  "vulnerabilities","iocs","intel_feeds","datasources","detection_rules",
  "alerts","incidents","actions","playbooks","reports","identity_risks",
  "privilege_restrictions","exposure_scores","causality_edges",
  "causality_nodes","audit_logs"
];
collections.forEach((name) => db._collection(name).truncate({ compact: false }));
print("truncated=" + collections.length);
'@
$bytes = [Text.Encoding]::UTF8.GetBytes($truncateScript)
$encoded = [Convert]::ToBase64String($bytes)
wsl -d Ubuntu-24.04 -- bash -lc "echo $encoded | base64 -d > /tmp/truncate-xsiamdb-mock.js && arangosh --server.endpoint tcp://127.0.0.1:8529 --server.username root --server.password changeme --javascript.execute /tmp/truncate-xsiamdb-mock.js"

foreach ($collection in $collections) {
    $file = "$wslDataDir/$collection.jsonl"
    Write-Host "Importing $collection"
    wsl -d Ubuntu-24.04 -- bash -lc "arangoimport --server.endpoint tcp://127.0.0.1:8529 --server.username root --server.password changeme --server.database xsiamdb --collection $collection --file $file --type jsonl --on-duplicate update --threads 2 --batch-size 16777216"
}

.\initdb\mock\validate_mock_counts.ps1
