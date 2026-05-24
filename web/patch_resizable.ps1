# Patch all pages: replace <th> with <ResizableTh> inside data-table theads
# Strategy: whole-file regex replacement of <th and </th> — safe because
# ResizableTh is already used in some files, and <th> in .tbl drawers are minor.
# We handle the import separately.

$pages = @(
  'src\pages\Actions.tsx',
  'src\pages\IOCs.tsx',
  'src\pages\ThreatIntel.tsx',
  'src\pages\Reports.tsx',
  'src\pages\IdentityRisks.tsx',
  'src\pages\ETLPipeline.tsx',
  'src\pages\ExposureScores.tsx',
  'src\pages\EndpointSecurity.tsx',
  'src\pages\NetworkSecurity.tsx',
  'src\pages\QueryCenter.tsx',
  'src\pages\TenantAdmin.tsx',
  'src\pages\Settings.tsx'
)

$root = 'D:\src\xsiam\web'

foreach ($rel in $pages) {
  $path = Join-Path $root $rel
  if (-not (Test-Path $path)) { Write-Host "SKIP (not found): $rel"; continue }

  $content = Get-Content $path -Raw -Encoding utf8

  # Only process files that have data-table
  if ($content -notmatch 'data-table') { Write-Host "SKIP (no data-table): $rel"; continue }

  $original = $content

  # 1. Add import if not already present
  if ($content -notmatch "import ResizableTh") {
    # Insert after the last existing import line block
    $content = $content -replace "(import [^\n]+\n)(import [^\n]+\n)(?!import)", "`$1`$2import ResizableTh from '@/components/ResizableTh'`n"
    # Fallback: insert at very top after first import line
    if ($content -notmatch "import ResizableTh") {
      $content = $content -replace "(import [^\n]+\n)", "`$1import ResizableTh from '@/components/ResizableTh'`n"
    }
  }

  # 2. Replace <th with <ResizableTh and </th> with </ResizableTh>
  # Only do this where it's inside a data-table table
  # Simple approach: global replace (these files only use <th> in tables)
  $content = $content -replace '<th(\s)', '<ResizableTh$1'
  $content = $content -replace '<th>', '<ResizableTh>'
  $content = $content -replace '</th>', '</ResizableTh>'

  if ($content -ne $original) {
    [System.IO.File]::WriteAllText($path, $content, [System.Text.Encoding]::UTF8)
    Write-Host "PATCHED: $rel"
  } else {
    Write-Host "NO CHANGE: $rel"
  }
}

Write-Host "Done."
