# -*- coding: utf-8 -*-
"""
Fix i18n over-replacement damage in TSX files.
These patterns were incorrectly translated because they matched JS identifiers.
"""
import os, re, sys

ROOT = r'D:\src\xsiam\web\src'

# Byte-level fixes: revert Chinese back to English inside JS contexts
# Pattern: look for CJK bytes that are part of JS identifiers or code (not JSX text)
BYTE_FIXES = [
    # 'total' -> '条' hit object key {total: 0}, meta.total, total_endpoints, etc.
    # Revert: .条 -> .total (property access)
    (b'.total\n', b'.total\n'),  # already fixed meta.total by earlier script
    # total: 0 in object literals - the key 'total' became '条'
    # { page: 1, page_size: 20, 条: 0, total_pages: 1 }
    # Already fixed by earlier script for meta.条 -> meta.total and 条_pages -> total_pages
    # But the key in useState still shows 条: 0
    # Let's use regex-based approach
]

# Use Python regex on text (utf-8) for surgical fixes
TEXT_FIXES = [
    # useState PageMeta initializers: { ... 条: 0, ... } -> total: 0
    (r'\{ page: 1, page_size: 20, 条: 0, total_pages: 1 \}',
     '{ page: 1, page_size: 20, total: 0, total_pages: 1 }'),
    (r'\{ page:1, page_size:20, 条:0, total_pages:1 \}',
     '{ page:1, page_size:20, total:0, total_pages:1 }'),
    # Dashboard type: total_alerts, total_incidents, total_assets, total_vulns
    (r'条_alerts', 'total_alerts'),
    (r'条_incidents', 'total_incidents'),
    (r'条_assets', 'total_assets'),
    (r'条_vulns', 'total_vulns'),
    # Assets KPI type fields: total_endpoints, total_users, total_cloud
    (r'条_endpoints', 'total_endpoints'),
    (r'条_users', 'total_users'),
    (r'条_cloud', 'total_cloud'),
    (r'条_vuln', 'total_vuln'),
    # mttr_hours
    (r'mttr_小时', 'mttr_hours'),
    # steps_total in Playbooks
    (r'steps_条', 'steps_total'),
    # iocMeta.total, feedMeta.total
    (r'iocMeta\.条', 'iocMeta.total'),
    (r'feedMeta\.条', 'feedMeta.total'),
    # meta.total (shouldn't be needed after previous fix, but just in case)
    (r'meta\.条', 'meta.total'),
    # 'total' as key in object: {total: ...} but NOT in JSX text "条"
    # rows variable names: csvRows became csv条记录 etc.
    (r'csv条记录', 'csvRows'),
    (r'\bcsvRows\b', 'csvRows'),  # keep existing correct ones
    # QueryCenter: rows variable
    (r'\b条记录\b(?!\s*<)', 'rows'),  # '条记录' as variable name (not in JSX)
    # timeRangeLabels: '近24小时' etc. - keep these, they're UI text
    # But '近' should remain since it's '近24H' -> '近24小时' (correct translation)
    # Dashboard.tsx timeRange keys like '24h': '近24小时' - correct, keep
    # The broken one was: timeRangeLabels = { '24h': '近24小时' } - that's OK actually
    # Check: 'Last 24H' -> '近24小时' is correct UI text
]

# Additional specific fixes per file
FILE_SPECIFIC = {
    'pages/Assets.tsx': [
        # KPI type fields
        (r'条: number', 'total: number'),
        (r'条_endpoints: number', 'total_endpoints: number'),
        (r'条_users: number', 'total_users: number'),
        (r'条_cloud_assets: number', 'total_cloud_assets: number'),
        # KPI label in array: ['endpoint', '终端', kpi?.条_endpoints] -> total_endpoints
        (r"kpi\?\.条_endpoints", "kpi?.total_endpoints"),
        (r"kpi\?\.条_users", "kpi?.total_users"),
        (r"kpi\?\.条_cloud_assets", "kpi?.total_cloud_assets"),
        (r"kpi\?\.条", "kpi?.total"),
        # in text: '终端总数' value: (kpi?.total_endpoints ?? 0) - already fixed above
        # '终端总数' label and value: {(kpi?.条_endpoints -> total_endpoints
        # '活跃Agent覆盖' note calculation
    ],
    'pages/Dashboard.tsx': [
        (r'stats\?\.条_alerts', 'stats?.total_alerts'),
        (r'stats\?\.条_incidents', 'stats?.total_incidents'),
        (r'stats\?\.条_assets', 'stats?.total_assets'),
        (r'stats\?\.条_vulns', 'stats?.total_vulns'),
        (r'stats\?\.mttr_小时', 'stats?.mttr_hours'),
        (r'\btype.*?条_alerts: number', 'total_alerts: number'),
        (r'\btype.*?条_incidents: number', 'total_incidents: number'),
    ],
    'pages/QueryCenter.tsx': [
        # rows variable: const rows = ... ; rows.forEach etc.
        # Only revert '条记录' when used as a variable name, not in JSX text
    ],
    'pages/ThreatIntel.tsx': [
        (r'iocMeta\.条', 'iocMeta.total'),
        (r'feedMeta\.条', 'feedMeta.total'),
    ],
    'pages/Vulnerabilities.tsx': [
        # critSevCount variable
        (r'条SevCount', 'critSevCount'),
        # stats?.patched -> already translated label 'patched' -> '已修复' but this is in JS code
        # Check: stats?.patched is a DB field -> should NOT be translated
        (r"stats\?\.已修复", "stats?.patched"),
    ],
    'pages/Playbooks.tsx': [
        (r'r\.steps_条\b', 'r.steps_total'),
        (r'steps_条\b', 'steps_total'),
        # "步完成" is fine for UI label "步 完成"
        # But {r.steps_done}/{r.steps_total} 步 {fmt...} - need to fix
    ],
    'pages/Alerts.tsx': [
        # '条' in jsx: meta.total 条 is ok in display but check meta initializer
    ],
}

def fix_file(path, extra_fixes=None):
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    original = content

    # Apply global text fixes
    for pattern, replacement in TEXT_FIXES:
        content = re.sub(pattern, replacement, content)

    # Apply file-specific fixes
    if extra_fixes:
        for pattern, replacement in extra_fixes:
            content = re.sub(pattern, replacement, content)

    if content != original:
        with open(path, 'w', encoding='utf-8') as f:
            f.write(content)
        return True
    return False

changed = []
for rel_path in [
    'pages/Actions.tsx',
    'pages/Alerts.tsx',
    'pages/Assets.tsx',
    'pages/Dashboard.tsx',
    'pages/DetectionRules.tsx',
    'pages/Devices.tsx',
    'pages/ExposureScores.tsx',
    'pages/IdentityRisks.tsx',
    'pages/Incidents.tsx',
    'pages/IntelFeeds.tsx',
    'pages/IOCs.tsx',
    'pages/Playbooks.tsx',
    'pages/QueryCenter.tsx',
    'pages/Reports.tsx',
    'pages/ThreatIntel.tsx',
    'pages/Vulnerabilities.tsx',
    'components/Sidebar.tsx',
]:
    path = os.path.join(ROOT, rel_path)
    if not os.path.exists(path):
        print(f'MISSING: {path}')
        continue
    extra = FILE_SPECIFIC.get(rel_path, [])
    if fix_file(path, extra):
        changed.append(rel_path)
        print(f'✓ {rel_path}')
    else:
        print(f'  {rel_path} (no change)')

print(f'\n完成：{len(changed)} 个文件已修改')
