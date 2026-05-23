# -*- coding: utf-8 -*-
import sys, os, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')

ROOT = r'D:\src\xsiam\web\src'
fixes = [
    ('total_终端', 'total_endpoints'),
    ('total_用户管理', 'total_users'),
    ('total_云资产', 'total_cloud_assets'),
    ("overflowY: '自动'", "overflowY: 'auto'"),
    ("overflow: '自动'", "overflow: 'auto'"),
    ("overflowX: '自动'", "overflowX: 'auto'"),
    ("stats?.已修复", "stats?.patched"),
    ('kpi?.total_终端', 'kpi?.total_endpoints'),
    # Also: 'auto' in style objects might have been translated in other ways
    # Check for other CSS property values that got translated
    ("position: '绝对'", "position: 'absolute'"),
    ("position: '相对'", "position: 'relative'"),
    ("position: '固定'", "position: 'fixed'"),
    ("display: '块'", "display: 'block'"),
    ("display: '无'", "display: 'none'"),
    ("display: '灵活'", "display: 'flex'"),
    ("visibility: '隐藏'", "visibility: 'hidden'"),
    ("visibility: '可见'", "visibility: 'visible'"),
    ("cursor: '指针'", "cursor: 'pointer'"),
    ("cursor: '默认'", "cursor: 'default'"),
    ("textAlign: '中心'", "textAlign: 'center'"),
    ("textAlign: '左'", "textAlign: 'left'"),
    ("textAlign: '右'", "textAlign: 'right'"),
    ("fontWeight: '粗体'", "fontWeight: 'bold'"),
    ("fontWeight: '正常'", "fontWeight: 'normal'"),
    ("flexDirection: '行'", "flexDirection: 'row'"),
    ("flexDirection: '列'", "flexDirection: 'column'"),
    ("alignItems: '中心'", "alignItems: 'center'"),
    ("justifyContent: '中心'", "justifyContent: 'center'"),
    ("whiteSpace: '无换行'", "whiteSpace: 'nowrap'"),
    ("pointerEvents: '无'", "pointerEvents: 'none'"),
    # Vulnerabilities patched field
    (".已修复 ", ".patched "),
    ("?.已修复", "?.patched"),
]

changed = []
for dirpath, dirnames, filenames in os.walk(ROOT):
    for fn in filenames:
        if not fn.endswith('.tsx'):
            continue
        path = os.path.join(dirpath, fn)
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            content = f.read()
        original = content
        for old, new in fixes:
            content = content.replace(old, new)
        if content != original:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(content)
            changed.append(fn)
            print('fixed:', fn)

print('done,', len(changed), 'files')
