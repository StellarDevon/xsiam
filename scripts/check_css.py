# -*- coding: utf-8 -*-
import sys, re
sys.stdout.reconfigure(encoding='utf-8', errors='replace')
with open(r'src/index.css', 'r', encoding='utf-8', errors='replace') as f:
    css = f.read()
# Find :root block
root_m = re.search(r':root\s*\{([^}]+)\}', css)
if root_m:
    print('ROOT VARS:')
    print(root_m.group(1)[:800])
print()
# Find all .btn- definitions
for m in re.finditer(r'\.btn-\w+[^{]*\{[^}]+\}', css):
    print(m.group()[:200])
    print()
