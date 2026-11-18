import json, os, subprocess, sys

here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def git(*args):
    return subprocess.run(['git', '-C', here] + list(args), capture_output=True, check=True, encoding='utf-8').stdout

commit = git('rev-parse', '--verify', (sys.argv[1] if len(sys.argv) > 1 else 'HEAD') + '^{commit}').strip()
entries = []
for record in git('ls-tree', '-r', '-l', '-z', commit, '--', 'mods/').split('\0'):
    if not record:
        continue
    meta, path = record.split('\t', 1)
    mode, kind, sha, size = meta.split()
    if kind != 'blob' or mode not in ('100644', '100755'):
        continue
    entries.append({'path': path, 'type': 'blob', 'sha': sha, 'size': int(size)})
lines = ['{', '  "format": 1,', '  "commit": ' + json.dumps(commit) + ',', '  "tree": [']
lines += ['    ' + json.dumps(entry, ensure_ascii=False) + (',' if i < len(entries) - 1 else '') for i, entry in enumerate(entries)]
lines += ['  ]', '}', '']
with open(os.path.join(here, 'tree.json'), 'w', encoding='utf-8', newline='\n') as f:
    f.write('\n'.join(lines))
print(len(entries), 'files in mods/ at', commit)
