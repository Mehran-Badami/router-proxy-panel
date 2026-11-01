"""Conservative release checks. Does not replace a manual review."""
from pathlib import Path
import re
import sys

ROOT=Path(__file__).resolve().parents[1]
TOP={'README.md','README.fa.md','LICENSE','SECURITY.md','THIRD_PARTY_NOTICES.md','Dockerfile','compose.yaml','.gitignore','.dockerignore'}
DIRS={'app':{'.py','.html'},'tests':{'.py'},'tools':{'.py'},'docs':{'.md'},'.github':{'.yml','.yaml'}}
RUNTIME={'access-token','catalog.json','state.json','health.json','runtime.json','dns-bootstrap.json','config.json','test.json','previous-config.json','sites.json','sites-previous.json'}
UUID=re.compile(r'\b[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\b')

def release_files(root=ROOT):
    result=[]
    for path in root.rglob('*'):
        if not path.is_file():continue
        rel=path.relative_to(root)
        if any(part in ('.git','__pycache__','dist') for part in rel.parts):continue
        if path.is_symlink():raise ValueError('Symlink is not permitted in a release')
        allowed=rel.as_posix() in TOP or (rel.parts[0] in DIRS and path.suffix in DIRS[rel.parts[0]])
        if not allowed or path.name in RUNTIME:raise ValueError('Unexpected release file: '+rel.as_posix())
        result.append(path)
    return sorted(result)

def audit(root=ROOT):
    failures=[]
    for path in release_files(root):
        text=path.read_text(encoding='utf-8')
        label=path.relative_to(root).as_posix()
        if re.search(r'[A-Za-z]:[\\/]Users[\\/]|/' + r'home/[A-Za-z0-9_.-]+/',text):failures.append((label,'personal absolute path'))
        if re.search(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----',text):failures.append((label,'private key'))
        if re.search(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})',text):failures.append((label,'GitHub credential'))
        for value in UUID.findall(text):
            if value!='00000000-0000-4000-8000-000000000001':failures.append((label,'non-example UUID'))
        if re.search(r'[?&]key=[A-Za-z0-9_-]{20,}',text):failures.append((label,'embedded panel access key'))
    if failures:raise ValueError('; '.join(name+': '+kind for name,kind in failures))
    return len(release_files(root))

if __name__=='__main__':
    try:print('Privacy checks passed for',audit(),'allowlisted source files')
    except ValueError as error:print(error,file=sys.stderr);sys.exit(1)
