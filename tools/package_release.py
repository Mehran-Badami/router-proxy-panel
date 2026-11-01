"""Only allowlisted, audited source files enter the archive; never Git history or runtime state."""
import argparse
import hashlib
from pathlib import Path
import zipfile
from privacy_guard import ROOT,audit,release_files

def package(destination):
    audit()
    destination=Path(destination).resolve()
    if destination.is_relative_to(ROOT) and destination.parent!=ROOT/'dist':
        raise ValueError('Use dist/ or a destination outside the source tree')
    destination.parent.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(destination,'w',compression=zipfile.ZIP_DEFLATED) as archive:
        for path in release_files():
            info=zipfile.ZipInfo('router-proxy-panel/'+path.relative_to(ROOT).as_posix(),date_time=(2026,1,1,0,0,0))
            info.external_attr=0o100644<<16
            archive.writestr(info,path.read_bytes(),compress_type=zipfile.ZIP_DEFLATED)
    digest=hashlib.sha256(destination.read_bytes()).hexdigest()
    destination.with_suffix(destination.suffix+'.sha256').write_text(digest+'  '+destination.name+'\n',encoding='ascii')
    print('Audited source archive created:',destination.name)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',default=str(ROOT/'dist/router-proxy-panel-source.zip'));args=parser.parse_args();package(args.output)
