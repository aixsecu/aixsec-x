"""Build a source-only release ZIP with a per-file SHA-256 manifest."""
import hashlib
import json
import re
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parent.parent
version = re.search(r'^VERSION = "([^"]+)"', (root / 'agent.py').read_text(), re.M).group(1)
files = sorted(set(list(root.glob('*.py')) + list(root.glob('README*.md')) +
                   [root / 'requirements.txt', root / 'RELEASE_NOTES.md', root / '.gitignore'] +
                   [p for folder in ('adapters', 'api_discovery', 'autonomy', 'context_optimization', 'docs', 'examples', 'scripts', 'bench')
                    for p in (root / folder).rglob('*')
                    if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py', '.md', '.json', '.yaml', '.yml', '.js')]))
destination = root / 'dist' / f'aixsec-x-{version}.zip'
destination.parent.mkdir(exist_ok=True)
manifest = {str(p.relative_to(root)): hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
with zipfile.ZipFile(destination, 'w', zipfile.ZIP_DEFLATED) as archive:
    for p in files:
        archive.write(p, f'aixsec-x-{version}/{p.relative_to(root)}')
    archive.writestr(f'aixsec-x-{version}/MANIFEST.sha256.json', json.dumps(manifest, indent=2))
with zipfile.ZipFile(destination) as archive:
    assert archive.testzip() is None
    for relative, digest in manifest.items():
        assert hashlib.sha256(archive.read(f'aixsec-x-{version}/{relative}')).hexdigest() == digest
checksum = hashlib.sha256(destination.read_bytes()).hexdigest()
destination.with_suffix('.zip.sha256').write_text(f'{checksum}  {destination.name}\n')
print(f'{destination}: {len(files)} files, {destination.stat().st_size} bytes; manifest verified')
