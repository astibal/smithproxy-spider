"""Use the production source packer for subprocess tests too."""
from pathlib import Path
import runpy

_packer = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                             'tools/pack-inspection-worker.py'))
packed = _packer['pack']
packed_arguments = _packer['pack_arguments']


def addon_modules(root):
    """Read the same addon module manifest used by the production build."""
    source_directory = Path(root) / 'src'
    manifest = source_directory / 'addon_worker_modules.txt'
    names = [line.strip() for line in manifest.read_text().splitlines()
             if line.strip()]
    return {Path(name).stem: (source_directory / name).read_text()
            for name in names}
