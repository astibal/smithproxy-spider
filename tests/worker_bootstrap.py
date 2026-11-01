"""Use the production source packer for subprocess tests too."""
from pathlib import Path
import runpy

_packer = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                             'tools/pack-inspection-worker.py'))


def _native_modules(modules):
    # Production bundles this module through the worker manifest. Native-only
    # subprocess tests need it too, without loading the compatibility runtime.
    result = dict(modules or {})
    source = Path(__file__).resolve().parents[1] / 'src/inspection_protocol_state.py'
    result.setdefault('inspection_protocol_state', source.read_text())
    return result


def packed(source, modules=None):
    return _packer['pack'](source, _native_modules(modules))


def packed_arguments(source, modules=None):
    return _packer['pack_arguments'](source, _native_modules(modules))


def addon_modules(root):
    """Read the same addon module manifest used by the production build."""
    source_directory = Path(root) / 'src'
    manifest = source_directory / 'addon_worker_modules.txt'
    names = [line.strip() for line in manifest.read_text().splitlines()
             if line.strip()]
    return {Path(name).stem: (source_directory / name).read_text()
            for name in names}
