"""Use the production source packer for subprocess tests too."""
from pathlib import Path
import runpy

packed = runpy.run_path(str(Path(__file__).resolve().parents[1] /
                           'tools/pack-inspection-worker.py'))['pack']
