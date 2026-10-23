"""Preserve the original observer outcome before exporting diagnostics offline."""
import json
from pathlib import Path
import subprocess
import sys
import traceback
from outer_guard import outer_guard


def run(original, export, output):
    result = {}
    try:
        original()
        result['original_observer_exit'] = 0
    except SystemExit as error:
        result['original_observer_exit'] = error.code if type(error.code) is int else (0 if error.code is None else 1)
    except Exception:
        result['original_observer_exit'] = 1
        result['original_observer_error'] = traceback.format_exc()
    output.write_text(json.dumps(result, indent=2))
    try:
        result['extraction_exit'] = export()
    except Exception:
        result['extraction_exit'] = 1
        result['extraction_error'] = traceback.format_exc()
    output.write_text(json.dumps(result, indent=2))
    return result['original_observer_exit'] or result['extraction_exit']


def main():
    outer_guard()
    sys.path.insert(0, '/opt/vpnctl-vm')
    import observer
    def export():
        return subprocess.run([sys.executable, '-B', str(Path(__file__).with_name('extract.py'))], timeout=300).returncode
    return run(observer.main, export, Path('/results/diagnostic-exit.json'))


if __name__ == '__main__':
    raise SystemExit(main())
