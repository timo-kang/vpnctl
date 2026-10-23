"""Post-exec address-space RSS, kept separate from inherited rusage peaks."""
from pathlib import Path


def parse_status(text):
    result = {}
    for line in text.splitlines():
        fields = line.split()
        if not fields or fields[0] not in ('VmRSS:', 'VmHWM:'): continue
        if len(fields) != 3 or fields[2] != 'kB' or not fields[1].isdigit() or fields[0] in result:
            raise ValueError('invalid process memory evidence')
        result[fields[0]] = int(fields[1])
    if set(result) != {'VmRSS:', 'VmHWM:'}: raise ValueError('process memory fields missing')
    return {'rss_kib': result['VmRSS:'], 'address_space_peak_rss_kib': result['VmHWM:']}


def sample_memory():
    try:
        return {'source': '/proc/self/status', **parse_status(Path('/proc/self/status').read_text())}
    except (OSError, ValueError) as error:
        return {'source': '/proc/self/status', 'unavailable': type(error).__name__}
