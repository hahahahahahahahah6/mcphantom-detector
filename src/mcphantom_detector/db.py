"""Load and validate offline database snapshots."""
import json
from importlib.resources import files


def load_db(path=None):
    if path is None:
        raw = files('mcphantom_detector').joinpath('data/deprecated.json').read_text(encoding='utf-8')
    else:
        with open(path, encoding='utf-8') as stream:
            raw = stream.read()
    data = json.loads(raw)
    required = {'package', 'short', 'status', 'deprecation', 'downloads',
                'known_vulnerability', 'repo'}
    if not isinstance(data, list):
        raise ValueError('database must be a list')
    seen = set()
    for entry in data:
        if not isinstance(entry, dict) or set(entry) != required:
            raise ValueError('database entry has invalid fields')
        for key in ('package', 'short', 'repo'):
            if not isinstance(entry[key], str) or not entry[key]:
                raise ValueError('database names must be nonempty strings')
        if entry['status'] not in ('deprecated', 'archived-source-only', 'maintained-source-only'):
            raise ValueError('invalid database status')
        for key in ('deprecation', 'known_vulnerability'):
            if entry[key] is not None and not isinstance(entry[key], str):
                raise ValueError('invalid database text')
        n = entry['downloads']
        if n is not None and (type(n) is not int or n < 0):
            raise ValueError('invalid download count')
        if entry['package'].lower() in seen:
            raise ValueError('duplicate database package')
        seen.add(entry['package'].lower())
    return data
