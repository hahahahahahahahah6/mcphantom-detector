"""Read configuration files without executing their contents."""
import ast
import json
import os
from pathlib import Path
import re
import shlex

try:
    import tomllib
except ImportError:  # Python 3.9 and 3.10
    tomllib = None

NAMES = {'.mcp.json', 'mcp.json', 'claude_desktop_config.json', '.claude.json',
         'claude.json', 'config.toml'}
REPO = 'modelcontextprotocol/servers-archived'


def strip_comment(line):
    quote = None
    escaped = False
    for i, ch in enumerate(line):
        if escaped:
            escaped = False
        elif ch == '\\' and quote == '"':
            escaped = True
        elif quote:
            if ch == quote:
                quote = None
        elif ch in ('"', "'"):
            quote = ch
        elif ch == '#':
            return line[:i]
    return line


def parse_toml_fallback(text):
    """Minimal line parser for command, args and url in MCP server tables."""
    result = {}
    current = None
    pending = ''
    for raw in text.splitlines():
        line = strip_comment(raw).strip()
        if not line:
            continue
        if pending:
            line = pending + ' ' + line
            pending = ''
        if line.startswith('[') and not line.startswith('["') and '=' not in line:
            if not line.endswith(']'):
                raise ValueError('invalid TOML table')
            match = re.fullmatch(r'\[mcp_servers\.(.+)\]', line)
            current = None
            if match:
                name = match.group(1).strip('"\'')
                if name in result:
                    raise ValueError('duplicate TOML table')
                current = result.setdefault(name, {})
            continue
        if '=' not in line:
            raise ValueError('invalid TOML assignment')
        key, value = (s.strip() for s in line.split('=', 1))
        if value.startswith('[') and not value.endswith(']'):
            pending = line
            continue
        if current is not None and key in ('command', 'args', 'url'):
            try:
                parsed = ast.literal_eval(value)
            except (ValueError, SyntaxError) as exc:
                raise ValueError('invalid TOML string or array') from exc
            if key == 'args':
                if not isinstance(parsed, list) or not all(isinstance(x, str) for x in parsed):
                    raise ValueError('args must be a string array')
            elif not isinstance(parsed, str):
                raise ValueError('expected TOML string')
            if key in current:
                raise ValueError('duplicate TOML key')
            current[key] = parsed
    if pending:
        raise ValueError('unterminated TOML array')
    return result


def parse_config(path):
    text = path.read_text(encoding='utf-8')
    if path.suffix.lower() == '.toml':
        if tomllib is not None:
            try:
                document = tomllib.loads(text)
                servers = document.get('mcp_servers', {})
            except ValueError:
                servers = parse_toml_fallback(text)
        else:
            servers = parse_toml_fallback(text)
        if not isinstance(servers, dict):
            return {}
        return {name: {k: v for k, v in entry.items() if k in ('command', 'args', 'url')}
                for name, entry in servers.items() if isinstance(entry, dict)}
    doc = json.loads(text)
    servers = doc.get('mcpServers', {}) if isinstance(doc, dict) else {}
    return servers if isinstance(servers, dict) else {}


def candidates(value, role=None):
    if isinstance(value, str):
        yield value.lower(), role
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from candidates(item, key)
    elif isinstance(value, list):
        for item in value:
            yield from candidates(item, role)


def token(name, text):
    return re.search(r'(?<![a-z0-9_@.\-])' + re.escape(name) + r'(?![a-z0-9_\-])', text) is not None


def bare(short, text, role):
    if role == 'args':
        return re.fullmatch(re.escape(short) + r'(?:@[^\s]+)?', text) is not None
    if role == 'command':
        # Command strings can include launchers and switches, e.g. npx -y NAME.
        try:
            words = shlex.split(text, posix=False)
        except ValueError:
            words = text.split()
        return any(re.fullmatch(re.escape(short) + r'(?:@[^\s]+)?', word) for word in words)
    return False


def match_entry(entry, database, file, server):
    strings = list(candidates(entry))
    matched = {}
    generic = False
    for text, role in strings:
        repo_specific = False
        for row in database:
            package, short = row['package'].lower(), row['short'].lower()
            archived = REPO in text
            # Archive source directories use git, sentry, etc., without server-.
            source_name = short[7:] if short.startswith('server-') else short
            archive_path = text.split(REPO, 1)[1] if archived else ''
            repo_match = archived and (token(short, text) or token(source_name, archive_path))
            if repo_match:
                repo_specific = True
            if token(package, text) or bare(short, text, role) or repo_match:
                high = short == 'server-puppeteer'
                message = row['deprecation'] or 'Archived source-only MCP server; no npm package.'
                if row['known_vulnerability']:
                    message += ' ' + row['known_vulnerability']
                matched[row['package']] = dict(rule='deprecated-mcp-server', severity='HIGH' if high else 'MEDIUM',
                    package=row['package'], server=server, file=str(file), message=message)
        if REPO in text and not repo_specific:
            generic = True
    if generic and not matched:
        matched[REPO] = dict(rule='deprecated-mcp-server', severity='MEDIUM', package=REPO,
            server=server, file=str(file), message='Archived-repo reference without a specific server name.')
    return list(matched.values())


def default_paths():
    home = Path.home()
    return [home / x for x in ('.claude.json', '.config/Claude/claude_desktop_config.json',
        'Library/Application Support/Claude/claude_desktop_config.json', '.cursor/mcp.json',
        '.codex/config.toml', '.vscode/mcp.json')]


def scan(paths, database, ignore=(), no_default_configs=False):
    roots = [(Path(x), True) for x in paths]
    if not roots:
        roots = [(Path.cwd(), False)]
        if not no_default_configs:
            roots += [(x, False) for x in default_paths() if x.exists()]
    files = {}
    errors, warnings, scanned = [], [], []
    for root, explicit in roots:
        if not root.exists():
            errors.append('Path does not exist: ' + str(root))
        elif root.is_file():
            files[root.absolute()] = files.get(root.absolute(), False) or explicit
        elif root.is_dir():
            def walk_error(exc):
                errors.append(str(exc))
            for directory, dirs, names in os.walk(root, followlinks=False, onerror=walk_error):
                dirs[:] = [d for d in dirs if not (Path(directory) / d).is_symlink()]
                for name in names:
                    f = Path(directory) / name
                    if name in NAMES and not f.is_symlink():
                        files.setdefault(f.absolute(), False)
        else:
            errors.append('Unreadable path: ' + str(root))
    findings = []
    for file, explicit in sorted(files.items()):
        scanned.append(str(file))
        try:
            servers = parse_config(file)
            for server, entry in servers.items():
                if isinstance(entry, dict):
                    findings.extend(match_entry(entry, database, file, server))
        except (OSError, ValueError, UnicodeError) as exc:
            (errors if explicit else warnings).append(str(file) + ': ' + str(exc))
    findings = [f for f in findings if not any(f['file'].startswith(prefix) for prefix in ignore)]
    findings.sort(key=lambda f: (f['file'], f['server'], f['package']))
    return findings, errors, warnings, scanned
