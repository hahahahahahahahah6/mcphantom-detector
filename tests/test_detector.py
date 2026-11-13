import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from mcphantom_detector.db import load_db
from mcphantom_detector.cli import main
from mcphantom_detector import scanner

# Independent transcription of the specification; never read the spec at runtime.
ARCHIVED = 'Archived and unmaintained; no security guarantees. See https://github.com/modelcontextprotocol/servers-archived'
UNSUPPORTED = 'Package no longer supported. Contact Support at https://www.npmjs.com/support for more info.'
VULNERABILITY = 'Remote code execution: prompt injection can make the agent run any command instead of the browser (Glow Labs, reported to maintainers; maintainers declined a fix — archived May 2025, no patch coming). No CVE assigned.'
ORACLE = [
 ('@modelcontextprotocol/server-github', 'server-github', ARCHIVED, 5743844),
 ('@modelcontextprotocol/server-postgres', 'server-postgres', ARCHIVED, 4760500),
 ('@modelcontextprotocol/server-slack', 'server-slack', UNSUPPORTED, 3757141),
 ('@modelcontextprotocol/server-puppeteer', 'server-puppeteer', ARCHIVED, 1582178),
 ('@modelcontextprotocol/server-brave-search', 'server-brave-search', UNSUPPORTED, 1545289),
 ('@modelcontextprotocol/server-google-maps', 'server-google-maps', UNSUPPORTED, 834859),
 ('@modelcontextprotocol/server-gitlab', 'server-gitlab', UNSUPPORTED, 290473),
 ('@modelcontextprotocol/server-gdrive', 'server-gdrive', UNSUPPORTED, 266018),
 ('@modelcontextprotocol/server-redis', 'server-redis', UNSUPPORTED, 141723),
 ('@modelcontextprotocol/create-server', 'create-server', UNSUPPORTED, 123166),
 ('@modelcontextprotocol/server-aws-kb-retrieval', 'server-aws-kb-retrieval', UNSUPPORTED, 23626),
 ('@modelcontextprotocol/server-everart', 'server-everart', UNSUPPORTED, 13186),
 ('@modelcontextprotocol/server-git', 'server-git', None, None),
 ('@modelcontextprotocol/server-sentry', 'server-sentry', None, None),
 ('@modelcontextprotocol/server-sqlite', 'server-sqlite', None, None),
 ('@modelcontextprotocol/server-fetch', 'server-fetch', None, None),
 ('@modelcontextprotocol/server-time', 'server-time', None, None),
]
ROOT = Path(__file__).resolve().parents[1]


class DetectorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.db = load_db()

    def config(self, entries, name='.mcp.json'):
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({'mcpServers': entries}), encoding='utf-8')
        return path

    def invoke(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = main(list(map(str, args)))
            except SystemExit as exc:
                code = exc.code
        return code, out.getvalue(), err.getvalue()

    def matches(self, entry):
        return scanner.match_entry(entry, self.db, 'fixture.json', 'x')

    def test_database_oracle(self):
        self.assertEqual(len(self.db), 17)
        self.assertEqual({r['package'] for r in self.db}, {r[0] for r in ORACLE})
        indexed = {r['package']: r for r in self.db}
        self.assertEqual(sum(r['downloads'] or 0 for r in self.db), 19082003)
        for package, short, deprecation, downloads in ORACLE:
            with self.subTest(package=package):
                row = indexed[package]
                self.assertEqual(row['short'], short)
                self.assertEqual(row['deprecation'], deprecation)
                self.assertEqual(row['downloads'], downloads)
                expected_repo = 'modelcontextprotocol/servers' if short in ('server-fetch', 'server-time') else 'modelcontextprotocol/servers-archived'
                expected_status = 'deprecated' if downloads is not None else ('maintained-source-only' if short in ('server-fetch', 'server-time') else 'archived-source-only')
                self.assertEqual(row['repo'], expected_repo)
                self.assertEqual(row['status'], expected_status)
                self.assertEqual(row['known_vulnerability'], VULNERABILITY if short == 'server-puppeteer' else None)
        self.assertEqual(sum(r['downloads'] is None and r['deprecation'] is None for r in self.db), 5)

    def test_all_seventeen_scoped_and_bare_forms(self):
        for package, short, _, _ in ORACLE:
            for entry in ({'command': 'node ' + package}, {'command': short},
                          {'command': 'npx -y ' + short}, {'args': [short]},
                          {'env': {'PACKAGE': package}}):
                with self.subTest(package=package, entry=entry):
                    result = self.matches(entry)
                    self.assertEqual(len(result), 1)
                    self.assertEqual(result[0]['package'], package)

    def test_github_config_medium(self):
        path = self.config({'x': {'command': 'npx -y @modelcontextprotocol/server-github'}})
        code, out, _ = self.invoke(path, '--json')
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)['findings'][0]['severity'], 'MEDIUM')

    def test_puppeteer_high_and_rce(self):
        result = self.matches({'command': 'npx @modelcontextprotocol/server-puppeteer'})
        self.assertEqual(result[0]['severity'], 'HIGH')
        self.assertIn('Remote code execution', result[0]['message'])
        self.assertIn('declined a fix', result[0]['message'])

    def test_unscoped_postgres(self):
        self.assertEqual(self.matches({'command': 'npx -y server-postgres'})[0]['severity'], 'MEDIUM')

    def test_scoped_args(self):
        self.assertEqual(len(self.matches({'command': 'npx', 'args': ['@modelcontextprotocol/server-slack']})), 1)

    def test_version_suffix(self):
        # '@' after the package is allowed by the specified trailing boundary.
        self.assertEqual(len(self.matches({'command': 'npx', 'args': ['@modelcontextprotocol/server-github@2025.4.8']})), 1)

    def test_uvx_launcher(self):
        self.assertEqual(len(self.matches({'command': 'uvx @modelcontextprotocol/server-brave-search'})), 1)

    def test_docker_launcher(self):
        self.assertEqual(len(self.matches({'command': 'docker', 'args': ['run', '--rm', '@modelcontextprotocol/server-gdrive']})), 1)

    def test_urls_and_windows(self):
        for value in ('file:///@modelcontextprotocol/server-github',
                      'https://example.org/@modelcontextprotocol/server-github',
                      r'C:\cache\@modelcontextprotocol/server-github'):
            self.assertEqual(len(self.matches({'url': value})), 1)

    def test_maintained_source_only_message(self):
        for short in ('server-fetch', 'server-time'):
            result = self.matches({'command': 'npx @modelcontextprotocol/' + short})
            self.assertEqual(len(result), 1)
            self.assertIn('Maintained source-only', result[0]['message'])
        result = self.matches({'command': 'npx @modelcontextprotocol/server-git'})
        self.assertEqual(len(result), 1)
        self.assertIn('Archived source-only', result[0]['message'])

    def test_archive_specific_source(self):
        found = self.matches({'url': 'https://github.com/modelcontextprotocol/servers-archived/tree/main/src/git'})
        self.assertEqual([f['package'] for f in found], ['@modelcontextprotocol/server-git'])

    def test_archive_generic(self):
        found = self.matches({'url': 'https://github.com/modelcontextprotocol/servers-archived'})
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['package'], 'modelcontextprotocol/servers-archived')
        self.assertEqual(found[0]['severity'], 'MEDIUM')

    def test_tomllib_and_fallback(self):
        text = '[mcp_servers.x]\ncommand = "npx"\nargs = ["@modelcontextprotocol/server-redis"]\n'
        path = self.root / 'config.toml'
        path.write_text(text)
        if scanner.tomllib is not None:
            with patch.object(scanner.tomllib, 'loads', wraps=scanner.tomllib.loads) as parser:
                self.assertEqual(len(self.matches(scanner.parse_config(path)['x'])), 1)
                parser.assert_called_once_with(text)
        parsed = scanner.parse_toml_fallback(text)
        self.assertEqual(len(self.matches(parsed['x'])), 1)
        with patch.object(scanner, 'tomllib', None):
            self.assertEqual(scanner.parse_config(path), parsed)

    def test_case_insensitivity(self):
        self.assertEqual(len(self.matches({'args': ['@MODELCONTEXTPROTOCOL/SERVER-GITHUB']})), 1)

    def test_two_servers(self):
        path = self.config({'a': {'args': ['server-github']}, 'b': {'args': ['server-postgres']}})
        self.assertEqual(len(json.loads(self.invoke(path, '--json')[1])['findings']), 2)

    def test_duplicate_package(self):
        self.assertEqual(len(self.matches({'command': 'server-github', 'args': ['@modelcontextprotocol/server-github']})), 1)

    def test_maintained_servers(self):
        for short in ('server-memory', 'server-everything', 'server-sequential-thinking'):
            self.assertEqual(self.matches({'command': short, 'args': ['@modelcontextprotocol/' + short]}), [])

    def test_fork_suffix(self):
        self.assertEqual(self.matches({'command': 'npx @modelcontextprotocol/server-github-fork'}), [])

    def test_foo_prefix(self):
        self.assertEqual(self.matches({'command': 'foo@modelcontextprotocol/server-github'}), [])

    def test_live_repo(self):
        self.assertEqual(self.matches({'url': 'https://github.com/modelcontextprotocol/servers/tree/main/src/git'}), [])

    def test_description_unscoped(self):
        self.assertEqual(self.matches({'description': 'uses server-github for docs'}), [])

    def test_toml_comments(self):
        text = '# @modelcontextprotocol/server-github\n[mcp_servers.x]\ncommand = "npx" # @modelcontextprotocol/server-github\nargs = ["server-memory"] # server-github\n'
        path = self.root / 'config.toml'
        path.write_text(text)
        self.assertEqual(self.matches(scanner.parse_config(path)['x']), [])
        self.assertEqual(self.matches(scanner.parse_toml_fallback(text)['x']), [])
        self.assertEqual(scanner.strip_comment('url = "https://host/#anchor" # comment'), 'url = "https://host/#anchor" ')

    def test_no_servers(self):
        path = self.root / 'mcp.json'
        path.write_text('{"other": "@modelcontextprotocol/server-github"}')
        self.assertEqual(self.invoke(path)[0], 0)
        self.assertEqual(json.loads(self.invoke(path, '--json')[1]), {'findings': []})

    def test_clean_config(self):
        path = self.config({'x': {'args': ['@modelcontextprotocol/server-memory']}})
        self.assertEqual(self.invoke(path)[0], 0)
        self.assertEqual(json.loads(self.invoke(path, '--json')[1]), {'findings': []})

    def test_filesystem_unknown(self):
        for word in ('server-filesystem', '@modelcontextprotocol/server-filesystem', 'server-unknown'):
            self.assertEqual(self.matches({'command': word}), [])

    def test_list(self):
        code, out, _ = self.invoke('list')
        self.assertEqual(code, 0)
        self.assertEqual(len(out.splitlines()), 17)
        for package, _, _, _ in ORACLE:
            self.assertIn(package, out)
        self.assertEqual(len(json.loads(self.invoke('list', '--json')[1])), 17)

    def test_version(self):
        self.assertEqual(self.invoke('--version')[:2], (0, '0.1.0\n'))

    def test_thresholds(self):
        path = self.config({'x': {'args': ['server-puppeteer']}})
        self.assertEqual(self.invoke(path)[0], 2)
        path = self.config({'x': {'args': ['server-github']}})
        self.assertEqual(self.invoke(path)[0], 0)
        self.assertEqual(self.invoke(path, '--fail-on', 'medium')[0], 2)

    def test_json_fields_and_sort(self):
        self.config({'z': {'args': ['server-puppeteer', 'server-github']}, 'a': {'args': ['server-postgres']}}, 'z/mcp.json')
        self.config({'b': {'args': ['server-github']}}, 'a/mcp.json')
        code, out, _ = self.invoke(self.root, '--json')
        self.assertEqual(code, 2)
        findings = json.loads(out)['findings']
        self.assertEqual(len(findings), 4)
        self.assertEqual(findings, sorted(findings, key=lambda f: (f['file'], f['server'], f['package'])))
        for f in findings:
            self.assertEqual(set(f), {'rule', 'severity', 'package', 'server', 'file', 'message'})
            self.assertEqual(f['rule'], 'deprecated-mcp-server')

    def test_ignore_repeat_single_value(self):
        self.config({'x': {'args': ['server-puppeteer']}})
        self.assertEqual(json.loads(self.invoke(self.root, '--ignore', self.root, '--ignore', 'other', '--json')[1]), {'findings': []})
        # A following positional path must remain a path, not another ignore value.
        missing = self.root / 'missing'
        self.assertEqual(self.invoke('--ignore', 'unrelated', missing)[0], 1)

    def test_malformed_explicit_and_walked(self):
        path = self.root / 'mcp.json'
        path.write_text('{bad')
        self.assertEqual(self.invoke(path)[0], 1)
        code, out, err = self.invoke(self.root, '--verbose')
        self.assertEqual(code, 0)
        self.assertIn('Warning:', err)
        self.assertIn(str(path), err)
        self.assertIn('Scanned: ' + str(path), err)

    def test_missing_path(self):
        self.assertEqual(self.invoke(self.root / 'absent')[0], 1)

    def test_custom_db_replacement(self):
        custom = dict(self.db[0], package='@example/retired', short='retired')
        path = self.root / 'custom.json'
        path.write_text(json.dumps([custom]))
        config = self.config({'x': {'args': ['server-puppeteer', '@example/retired']}})
        code, out, _ = self.invoke(config, '--db', path, '--json')
        self.assertEqual(code, 0)
        self.assertEqual([f['package'] for f in json.loads(out)['findings']], ['@example/retired'])
        self.assertEqual(len(json.loads(self.invoke('list', '--db', path, '--json')[1])), 1)
        for content in ('{bad', '{}', '[{}]', '[{"downloads": "wrong"}]'):
            path.write_text(content)
            self.assertEqual(self.invoke(config, '--db', path)[0], 1)

    def test_default_discovery(self):
        self.config({'x': {'args': ['server-puppeteer']}})
        with patch('os.getcwd', return_value=str(self.root)), patch.object(scanner, 'default_paths', return_value=[]):
            self.assertEqual(self.invoke('scan')[0], 2)
            self.assertEqual(self.invoke('scan', '--no-default-configs')[0], 2)
            self.assertEqual(self.invoke()[0], 2)

    def test_home_discovery(self):
        path = self.config({'x': {'args': ['server-puppeteer']}})
        empty = self.root / 'empty'
        empty.mkdir()
        with patch('os.getcwd', return_value=str(empty)), patch.object(scanner, 'default_paths', return_value=[path]):
            self.assertEqual(self.invoke('scan')[0], 2)
            self.assertEqual(self.invoke('scan', '--no-default-configs')[0], 0)

    def test_module_entrypoint(self):
        env = dict(os.environ, PYTHONPATH=str(ROOT / 'src'))
        result = subprocess.run([sys.executable, '-m', 'mcphantom_detector', '--version'], env=env, capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (0, '0.1.0\n'))

    @unittest.skipUnless(shutil.which('mcphantom-detector'), 'console script not installed')
    def test_console_entrypoint(self):
        result = subprocess.run(['mcphantom-detector', '--version'], capture_output=True, text=True)
        self.assertEqual((result.returncode, result.stdout), (0, '0.1.0\n'))

    def test_self_scan(self):
        self.assertEqual(self.invoke(ROOT)[0], 0)
        self.assertEqual(json.loads(self.invoke(ROOT, '--json')[1]), {'findings': []})

    def test_bundled_resource_and_distributions(self):
        from importlib.resources import files
        self.assertEqual(json.loads(files('mcphantom_detector').joinpath('data/deprecated.json').read_text(encoding='utf-8')), self.db)
        # Build verification creates these; when present inspect both archives.
        for path in (ROOT / 'dist').glob('*'):
            if path.suffix == '.whl':
                with zipfile.ZipFile(path) as archive:
                    raw = archive.read('mcphantom_detector/data/deprecated.json')
            elif path.name.endswith('.tar.gz'):
                with tarfile.open(path) as archive:
                    member = next(m for m in archive.getmembers() if m.name.endswith('/src/mcphantom_detector/data/deprecated.json'))
                    raw = archive.extractfile(member).read()
            else:
                continue
            self.assertEqual(json.loads(raw), self.db)

    def test_usage_errors(self):
        for args in (('--unknown',), ('--fail-on', 'low'), ('--ignore',), ('list', '--verbose')):
            self.assertEqual(self.invoke(*args)[0], 1)

    def test_walk_filter_and_symlinks(self):
        path = self.config({'x': {'args': ['server-puppeteer']}}, 'unrecognized.json')
        self.assertEqual(self.invoke(self.root)[0], 0)
        self.assertEqual(self.invoke(path)[0], 2)
        (self.root / 'mcp.json').symlink_to(path)
        self.assertEqual(self.invoke(self.root)[0], 0)

    def test_toml_no_table_and_malformed(self):
        path = self.root / 'config.toml'
        path.write_text('title = "@modelcontextprotocol/server-github"\n')
        self.assertEqual(self.invoke(path)[0], 0)
        path.write_text('[mcp_servers.x\nargs = ["broken"')
        self.assertEqual(self.invoke(path)[0], 1)
        self.assertEqual(self.invoke(self.root)[0], 0)

    def test_nested_nonstring_values(self):
        self.assertEqual(len(self.matches({'nested': {'env': {'X': '@modelcontextprotocol/server-github'}, 'other': [1, None, False]}})), 1)


if __name__ == '__main__':
    unittest.main()
