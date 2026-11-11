"""Command-line interface. No network requests or filesystem mutations."""
import argparse
import json
import sys
from . import __version__
from .db import load_db
from .scanner import scan


class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(1, self.prog + ': error: ' + message + '\n')


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    parser = Parser(prog='mcphantom-detector')
    parser.add_argument('--version', action='version', version=__version__)
    sub = parser.add_subparsers(dest='action', parser_class=Parser)
    scan_parser = sub.add_parser('scan', help='scan MCP config files')
    scan_parser.add_argument('paths', nargs='*')
    scan_parser.add_argument('--verbose', action='store_true')
    scan_parser.add_argument('--ignore', action='append', default=[])
    scan_parser.add_argument('--fail-on', choices=('high', 'medium'), default='high')
    scan_parser.add_argument('--no-default-configs', action='store_true')
    list_parser = sub.add_parser('list', help='print database snapshot')
    for child in (scan_parser, list_parser):
        child.add_argument('--json', action='store_true')
        child.add_argument('--db')
    if not args or args[0] not in ('scan', 'list', '--version', '-h', '--help'):
        args.insert(0, 'scan')
    options = parser.parse_args(args)
    try:
        database = load_db(options.db)
    except (OSError, ValueError, UnicodeError) as exc:
        print('Database error: ' + str(exc), file=sys.stderr)
        return 1
    if options.action == 'list':
        if options.json:
            print(json.dumps(database, ensure_ascii=False))
        else:
            for row in database:
                print('{}\t{}\t{}'.format(row['package'], row['status'],
                    row['downloads'] if row['downloads'] is not None else '-'))
        return 0
    findings, errors, warnings, scanned = scan(options.paths, database, options.ignore, options.no_default_configs)
    for warning in warnings:
        print('Warning: ' + warning, file=sys.stderr)
    for error in errors:
        print('Error: ' + error, file=sys.stderr)
    if options.verbose:
        for file in scanned:
            print('Scanned: ' + file, file=sys.stderr)
    if options.json:
        print(json.dumps({'findings': findings}, ensure_ascii=False))
    else:
        for f in findings:
            print('{file}: {server}: {severity} {rule} {package}: {message}'.format(**f))
        print('{} finding(s)'.format(len(findings)))
    if errors:
        return 1
    return 2 if any(f['severity'] == 'HIGH' or options.fail_on == 'medium' for f in findings) else 0
