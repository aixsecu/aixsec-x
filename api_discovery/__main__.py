"""Offline import / explicitly requested GET discovery, without starting the AI agent."""
import argparse
import json
from pathlib import Path

from . import discover, import_document
from .parser import MAX_BYTES
from inventory import Inventory


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True, help='Document URL / discovery start URL and scope origin')
    parser.add_argument('--document', type=Path, help='Local OpenAPI/Swagger/Postman document; no network')
    parser.add_argument('--discover', action='store_true', help='Explicitly enable GET-only network discovery')
    parser.add_argument('--output', type=Path, required=True, help='Inventory output JSON')
    parser.add_argument('--max-requests', type=int, default=24)
    args = parser.parse_args()
    if bool(args.document) == args.discover:
        parser.error('Choose exactly one of --document or --discover')
    try:
        if args.document:
            with args.document.open('rb') as stream:
                raw = stream.read(MAX_BYTES + 1)
            if len(raw) > MAX_BYTES:
                raise ValueError('Document exceeds 2 MB')
            data = import_document(raw.decode('utf-8'), args.url)
        else:
            data = discover(args.url, max_requests=args.max_requests)
        inv = Inventory()
        inv.ingest([{'name': 'api_import' if args.document else 'api_discovery', 'outcome': 'ok', 'data': data}])
        output = {'inventory': inv.to_dict(), 'api_operations': inv.api_inventory(),
                  'warnings': data['warnings'], 'documents': data['documents'],
                  'requests': data.get('requests', []), 'truncated': data.get('truncated', False)}
        args.output.write_text(json.dumps(output, ensure_ascii=False, indent=2), encoding='utf-8')
        print(f"Saved {len(output['api_operations'])} operations to {args.output}")
    except (OSError, ValueError, TypeError, AttributeError, RecursionError) as exc:
        parser.exit(1, f'API discovery/import failed: {type(exc).__name__}\n')


if __name__ == '__main__':
    main()
