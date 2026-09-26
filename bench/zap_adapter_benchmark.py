#!/usr/bin/env python3
"""Deterministic scheduling benchmark; does not launch ZAP or touch a target."""
import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from zap_workers import batch_jobs  # noqa: E402


def run(groups=1000, batch_size=8):
    jobs = [{'request_id': str(i), 'auth_context': 'anonymous',
             '_entry': {'request': {'url': f'https://bench.invalid/item/{i}',
                                    'method': 'GET', 'headers': []}}}
            for i in range(groups)]
    started = time.perf_counter()
    batches = batch_jobs(jobs, batch_size, 'guest')
    elapsed = time.perf_counter() - started
    launches = len(batches)
    return {'groups': groups, 'batch_size_limit': batch_size, 'jobs': launches,
            'average_batch_size': round(groups / launches, 3) if launches else 0,
            'jvm_launches_avoided': groups - launches,
            'jvm_reuse_ratio': round((groups - launches) / groups, 4) if groups else 0,
            'scheduler_seconds': round(elapsed, 6)}


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--groups', type=int, default=1000)
    parser.add_argument('--batch-size', type=int, default=8)
    args = parser.parse_args()
    print(json.dumps(run(max(0, args.groups), max(1, args.batch_size)), indent=2))
