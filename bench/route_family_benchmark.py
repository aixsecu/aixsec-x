#!/usr/bin/env python3
"""Deterministic CPU-only benchmark for Route Family construction."""
import argparse
import json
from pathlib import Path
import sys
import time

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from route_family import RouteFamilyBuilder  # noqa: E402


def run(count=10000):
    entries={}
    routes=('login','logout','register','search','orders','products','accounts','reports')
    for index in range(count):
        route=routes[index%len(routes)];url=f'https://example.test/{route}/{index%1000}?page={index%50}'
        captured={'request':{'url':url,'method':'GET','headers':[]},
            'response':{'status':200,'headers':[],'content':{'mimeType':'text/html',
                'text':f'<html><body><main id="react-{index}"><input name="page"></main></body></html>'}}}
        entries[str(index)]={'request_id':str(index),'url':url,'method':'GET',
                            'auth_context':'anonymous','_entry':captured}
    began=time.perf_counter_ns();result=RouteFamilyBuilder().build(entries)
    elapsed=(time.perf_counter_ns()-began)/1_000_000
    return {'request_groups':count,'families':result['family_count'],'elapsed_ms':round(elapsed,3),
            'microseconds_per_group':round(elapsed*1000/count,3),
            'groups_per_second':round(count/(elapsed/1000),1) if elapsed else 0}


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--groups',type=int,default=10000)
    print(json.dumps(run(max(1,parser.parse_args().groups)),indent=2))
