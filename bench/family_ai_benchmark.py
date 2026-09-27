#!/usr/bin/env python3
"""Deterministic accounting benchmark for constrained family AI assistance."""
import argparse
import json
from pathlib import Path
import sys

sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from family_ai import FamilyAIAssistant  # noqa: E402


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--families',type=int,default=100)
    parser.add_argument('--low-confidence',type=int,default=15)
    parser.add_argument('--evidence-resolved',type=int,default=9)
    args=parser.parse_args();print(json.dumps(FamilyAIAssistant.benchmark(
        args.families,args.low_confidence,1 if args.low_confidence else 0,args.evidence_resolved),indent=2))
