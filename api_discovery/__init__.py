"""Phase 2.1: bounded API discovery and declared/observed operation inventory.

No operation execution, auth testing, remote $ref retrieval or vulnerability verdicts.
"""
from .parser import import_document, infer_schema
from .discovery import discover

__all__ = ['import_document', 'infer_schema', 'discover']
