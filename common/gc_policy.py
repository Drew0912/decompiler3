'''Cyclic garbage collection spaced out while a script is decompiled or compiled'''

import gc
from contextlib import contextmanager

GC_THRESHOLD = 1_000_000    # Python's default is 2,000


@contextmanager
def infrequent_gc():
    '''Collect every GC_THRESHOLD new objects, then restore the previous thresholds'''
    previous = gc.get_threshold()
    gc.set_threshold(GC_THRESHOLD, *previous[1:])
    try:
        yield

    finally:
        gc.set_threshold(*previous)
