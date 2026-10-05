import logging

__all__ = (
    'log',
)

# Registered via getLogger: a bare Logger() never has its level cache cleared, so setLevel/assertLogs go stale
log = logging.getLogger('decompiler3')
log.setLevel(logging.INFO)
log.propagate = False
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s][%(filename)s:%(lineno)d][%(levelname)s] %(message)s', datefmt = '%m-%d %H:%M:%S'))

log.addHandler(handler)
