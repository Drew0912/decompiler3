import logging
import sys

__all__ = (
    'log',
)


class _StderrHandler(logging.StreamHandler):
    '''Writes to whatever sys.stderr is when a record is emitted (like logging's own last-resort handler), so
    contextlib.redirect_stderr silences the log as it does print(file = sys.stderr)'''

    def __init__(self):
        logging.Handler.__init__(self)  # StreamHandler.__init__ would assign self.stream, a read-only property here

    @property
    def stream(self):
        return sys.stderr

    def setStream(self, stream):
        raise TypeError('_StderrHandler always writes to the current sys.stderr')


# Registered via getLogger: a bare Logger() never has its level cache cleared, so setLevel/assertLogs go stale
log = logging.getLogger('decompiler3')
log.setLevel(logging.INFO)
log.propagate = False
handler = _StderrHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s][%(filename)s:%(lineno)d][%(levelname)s] %(message)s', datefmt = '%m-%d %H:%M:%S'))

log.addHandler(handler)
