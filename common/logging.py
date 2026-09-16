import logging

log = logging.Logger('', level = logging.INFO)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('[%(asctime)s][%(filename)s:%(lineno)d][%(levelname)s] %(message)s', datefmt = '%m-%d %H:%M:%S'))

log.addHandler(handler)