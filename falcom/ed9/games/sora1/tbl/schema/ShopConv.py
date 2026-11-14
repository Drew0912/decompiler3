from falcom.ed9.parser.tbl import TableDataEntry


# t_shop.tbl
class ShopConv(TableDataEntry):
    DESCRIPTOR = (
        ('id',    'W'),
        ('pad02', 'P2'),
        # rate0..rate7: conversion rates, read by index 0..7 and truncated to an integer; each index also
        # picks one of the items 0x136..0x13D (the seven sepith and Sepith Mass), which one is not read yet.
        # rate0 is also read alone: shown as a number, and used in a multiply and a divide
        ('rate0', 'f'),
        ('rate1', 'f'),
        ('rate2', 'f'),
        ('rate3', 'f'),
        ('rate4', 'f'),
        ('rate5', 'f'),
        ('rate6', 'f'),
        ('rate7', 'f'),
    )
