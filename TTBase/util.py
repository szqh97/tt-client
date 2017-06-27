#!/usr/bin/env python
# -*- coding: utf-8 -*-
import logging
import sys

log = logging
def install_logger(name):
    global log
    log = logging.getLogger(name)
    formatter = logging.Formatter('%(threadName)s %(asctime)s %(levelname)s %(name)s [%(funcName)s<%(lineno)d>]:%(message)s')
    file_handler = logging.FileHandler('./tt-client.log')
    file_handler.setFormatter(formatter)
    stream_handler = logging.StreamHandler(sys.stdout)
    stream_handler.setFormatter(formatter)
    #log.addHandler(file_handler)
    log.addHandler(stream_handler)
    log.setLevel(logging.DEBUG)
    return log


