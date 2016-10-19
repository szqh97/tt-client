#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import socket
from tornado import iostream
import MessageHandler

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
addr = ('120.26.137.224', 48000)
stream = iostream.IOStream(sock)
stream.connect(addr)

stream.write(MessageHandler._Login('b1', 'b1'))

time.sleep(1)
