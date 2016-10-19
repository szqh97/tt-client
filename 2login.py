#!/usr/bin/env python
# -*- coding: utf-8 -*-
import MessageHandler
import socket

errbody = MessageHandler._Login('','')


addr = ('120.26.137.224', 28000)
socklist  =[]
for i in xrange(100):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)
    socklist.append(s)
for s in socklist:
    s.send(errbody)
    s.send(errbody)
    s.send(errbody)
