#!/usr/bin/env python
# -*- coding: utf-8 -*-
import socket

HEAD_PDU_LEN =16
class TTSocket(object):

    """Docstring for TTSocket. """

    def __init__(self, host, port):
        self.buf = b''
        self.sock = sockt.sockt(socket.AF_INET, socket.SOCK_STREAM, 0)
        try:
            self.sock.connect((host, port))
        except Exception as e:
            print 'connect addr errror!'
            raise e

    def Recv(self):
        buf = self.sock.recv(1024)
        self.buf = buf
        while len(buf) == 1024:
            buf = self.sock.recv(1024)
            self.buf = self.buf + buf

    def Send(self, buf):
        len = self.sock.send(buf)
        return len

    def Close(self):
        self.sock.close()
        

