#!/usr/bin/env python
# -*- coding: utf-8 -*-
import errno
import functools
import socket
import time
from tornado.ioloop import IOLoop
from ClientConn import ClientConn
from TTBase.util import install_logger
import sys
import os
log = install_logger("TestServer")

class ClientServer(object):
    """
    ClientServer is a server managing ClientConn's sockets
    """
    def __init__(self, username):
        self._fd_map = {}
        self._io_loop = IOLoop.current()
        self._username = username

    def createClientConn(self):
        conn = ClientConn(self._username)
        conn.connect()
        self._fd_map[conn._socket.fileno()] = conn

    
    def ClientConnHeartBeatTimer(self, ioloop):
#       log.debug('heartbeat ...')
        for c in self._fd_map.values():
            if c._online:
                c.heartbeat()
            if not c._connected:
                del self._fd_map[c._socket.fileno()]
        log.info('online users cnt: {}'.format(len(self._fd_map)))
        self._io_loop.add_timeout(time.time() + 30, self.ClientConnHeartBeatTimer, self._io_loop)

    def registerClientConns(self):
        for conn in self._fd_map.values():
            conn.login()
            #conn.createGroup()
            time.sleep(4)
            #conn.changeGroupMember(2396, 18, [10], 1)
            #conn.removeGroup(2396, 18)
            #conn.updateGroupInfo(2396, 103, 20, "rtest-2")
            conn.getNormalGroupList(2396)

        for fd in self._fd_map.keys():
            c = self._fd_map[fd]
            callback = functools.partial(self.client_handler, c._socket)
            self._io_loop.add_handler(fd, callback, IOLoop.READ)
        

    def client_handler(self, sock, fd, events):
        try:
            sock.fileno()
        except Exception as e:
            log.info('fd {} closed ...'.format(fd))
            del self._fd_map[fd]
        conn = self._fd_map.get(fd, None)
        if conn is None:
            log.info("conn is closed or disconnected, ")
            sys.exit(1)
            pass
        else:
            if conn._connected  :
                conn.recvData()
            else: 
                del self._fd_map[fd]
                log.info('user {} is off-line'.format(conn.username))
def main(username):
    cs = ClientServer(username)
    cs.createClientConn()
    cs.registerClientConns()
    cs.ClientConnHeartBeatTimer(cs._io_loop)
    cs._io_loop.start()

if __name__ == "__main__":
    log.info('TEST SERVER STARTING ....')
    if len(sys.argv) != 2:
        print "usage: {} djxxxx".format(sys.argv[0])
        sys.exit(1)
    main(sys.argv[1])
    log.info('TEST SERVER STOP....')
