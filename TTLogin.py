#!/usr/bin/env python
# -*- coding: utf-8 -*-
import errno
import functools
import socket
import time
from tornado.ioloop import IOLoop
from ClientConn import ClientConn
from TTBase.util import install_logger
log = install_logger("TestServer")

from config import cnt, MIN_TO_ID, MAX_TO_ID, MIN_FROM_ID, MAX_FROM_ID, snd_msg_interval
class ClientServer(object):
    """
    ClientServer is a server managing ClientConn's sockets
    """
    def __init__(self):
        self._fd_map = {}
        self._io_loop = IOLoop.current()

    def gen_batch_clients(self):
        # users sending msg
        for i in xrange(cnt):
            c_sender = ClientConn(u'test' + str(i+1))
            c_sender.connect()
            self._fd_map[c_sender._socket.fileno()] = c_sender
        log.debug("_fd_map length is {}".format(len(self._fd_map)))

    def _TEST_genClientConn(self):
               
        c1 = ClientConn(u'test1')
        c1.connect()
        self._fd_map[c1._socket.fileno()] = c1

        c2 = ClientConn(u'test2')
        c2.connect()
        self._fd_map[c2._socket.fileno()] = c2
        log.debug("_fd_map length is {}".format(len(self._fd_map)))

        pass
    
    def ClientConnHeartBeatTimer(self, ioloop):
#       log.debug('heartbeat ...')
#       for c in self._fd_map.values():
#           if c._online:
#               c.heartbeat()
#           if not c._connected:
#               del self._fd_map[c._socket.fileno()]
        log.info('online users cnt: {}'.format(len(self._fd_map)))
        self._io_loop.add_timeout(time.time() + 30, self.ClientConnHeartBeatTimer, self._io_loop)

    def ClientConnSendMsg(self, ioloop):
        msg = 'dgjzZcuwYVvgiMtBlzoa8RS7edxfMniMPR2naJakzDo6jfQKGGbzEee6ENKT4qW8o95BhdaLX1yonQuqKImGAJv9fdeyZEvjlfzrT5S4g3I='
        for c in self._fd_map.values():
            if c._online:
                c.sendMsg()
        self._io_loop.add_timeout(time.time() + snd_msg_interval, self.ClientConnSendMsg, self._io_loop)

    def registerClientConns(self):
        for conn in self._fd_map.values():
            conn.login()

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
            log.info("conn is closed or disconnected, user_id: {}".format(conn._m_user_id))
            pass
        else:
            if conn._connected  :
                conn.recvData()
            else: 
                del self._fd_map[fd]
                log.info('user {} is off-line'.format(conn.username))
def main():
    cs = ClientServer()
    #cs._TEST_genClientConn()
    cs.gen_batch_clients()
    cs.registerClientConns()
#   cs.ClientConnHeartBeatTimer(cs._io_loop)
#   cs.ClientConnSendMsg(cs._io_loop)
#   cs._io_loop.start()

if __name__ == "__main__":
    log.info('TEST SERVER STARTING ....')
    main()
    log.info('TEST SERVER STOP....')
