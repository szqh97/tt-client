#!/usr/bin/env python
# -*- coding: utf-8 -*-

import httplib2
import json
import logging
import socket
from IM.Login_pb2 import *
from IM.BaseDefine_pb2 import *
from  TTBase.ImPdu import *
import time
import hashlib

class Client(object):

    """Docstring for Client. """

    def __init__(self, username,
            ttserver="http://120.26.137.224:28080/msg_server"):
        """
        ttserver is like: http://192.168.1.15:8400/msg_server
        """
        self.username = username
        h = hashlib.md5(self.username)
        self.password = h.hexdigest()
        print self.password
        self.ttserver = ttserver
        self._socket = None

    def _getPriorIP(self):
        http = httplib2.Http(disable_ssl_certificate_validation=True)
        resp, content = http.request(method='GET', uri=self.ttserver)
        if resp.status == 200:
            result = json.loads(content)
            code = result.get('code')
            if code == 0:
                priorIP = result.get('priorIP', None)
                port = result.get('port', None)
                return priorIP, port
            else:
                logging.error('get msg server error: {}'.format(content))
        else:
            logging.error('status is not 200, get msg server error: {}'.format(content))

    def connect(self):
        """
        connect teamtalk
        """
        ip, port  = self._getPriorIP() 
        if ip is not None and port is not None:
            self.priorIP = ip
            self.port = port
        else:
            logging.Error("prior IP is EMTPY!!")

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((ip, int(port)))
        print ip, port

    def login(self):
        req = IMLoginReq()
        req.Clear()
        req.user_name  = self.username
        req.password = self.password
        req.online_status = USER_STATUS_ONLINE
        req.client_type = CLIENT_TYPE_IOS
        req.client_version = "1.0.0"

        msg = req.SerializeToString()
        print msg, len(msg)
        pdu = ImPdu()
        pdu.msg = msg
        pdu.length += len(msg)
        pdu.service_id = SID_LOGIN
        pdu.command_id = CID_LOGIN_REQ_USERLOGIN
        pdu.seq_num = 2**3

        pdu_msg = pdu.SerializeToString()
        print 'pdu strings is ', pdu_msg, len(pdu_msg)
        print self._socket.send(pdu_msg)
        print self._socket.recv(10000)
        time.sleep(1)

        pass


c = Client("t1")
c.connect()
c.login()

        
