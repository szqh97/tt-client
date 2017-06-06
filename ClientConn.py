#!/usr/bin/env python
# -*- coding: utf-8 -*-

import httplib2
import struct
import traceback
import json
import logging
import socket
import time
import hashlib
from TTBase.util import install_logger
from TTBase.ImPdu import *
from IM.Login_pb2 import *
from IM.BaseDefine_pb2 import *
from IM.Buddy_pb2 import *
from IM.Message_pb2 import *
from IM.Group_pb2 import *
import ClientConnReq 
from tornado.ioloop import IOLoop
from config import cnt, MIN_TO_ID, MAX_TO_ID, MIN_FROM_ID, MAX_FROM_ID

log = install_logger("ClientConn")

def traceHandler(fn):
    log.debug('Entering {} ...'.format(fn.__name__))
    def w(x, y):
        return fn(x, y)
    log.debug('Leaving {} ...'.format(fn.__name__))
    return w

class ClientConn(object):

    """Docstring for ClientConn. """

    def __init__(self, username,
            ttserver="http://app-test.kaipao.cc/msg_server"):
        """
        ttserver is like: http://192.168.1.15:8400/msg_server
        """
        self.username = username
        h = hashlib.md5(self.username)
        self.password = h.hexdigest()
        h = hashlib.md5(self.password)
        self.password = h.hexdigest()
        self.ttserver = ttserver
        self._socket = None
        self._buffer = b''
        self._m_open = False
        self._connected = False
        self._online = False
        self._m_user_id = -1

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
                log.error('get msg server error: {}'.format(content))
        else:
            log.error('status is not 200, get msg server error: {}'.format(content))

    def connect(self):
        """
        connect teamtalk
        """
        ip, port  = self._getPriorIP() 
        if ip is not None and port is not None:
            self.priorIP = ip
            self.port = port
        else:
            log.error("prior IP is EMTPY!!")

        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.connect((ip, int(port)))
        log.info('ip:{}, port:{}'.format(ip, port))
        self._connected = True

    def sendData(self, buf):
        #log.debug('send data: {}'.format(buf.encode('utf-8')))
        self._socket.send(buf)

    def recvData(self):
        pdu = ImPdu()
        try:
            pduheaderbuf = self._socket.recv(16)
        except Exception as e:
            if e.errno == errno.ECONNRESET:
                log.error('receive failed: {}'.format(traceback.format_exc()))
                self._connected = False
        else:
            if len(pduheaderbuf) != 16:
                log.error("read pdu len errror, len: {}".format(len(pduheaderbuf)))
                self._connected = False
                return 
            try:
                pdu.FromString(pduheaderbuf)
            except Exception:
                log.error('unpack pdu length error: {}'.format(traceback.format_exc()))
            else:
                buf = self._socket.recv(pdu.length - 16)
                self._buffer = pduheaderbuf
                self._buffer += buf
        self.handlePdu()

    def handlePdu(self):
        if len(self._buffer) < 16 :
            log.info('recv data error: {}, length: {}'.format(self._buffer, len(self._buffer)))
            return 
        pdu = ImPdu()
        try:
            pdu.FromString(self._buffer)
        except Exception:
            log.info('=========> buffer is : [{}]'.format(self._buffer))
            log.info(traceback.format_exc())
        self._buffer = ''
        if pdu.command_id == CID_LOGIN_RES_USERLOGIN:
            self.handleLoginResponse(pdu)
        elif pdu.command_id == CID_BUDDY_LIST_RECENT_CONTACT_SESSION_RESPONSE:
            self.handleRecentContactSessionResponse(pdu)
        elif pdu.command_id == CID_BUDDY_LIST_USER_INFO_RESPONSE:
            self.hanledUserInfo(pdu)
        elif pdu.command_id == CID_MSG_DATA_ACK:
            self.handleSendMsg(pdu)
        elif pdu.command_id == CID_MSG_UNREAD_CNT_RESPONSE:
            self.handleUnreadCnt(pdu)
        elif pdu.command_id == CID_MSG_DATA:
            self.handleMsgData(pdu)
        elif pdu.command_id == CID_MSG_LIST_RESPONSE:
            self.handleListResponse(pdu)
        elif pdu.command_id == CID_OTHER_HEARTBEAT:
            self.handleHeartBeat(pdu)
        elif pdu.command_id == CID_MSG_READ_NOTIFY:
            self.handleReadNotify(pdu)
        elif pdu.command_id == CID_GROUP_CREATE_RESPONSE:
            self.handleCreateGroupResponse(pdu)
        else:
            log.info('Invalid command_id: {}'.format(pdu.command_id))
    
    def handleReadNotify(self, pdu):
        log.debug("In handleReadNotify")
        pass

    def handleRecentContactSessionResponse(self, pdu):
        resp = IMRecentContactSessionRsp.FromString(pdu.msg)
        log.info('in handleRecentContactSessionResponse , user: {},'
                ' concatSessionList: {}'.format(self._m_user_id, len(resp.contact_session_list)))
        pdu_msg = ClientConnReq._UnreadMsgCntReq(self._m_user_id)
        self._socket.send(pdu_msg)

    def handleMsgData(self, pdu):
        msg = IMMsgData.FromString(pdu.msg)
        log.info("in handleMsgData, user_id: {}, msg len: {}".format(self._m_user_id, msg.msg_data.__len__()))
        pdu_msg = ClientConnReq._MsgDataAck(self._m_user_id, msg.from_user_id, msg.msg_id)
        self._socket.send(pdu_msg)
        if msg.from_user_id == msg.to_session_id:
            return
        pdu_msg = ClientConnReq._MsgReadAck(self._m_user_id, msg.from_user_id, msg.msg_id)
        self._socket.send(pdu_msg)

    def heartbeat(self):
        """
            send heartbeat package in TestServer
        """
        pdu_msg = ClientConnReq._Heartbeat()
        self._socket.send(pdu_msg)

    def handleHeartBeat(self, pdu):
        #log.debug('in handleHeartBeat , fd: {}'.format(self._socket.fileno()))
        pass
    
    def handleListResponse(self, pdu):
        resp = IMLoginRes.FromString(pdu.msg)
        if resp.result_code != 0:
            log.error("login error: {}, {}".format(resp.result_code, resp.result_string.encode('utf-8')))
        else:
            self.m_open = True
            self._userInfo = resp.user_info

    def sendMsg(self ):
        """
        send msg to user which user_id = self._m_user_id + 5000
        send 20 msg per second

        """
        encrypted_msg = 'dgjzZcuwYVvgiMtBlzoa8RS7edxfMniMPR2naJakzDo6jfQKGGbzEee6ENKT4qW8o95BhdaLX1yonQuqKImGAJv9fdeyZEvjlfzrT5S4g3I='
        if self._m_user_id >= MIN_FROM_ID and self._m_user_id < MAX_FROM_ID:
            to_user_id = self._m_user_id + 5000 - 1
            log.debug("In sendMsg, from {} -> {}".format(self._m_user_id, to_user_id))
            pdu_msg = ClientConnReq._MsgData(self._m_user_id, to_user_id, encrypted_msg )
            self._socket.send(pdu_msg)
        elif self._m_user_id >= MIN_TO_ID and self._m_user_id < MAX_TO_ID:
            pass

    def handleUnreadCnt(self, pdu):
        resp = IMUnreadMsgCntRsp.FromString(pdu.msg)
        total_cnt= resp.total_cnt
        log.debug('in handleUnreadCnt, user: {}, user_id: {},' 
                'unread msg cnt: {}'.format(self.username, self._m_user_id, total_cnt))
        self.sendMsg()
        pass

    def handleLoginResponse(self, pdu):
        seqNo = pdu.seq_num
        msgResp = IMLoginRes.FromString(pdu.msg)
        ret = msgResp.result_code
        retMsg = msgResp.result_string
        if ret == 0 :
            self._online = True
            self._m_user_id = msgResp.user_info.user_id
            log.info('login successful: {}, {}'.format(ret, retMsg.encode('utf-8')))
            log.info('user id is : {}'.format(self._m_user_id))
#           pdu_msg = ClientConnReq._RecentContactSessionReq(self._m_user_id)
#           self._socket.send(pdu_msg)
#           log.info('_RecentContactSessionReq: {}'.format(self._m_user_id))
            #self.logout()
            #self.sendData(pdu_msg)
        else:
            log.error('login failed: {}, {}'.format(ret, retMsg.encode('utf-8')))

        pass

    def handleCreateGroupResponse(self, pdu):
        log.info("in handleCreateGroupResponse..")
        pass

    def hanledUserInfo(self, pdu):
        pass

    def handleSendMsg(self, pdu):
        """
           get unread msg while receiving msg
           CID_MSG_DATA_ACK
        """
        resp = IMMsgDataAck.FromString(pdu.msg)
        from_user_id = resp.user_id
        to_user_id = resp.session_id
        msg_id = resp.msg_id
        log.info("in  handleSendMsg, self.user_id: {}, from_user_id: {}, "
                " to_user_id: {}, msg_id: {}".format(self._m_user_id, from_user_id, to_user_id, msg_id))

    def login(self):
        pdu_msg = ClientConnReq._Login(self.username, self.password)
        try:
            self._socket.send(pdu_msg)
        except Exception as e:
            raise e
        else:
            pass

    def logout(self):
        pdu_msg = ClientConnReq._Logout()
        self._socket.send(pdu_msg)
        self._connected = False
        self._online = False
        self._socket.close()
        log.info('user {} closed'.format(self.username))

    def createGroup(self):
        user_id = 2396
        u_list = [12460, 13, 5]
        pdu_msg =ClientConnReq._CreateGroupReq(2396,  "test-g-1",u_list, "http://kaipao.cc/default_avatar.png" )
        time.sleep(4)
        log.info("in createGroupReq")
        self._socket.send(pdu_msg)

        
#### FOR TEST ONLY ####
#c = ClientConn("dj352801")
#c.connect()
#c.login()

