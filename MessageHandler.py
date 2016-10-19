#!/usr/bin/env python
# -*- coding: utf-8 -*-

import traceback
from IM import *
from IM import BaseDefine_pb2
from IM import Buddy_pb2
from IM import File_pb2
from IM import Group_pb2
from IM import Login_pb2
from IM import Message_pb2
from IM import Other_pb2
from IM import Server_pb2
from IM import SwitchService_pb2
from TTBase import ImPdu
from TTSocketHandler import TTSocket


def _Heartbeat():
    hb = Other_pb2.IMHeartBeat()
    hb.Clear()
    pdu = ImPdu.ImPdu()
    pdu.setMsg(hb.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_OTHER)
    pdu.setCommandId(BaseDefine_pb2.CID_OTHER_HEARTBEAT)
    return pdu.SerializeToString()
    
def _Login(username, password, client_type=BaseDefine_pb2.CLIENT_TYPE_IOS):
    loginReq = Login_pb2.IMLoginReq()
    loginReq.Clear()
    pdu = ImPdu.ImPdu()
    try:
        loginReq.user_name = username
        loginReq.password = password
        loginReq.online_status = BaseDefine_pb2.USER_STATUS_ONLINE
        loginReq.client_type = client_type
        loginReq.SerializeToString()
        loginReq.client_version = 'v1.1.0'
    except Exception as e:
        print traceback.format_exc()
        raise e
    else:
        pdu.setMsg(loginReq.SerializeToString())
        pdu.setServiceId(BaseDefine_pb2.SID_LOGIN)
        pdu.setCommandId(BaseDefine_pb2.CID_LOGIN_REQ_USERLOGIN)
        return pdu.SerializeToString()

def _Logout():
    logoutReq = Login_pb2.IMLogoutReq()
    logoutReq.Clear()
    pdu = ImPdu.ImPdu()
    pdu.setMsg(logoutReq.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_LOGIN)
    pdu.setCommandId(BaseDefine_pb2.CID_LOGIN_REQ_LOGINOUT)
    return pdu.SerializeToString()

def _RecentContactSessionReq(user_id, last_update_time=0):
    req = Buddy_pb2.IMRecentContactSessionReq()
    req.Clear()
    req.user_id = user_id
    req.latest_update_time = last_update_time
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_BUDDY_LIST)
    pdu.setCommandId(BaseDefine_pb2.CID_BUDDY_LIST_RECENT_CONTACT_SESSION_REQUEST)
    return pdu.SerializeToString()

def _UnreadMsgCntReq(user_id):
    req = Message_pb2.IMUnreadMsgCntReq()
    req.Clear()
    req.user_id = user_id
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_MSG)
    pdu.setCommandId(BaseDefine_pb2.CID_MSG_UNREAD_CNT_REQUEST)
    return pdu.SerializeToString()

def _ClientUserInfoRequest(user_id, user_id_list):
    req = Buddy_pb2.IMUsersInfoReq()
    req.Clear()
    req.user_id = user_id
    
    req.user_id_list.extend(user_id_list)
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_BUDDY_LIST)
    pdu.setCommandId(BaseDefine_pb2.CID_BUDDY_LIST_USER_INFO_REQUEST)

class ClientConn(TTSocket):

    """Docstring for PduHandler. """

    def __init__(self, host, port):
        """TODO: to be defined1. """
        super(this, TTSocket).__init__(host, port)

    def Login(self, username, password):
        loginBody = _Login(username, password)
        self.Send(loginBody)

    def ProcLoop(self):
        while True:
            self.Recv()
            self._pduProc(self.buf)

    def _pduProc(self, pduBuf):
        pdu = ImPdu.ImPdu()
        pdu.FromString(pduBuf)
        if self.pdu.command_id == BaseDefine_pb2.CID_LOGIN_RES_USERLOGIN:
            self._onLogin()
        elif self.pdu.command_id == BaseDefine_pb2.CID_LOGIN_KICK_USER:

            pass

    def _onLogin(self):
        loginResp = Login_pb2.IMLoginRes()
        loginResp.Clear()
        loginResp.FromString(self.pdu.msg)


    def _onLogOut(self):
        self.Close()




            
        

#test only 
#rint _Login('1', '1')
#rint _Logout()
#rint _Heartbeat()
#rint _UnreadMsgCntReq(1)
#rint _ClientUserInfoRequest(1, [1,11,])
#rint _RecentContactSessionReq(1, 11)
