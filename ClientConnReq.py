#!/usr/bin/env python
# -*- coding: utf-8 -*-

import time
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
import traceback

from TTBase.util import install_logger
log = install_logger('ClientConnReq')

def _Heartbeat():
    #log.info('_Heartbeat')
    hb = Other_pb2.IMHeartBeat()
    hb.Clear()
    pdu = ImPdu.ImPdu()
    pdu.setMsg(hb.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_OTHER)
    pdu.setCommandId(BaseDefine_pb2.CID_OTHER_HEARTBEAT)
    return pdu.SerializeToString()
    
def _Login(username, password, client_type=BaseDefine_pb2.CLIENT_TYPE_ANDROID):
    log.info('_Login, username: {}, client_type: {}'.format(username, client_type))
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
    log.info('_Logout')
    logoutReq = Login_pb2.IMLogoutReq()
    logoutReq.Clear()
    pdu = ImPdu.ImPdu()
    pdu.setMsg(logoutReq.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_LOGIN)
    pdu.setCommandId(BaseDefine_pb2.CID_LOGIN_REQ_LOGINOUT)
    return pdu.SerializeToString()

def _RecentContactSessionReq(user_id, last_update_time=0):
    log.info('_RecentContactSessionReq, user_id: {}'.format(user_id))
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
    log.info('_UnreadMsgCntReq, user id: {}'.format(user_id))
    req = Message_pb2.IMUnreadMsgCntReq()
    req.Clear()
    req.user_id = user_id
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_MSG)
    pdu.setCommandId(BaseDefine_pb2.CID_MSG_UNREAD_CNT_REQUEST)
    return pdu.SerializeToString()

def _ClientUserInfoRequest(user_id, user_id_list):
    log.info('_ClientUserInfoRequest, user_id: {}'.format(user_id))
    req = Buddy_pb2.IMUsersInfoReq()
    req.Clear()
    req.user_id = user_id
    
    req.user_id_list.extend(user_id_list)
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_BUDDY_LIST)
    pdu.setCommandId(BaseDefine_pb2.CID_BUDDY_LIST_USER_INFO_REQUEST)
    return pdu.SerializeToString()

def _MsgData(from_user_id, to_user_id, msg_data, msg_type=BaseDefine_pb2.MSG_TYPE_SINGLE_TEXT):
    log.info('_MsgData, from {} -> {}'.format(from_user_id, to_user_id))
    req = Message_pb2.IMMsgData()
    req.Clear()
    req.msg_data = msg_data 
    req.from_user_id = from_user_id
    req.to_session_id = to_user_id
    req.msg_id = 0
    req.msg_type = msg_type
    req.create_time = int(time.time())
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_MSG)
    pdu.setCommandId(BaseDefine_pb2.CID_MSG_DATA)
    return pdu.SerializeToString()

def _MsgDataAck(from_user_id, session_id, msg_id, session_type=BaseDefine_pb2.SESSION_TYPE_SINGLE):
    log.info("_MsgDataAck, from {} , to {}, msg_id: {}".format(from_user_id, session_id, msg_id))
    req = Message_pb2.IMMsgDataAck()
    req.Clear()
    req.user_id = from_user_id
    req.session_id = session_id
    req.session_type = session_type
    req.msg_id = msg_id
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_MSG)
    pdu.setCommandId(BaseDefine_pb2.CID_MSG_DATA_ACK)
    return pdu.SerializeToString()

    pass

def _MsgReadAck(from_user_id, session_id, msg_id, session_type=BaseDefine_pb2.SESSION_TYPE_SINGLE):
    log.debug('_MsgReadAck, from: {}, to: {}, msg_id: {}'.format(from_user_id, session_id, msg_id))
    req = Message_pb2.IMMsgDataReadAck()
    req.Clear()
    req.user_id = from_user_id
    req.session_id  = session_id
    req.session_type = session_type
    req.msg_id = msg_id
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_MSG)
    pdu.setCommandId(BaseDefine_pb2.CID_MSG_READ_ACK)
    return pdu.SerializeToString()

