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

def _CreateGroupReq(user_id, group_name, user_list, avatar):
    log.debug("_CreateGroupReq")
    req = Group_pb2.IMGroupCreateReq()
    req.Clear()
    req.user_id = user_id
    req.group_type = 1
    req.group_name = group_name
    req.member_id_list.extend(user_list)
    req.group_avatar = avatar
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_GROUP)
    pdu.setCommandId(BaseDefine_pb2.CID_GROUP_CREATE_REQUEST)
    return pdu.SerializeToString()

def _DisbandGroupReq(user_id, group_id):
    log.info("user: %d disband group: %d", user_id, group_id)
    req = Group_pb2.IMGroupRemoveGroupRequest()
    req.Clear()
    req.user_id = user_id
    req.group_id = group_id
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_GROUP)
    pdu.setCommandId(BaseDefine_pb2.CID_GROUP_REMOVE_GROUP_REQUEST)
    return pdu.SerializeToString()

def _ChangeGroupMembmber(user_id, group_id,  add_user_list, ctype = 1):
    log.info("user_id: %d add users to group: %d", user_id, group_id)
    req = Group_pb2.IMGroupChangeMemberReq();
    req.Clear()
    req.user_id = user_id
    req.group_id = group_id
    req.member_id_list.extend(add_user_list)
    req.change_type = ctype 
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_GROUP)
    pdu.setCommandId(BaseDefine_pb2.CID_GROUP_CHANGE_MEMBER_REQUEST)
    return pdu.SerializeToString()

def _UpdateGroupInfo(user_id, etype, group_id, update_data):
    log.info("user_id: %d update group: %d, type: %d, data: %s", user_id, etype, group_id, update_data)
    req = Group_pb2.IMGroupUpdateInfoReq()
    req.Clear()
    req.user_id = user_id
    req.type = etype
    req.group_id = group_id
    req.update_data = update_data
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_GROUP)
    pdu.setCommandId(BaseDefine_pb2.CID_GROUP_UPDATE_GROUP_REQUEST)
    return pdu.SerializeToString()

def _getGroupList(user_id):
    log.info("user: %d, requsest grouplist")
    req = Group_pb2.IMNormalGroupListReq()
    req.Clear()
    req.user_id = user_id
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_GROUP)
    pdu.setCommandId(BaseDefine_pb2.CID_GROUP_NORMAL_LIST_REQUEST)
    return pdu.SerializeToString()

def _getGroupInfoList(user_id, group_id_list):
    log.info("user_id: {}, group_id_list: {}".format(user_id, group_id_list))
    req = Group_pb2.IMGroupInfoListReq()
    req.Clear()
    req.user_id = user_id
    req.group_id_list.extend(group_id_list)
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_GROUP)
    pdu.setCommandId(BaseDefine_pb2.CID_GROUP_INFO_REQUEST)
    return pdu.SerializeToString()

def _getLatestMsgId(user_id, session_type, session_id):
    log.info("userId:{}, session_type:{}, session_id:{}".format(user_id, session_type, session_id))
    req = Message_pb2.IMGetLatestMsgIdReq()
    req.Clear()
    req.user_id = user_id
    req.session_type = session_type
    req.session_id = session_id
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_MSG)
    pdu.setCommandId(BaseDefine_pb2.CID_MSG_GET_LATEST_MSG_ID_REQ)
    return pdu.SerializeToString()

def _getMsgListReq(user_id, session_type, session_id, msg_id_begin, cnt):
    log.info("userId:{}, sessiontype:{}, session_id:{}, msgid_begin:{}, cnt:{}".format( user_id, session_type, session_id, msg_id_begin, cnt))
    req = Message_pb2.IMGetMsgListReq()
    req.Clear()
    req.user_id = user_id
    req.session_type = session_type
    req.session_id = session_id
    req.msg_id_begin = msg_id_begin
    req.msg_cnt = cnt
    pdu = ImPdu.ImPdu()
    pdu.setMsg(req.SerializeToString())
    pdu.setServiceId(BaseDefine_pb2.SID_MSG)
    pdu.setCommandId(BaseDefine_pb2.CID_MSG_LIST_REQUEST)
    return pdu.SerializeToString()

