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
from IM import Group_pb2
from TTBase import ImPdu
from TTSocketHandler import TTSocket

from TTBase.util import install_logger
log = install_logger('ClientConnResp')

def _loginResponse(pdu):
    resp = IMLoginRes.FromString(pdu.msg)

def _createGroupResponse(pdu):
    resp = Group_pb2.IMGroupCreateRsp.FromString(pdu.msg)
    log.info("in _createGroupResponse: {}".format(resp.result_code) )
    log.info("in create group id: {}".format(resp.group_id))
    
def _disbandGroupResponse(pdu):
    resp = Group_pb2.IMGroupRemoveGroupResp.FromString(pdu.msg)
    log.info("in _disbandGroupResponse, result: {}".format(resp.result_code))

def _groupEventNotify(pdu):
    msg = Group_pb2.IMGroupEventNotify.FromString(pdu.msg)
    log.info("in _groupEventNotify receiving notify msg, user: {}, type: {}".format(msg.user_id, msg.type))

def _groupchangemember(pdu):
    msg = Group_pb2.IMGroupChangeMemberRsp.FromString(pdu.msg)
    log.info("in change group member response, user_id: %d, change_type: %d, result_code: %d", msg.user_id, msg.change_type, msg.result_code)

def _updateGroupInfoResponse(pdu):
    msg = Group_pb2.IMGroupUpdateInfoResp.FromString(pdu.msg)
    log.info("in update group info response, user_id = %d, change_type: %d, group_id:%d, result_code: %d",
            msg.user_id, msg.type, msg.group_id, msg.result_code)


def _getNormalGroupList(pdu):
    msg = Group_pb2.IMNormalGroupListRsp.FromString(pdu.msg)
    log.info("in get normal grouplist, user_id: {}, group size:{}".format(msg.user_id, msg.group_id_list))

def _GroupInfoListResponse(pdu):
    msg = Group_pb2.IMGroupInfoListRsp.FromString(pdu.msg)
    log.info("in group info list , user_id: {}, group info list: {}".format(msg.user_id, [x.group_name for x in msg.group_info_list]))
    print [x.announcement for x in msg.group_info_list]
    print [len(x.group_member_list) for x in msg.group_info_list]

def _GetRecentSessionResponse(pdu):
    resp = Buddy_pb2.IMRecentContactSessionRsp.FromString(pdu.msg)
    contact_session_list = [{"session_id": s.session_id, "type": s.session_type} for s in resp.contact_session_list]
    log.info("contact session list: {}".format(contact_session_list))

def _GetUnreadMsgCountResp(pdu):
    resp = Message_pb2.IMUnreadMsgCntRsp.FromString(pdu.msg)
    unreadinfolist = [{"session_id": s.session_id, "type":s.session_type, "cnt":s.unread_cnt, "lmsgid":s.latest_msg_id , "latest_from_id": s.latest_msg_from_user_id} for s in resp.unreadinfo_list]
    log.info("count: {}, unread info list: {}".format(resp.total_cnt, unreadinfolist))

def _GetLatestMsgIdResp(pdu):
    resp = Message_pb2.IMGetLatestMsgIdRsp.FromString(pdu.msg)
    log.info("latest msg id: {}".format(resp.latest_msg_id))

def _GetMsgListResp(pdu):
    resp = Message_pb2.IMGetMsgListRsp.FromString(pdu.msg)
    msgList = [{"msg_id": x.msg_id, "msg_ts": x.create_time, "type": x.msg_type, "from": x.from_session_id, "data":x.msg_data} for x in resp.msg_list]
    log.info(" last msgid : {}".format(resp.last_read_msg_id) )
    print msgList

def _DeleteMsgResp(pdu):
    resp = Message_pb2.IMDeleteMsgRsp.FromString(pdu.msg)
    log.info("user_id: {}, result: {}".format(resp.user_id, resp.result))

def _checkUserResp(pdu):
    resp = Control_pb2.IMUserCheckRsp.FromString(pdu.msg)
    log.info("user_id: {}, result_code: {}".format(resp.user_id, resp.result_code))
def _getusersinfoByname(pdu):
    resp = Buddy_pb2.IMUsersInfoByNameRsp.FromString(pdu.msg);
    log.info("userid:{}, len:{}".format(resp.user_id, len(resp.user_info_list)))
    idlist = [x.id for x in resp.user_info_list]
    print "xxxxxxxxxxx", idlist
