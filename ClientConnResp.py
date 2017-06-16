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
log = install_logger('ClientConnReq')

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
