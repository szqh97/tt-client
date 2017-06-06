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
    


