#!/usr/bin/env python
# -*- coding: utf-8 -*-
import struct
import SeqGenerator

PDU_HEAD_LEN = 16

class ImPdu(object):

    """
     typedef struct {
	 uint32_t    length;       // the whole pdu length
	 uint16_t    version;      // pdu version number
	 uint16_t    flag;         // not used
	 uint16_t    service_id;   //
	 uint16_t    command_id;   //
	 uint16_t    seq_num;     // 包序号
	 uint16_t    reversed;    // 保留
     } PduHeader_t;
    """

    def __init__(self, service_id=1, command_id=1, client_id=1, reversed=0, msg=b'' ):
        self.length = PDU_HEAD_LEN
	self.version = 1
	self.flag = 1
	self.service_id = service_id
	self.command_id = command_id
	self.seq_num = SeqGenerator.get_seq_id(client_id).next()
	self.reversed = reversed
        self.msg = msg

    def setServiceId(self, service_id):
        self.service_id = service_id

    def setCommandId(self, command_id):
        self.command_id = command_id

    def setMsg(self, msg):
        self.msg = msg
        self.length = PDU_HEAD_LEN + len(self.msg)

    def SerializeToString(self):
        return  struct.pack('>I6h', self.length, self.version, self.flag, self.service_id, self.command_id, self.seq_num % 32767, self.reversed)  + self.msg

    def FromString(self, buf):
        self.msg = buf[PDU_HEAD_LEN:]
        (self.length, self.version, self.flag, self.service_id, self.command_id, self.seq_num, self.reversed) = struct.unpack('>I6h', buf[0:PDU_HEAD_LEN])

