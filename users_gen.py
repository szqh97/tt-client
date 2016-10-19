#!/usr/bin/env python
# -*- coding: utf-8 -*-
import time
import hashlib

user_prefix='test'
f = open('./batch_users.sql', 'w')
_sql = 'insert into IMUser (sex, name, domain, nick, password, salt, phone, avatar, departId, status, created, updated, push_shield_status, sign_info) values (1, "{name}", "{name}", "{name}", "{password}", "0000", "11111111111", "http://192.168.1.15/T3KaETB5AT1R49Ip6K.jpeg", 1, 0, {ts}, {ts}, 0, "a" );'
for i in xrange(10000):
    ts = int(time.time())
    name = user_prefix + str(i+1)
    password = hashlib.md5(hashlib.md5(hashlib.md5(name).hexdigest() ).hexdigest()+'0000').hexdigest()

    #print _sql.format(name=name, password=password, ts=ts )
    f.write(_sql.format(name=name, password=password, ts=ts))
    f.write('\n')
    
f.close()
