#!/usr/bin/env python
# -*- coding: utf-8 -*-

client_seq = {}
def get_seq_id(client_id):
    global client_seq
    if not client_seq.get(client_id):
        client_seq[client_id] = 1
    else:
        client_seq[client_id] += 1
    yield client_seq[client_id]
