#!/usr/bin/env python
# -*- coding: utf-8 -*-

__author__ = 'Michael Strecke'

import struct

import socket

def outhex(s):
    print "Länge:",len(s)
    for x in s:
        print hex(ord(x)),
    print

class camDirect(object):
    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))


    def close(self):
        self.socket.close()


    def genpacket(self,opcode,data=None):
        if data is None: data = ""
        header = struct.pack("<4sHB8xL4x","MO_O",opcode,0,len(data))
        return header+data

socket.setdefaulttimeout(10)
cd = camDirect("192.168.0.102",88)
p = cd.genpacket(0)
outhex(p)
cd.socket.send(p)
data = cd.socket.recv(1024)
outhex(data)
cd.close()
