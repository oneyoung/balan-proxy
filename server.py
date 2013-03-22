#!/usr/bin/env python

# Copyright (c) 2012 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import struct
import string
import logging
from gevent import socket
from gevent import select
from gevent.server import StreamServer

MAX_CON = 20
connected = 0


class Codec:
    def __init__(self, key):
        self._encrypt_table = ''.join(self._hash_table(key))
        self._decrypt_table = string.maketrans(self._encrypt_table,
                                               string.maketrans('', ''))

    @staticmethod
    def _hash_table(key):
        import hashlib
        m = hashlib.md5()
        m.update(key)
        s = m.digest()
        (a, b) = struct.unpack('<QQ', s)
        table = [c for c in string.maketrans('', '')]
        for i in xrange(1, 1024):
            table.sort(lambda x, y: int(a % (ord(x) + i) - a % (ord(y) + i)))
        return table

    def encrypt(self, data):
        return data.translate(self._encrypt_table)

    def decrypt(self, data):
        return data.translate(self._decrypt_table)


class ServerHandler(Codec):
    def handle_tcp(self, sock, remote, sock_str=''):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    if remote.send(self.decrypt(sock.recv(4096))) <= 0:
                        break
                if remote in r:
                    if sock.send(self.encrypt(remote.recv(4096))) <= 0:
                        break
        finally:
            remote.close()
            logging.info('[%d/%d] <== %s' % (connected, MAX_CON, sock_str))

    def send_encrpyt(self, sock, data):
        sock.send(self.encrypt(data))

    def read_socket(self, sock, size):
        remain = size
        buf = ''
        retry = 0
        while remain > 0:
            buf += sock.recv(remain)
            remain = size - len(buf)
            retry += 1
        return buf

    def handle(self, sock, address):
        global connected
        try:
            connected += 1
            sock_str = "%s:%d" % (address[0], address[1])
            logging.info('[%d/%d] ==> %s' % (connected, MAX_CON, sock_str))
            import StringIO
            header = self.read_socket(sock, 262)
            print repr(header)
            rfile = StringIO.StringIO(header)
            self.send_encrpyt(sock, "\x05\x00")
            data = self.decrypt(rfile.read(4))
            mode = ord(data[1])
            addrtype = ord(data[3])
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(rfile.read(4)))
            elif addrtype == 3:
                addr = self.decrypt(
                    rfile.read(ord(self.decrypt(sock.recv(1)))))
            else:
                # not support
                return
            port = struct.unpack('>H', self.decrypt(rfile.read(2)))
            reply = "\x05\x00\x00\x01"
            try:
                if mode == 1:
                    remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    remote.connect((addr, port[0]))
                    local = remote.getsockname()
                    reply += socket.inet_aton(local[0]) + struct.pack(">H", local[1])
                    sock_str += "<==>%s:%d" % (addr, port[0])
                    logging.debug(sock_str)
                else:
                    reply = "\x05\x07\x00\x01"  # Command not supported
                    logging.error('command not supported')
            except socket.error:
                # Connection refused
                reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            self.send_encrpyt(sock, reply)
            if reply[1] == '\x00':
                if mode == 1:
                    self.handle_tcp(sock, remote, sock_str)
        except socket.error, e:
            logging.error('socket error: ' + str(e))
        finally:
            connected -= 1


def load_config(fname):
    import json

    config = json.load(open(fname), encoding='utf-8')
    return config


if __name__ == '__main__':
    # logging init
    logging.basicConfig(filename="/tmp/proxy_server.log", level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s')
    config = load_config('config.json')
    handler = ServerHandler(config.get('key'))
    server = StreamServer(('127.0.0.1', int(config.get('port'))), handler.handle)
    server.serve_forever()
