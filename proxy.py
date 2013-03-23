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
    def __init__(self, *args):
        self.active_num = 0
        Codec.__init__(self, *args)

    def handle_tcp(self, sock, remote, sock_str=''):
        try:
            fdset = [sock, remote]
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    try:
                        if remote.send(self.decrypt(sock.recv(4096))) <= 0:
                            break
                    except socket.error, e:
                        logging.error(sock_str + " remote send error: " + str(e))
                if remote in r:
                    try:
                        if sock.send(self.encrypt(remote.recv(4096))) <= 0:
                            break
                    except socket.error, e:
                        logging.error(sock_str + " sock send error: " + str(e))
        finally:
            remote.close()
            logging.info('[%d] <== %s' % (self.active_num, sock_str))

    def send_encrpyt(self, sock, data):
        sock.send(self.encrypt(data))

    def handle(self, sock, address):
        try:
            self.active_num += 1
            sock_str = "%s:%d" % (address[0], address[1])
            logging.info('[%d] ==> %s' % (self.active_num, sock_str))
            sock.recv(3)  # recv 3 bytes version id/method selection msg
            self.send_encrpyt(sock, "\x05\x00")  # reply version + No Auth
            data = self.decrypt(sock.recv(4))
            mode = ord(data[1])
            addrtype = ord(data[3])
            if addrtype == 1:
                addr = socket.inet_ntoa(self.decrypt(sock.recv(4)))
            elif addrtype == 3:
                addr = self.decrypt(
                    sock.recv(ord(self.decrypt(sock.recv(1)))))
            else:
                # not support
                return
            port = struct.unpack('>H', self.decrypt(sock.recv(2)))
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
            except socket.error, e:
                # Connection refused
                logging.error(sock_str + ' remote conn fail: ' + str(e))
                reply = '\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00'
            self.send_encrpyt(sock, reply)
            if reply[1] == '\x00':
                if mode == 1:
                    self.handle_tcp(sock, remote, sock_str)
        except Exception, e:
            logging.error(sock_str + ' socket error: ' + str(e))
        finally:
            self.active_num -= 1


class LocalHandler():
    def __init__(self):
        self._servers = []

    def add_server(self, addr, key):
        self._servers.append((addr, Codec(key)))

    def _pick_server(self):
        import random
        servers = self._servers
        index = random.randint(0, len(servers) - 1)
        host, codec = servers[index]
        return (host, codec)

    def _handle_tcp(self, sock, remote, codec):
        try:
            fdset = [sock, remote]
            counter = 0
            while True:
                r, w, e = select.select(fdset, [], [])
                if sock in r:
                    r_data = sock.recv(4096)
                    if counter == 1:
                        try:
                            logging.info(
                                "Connecting " + r_data[5:5 + ord(r_data[4])])
                        except Exception:
                            pass
                    if counter < 2:
                        counter += 1
                    if remote.send(codec.encrypt(r_data)) <= 0:
                        break
                if remote in r:
                    if sock.send(codec.decrypt(remote.recv(4096))) <= 0:
                        break
        finally:
            remote.close()

    def handle(self, sock, address):
        try:
            host, codec = self._pick_server()
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.connect(host)
            self._handle_tcp(sock, remote, codec)
        except socket.error, e:
            logging.error(str(host) + ' socket error: ' + str(e))


def start_server(port, key):
    logging.basicConfig(filename="/tmp/proxy_server_%s.log" % port, level=logging.WARNING,
                        format='%(asctime)s %(levelname)s: %(message)s')
    handler = ServerHandler(key)
    logging.info("Listen to port: %s" % port)
    server = StreamServer(('0.0.0.0', int(port)), handler.handle)
    server.serve_forever()


def start_local(config):
    import sys
    logging.basicConfig(stream=sys.stdout, level=logging.DEBUG,
                        format='%(asctime)s %(levelname)s: %(message)s')

    from ConfigParser import ConfigParser
    parser = ConfigParser()
    parser.read(config)
    listen_port = parser.getint('local', 'listen_port')

    handler = LocalHandler()
    for section in parser.sections():
        if section == 'local':
            continue
        try:
            host = parser.get(section, 'host')
            port = parser.getint(section, 'port')
            key = parser.get(section, 'key')
        except:
            logging.warning("invalid proxy config: %s" % section)
            logging.warning(parser.items(section))
            continue
        logging.info("add server: %s:%s" % (host, port))
        handler.add_server((host, port), key)

    logging.info("Listen to port: %s" % listen_port)
    server = StreamServer(('127.0.0.1', listen_port), handler.handle)
    server.serve_forever()


if __name__ == '__main__':
    from optparse import OptionParser
    usage = '''usage:
        as server: %prog -s PORT KEY
        as local : %prog [OPTIONS] '''
    parser = OptionParser(usage=usage)
    parser.add_option('-s', '--server', dest='server', default=False,
                      action="store_true", help="Proxy run as a server")
    parser.add_option('-c', '--config', dest='config', default='config.ini',
                      help="config file for local mode, default: config.ini",
                      metavar='FILE')

    (options, args) = parser.parse_args()
    if options.server:
        port, key = args[-2:]
        start_server(int(port), key)
    else:
        config = options.config
        start_local(config)
