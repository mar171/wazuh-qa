import sys
import logging
import socketserver
import threading
import time
import argparse
from datetime import datetime

LOGGER = logging.getLogger('syslog_server_simulator')

TCP, UDP = 'tcp', 'udp'
HOST = "0.0.0.0"

global total_messages
global store_messages

total_messages = 0
lock = threading.RLock()


class SyslogUDPHandler(socketserver.BaseRequestHandler):

    def handle(self):
        global total_messages
        global store_messages

        with lock:
            total_messages += 1
            if store_messages:
                data = bytes.decode(self.request[0].strip())
                logging.info(f"RECV: {data}")
                socket = self.request[1]
                with open(store_messages, 'w+') as f:
                    f.write(f"{data}")


class SyslogTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        global total_messages
        global store_messages
        with lock:
            total_messages += 1
            if store_messages:
                data = self.request.recv(8192).strip()
                logging.info(f"RECV: {data}")
                with open(store_messages, 'w+') as f:
                    f.write(f"{data}")


def set_logging(debug=False):
    LOGGER.setLevel(logging.DEBUG if debug else logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))
    LOGGER.addHandler(handler)


def validate_parameters(parameters):
    """Validate parameters
    Args:
        parameters (argparse.Namespace): Parameters to validate
    """
    if parameters.protocol != TCP and parameters.protocol != UDP:
        LOGGER.error(f"Protocol {parameters.protocol} not supported")
        sys.exit(1)

    if parameters.server_time >= 0:
        LOGGER.error(f"Server time {parameters.server_time} should be greater than 0")
        sys.exit(1)

    if parameters.interval >= 0:
        LOGGER.error(f"Interval {parameters.interval} should be greater than 0")
        sys.exit(1)


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-p', '--protocol', metavar='<protocol>', type=str,
                            help='Protocol', required=False, default='udp', dest='protocol')

    arg_parser.add_argument('-P', '--port', metavar='<port>', type=int,
                            help='Port', required=False, default=514, dest='port')

    arg_parser.add_argument('-f', '--store-events-file', metavar='<store-events-file>', type=str,
                            help='File where store received events', required=False, default=None, dest='file_store_events')

    arg_parser.add_argument('-i', '--interval', metavar='<interval>', type=int,
                            help='Set interval for data gathering', required=False, default=None, dest='interval')

    arg_parser.add_argument('-t', '--server-time', metavar='<server-time>', type=int,
                            help='Syslog server time', required=True, default=None, dest='server_time')

    arg_parser.add_argument('-d', '--debub', metavar='<debug>', type=bool,
                            help='Enable debug mode', required=False, default=False, dest='debug')

    return arg_parser.parse_args()


def main():
    global store_messages
    global total_messages

    data_total = []
    parameters = get_parameters()

    set_logging(parameters.debug)
    validate_parameters(parameters)

    time_limit = time.time() + parameters.server_time
    store_messages = parameters.file_store_events

    socketserver.TCPServer.allow_reuse_address = True
    if parameters.protocol == TCP:
        server = socketserver.TCPServer((HOST, parameters.port), SyslogTCPHandler)
    elif parameters.protocol == UDP:
        server = socketserver.UDPServer((HOST, parameters.port), SyslogUDPHandler)

    server_thread = threading.Thread(target=server.serve_forever)

    LOGGER.info("Starting syslog server")

    server_thread.start()
    time_interval_previous = datetime.now()

    while True and time.time() < time_limit:
        time_interval_last = datetime.now()
        if (time_interval_last - time_interval_previous).total_seconds() >= parameters.interval:
            data_total.append(total_messages)
            with lock:
                total_messages = 0
            time_interval_previous = time_interval_last

    LOGGER.info("Shutting down server")
    server.shutdown()

    server_thread.join()

    final_messages_number = sum(messages for messages in data_total)
    LOGGER.info(f"Total messages {final_messages_number}")

    return final_messages_number


if __name__ == '__main__':
    main()
