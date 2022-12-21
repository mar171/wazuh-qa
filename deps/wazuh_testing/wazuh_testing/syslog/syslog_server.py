import sys
import logging
import socketserver
import threading

TCP, UDP = 'tcp', 'udp'
HOST = "0.0.0.0"
common_logger_handler = logging.StreamHandler(sys.stdout)
common_logger_handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))


class SyslogTCPServer(socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, logger=None,
                 store_messages_filepath=None):
        self.lock = threading.RLock()
        self.n_messages = 0
        self.received_messages = []
        self.logger = logger
        self.store_messages_filepath = store_messages_filepath
        socketserver.TCPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=True)

    @property
    def n_messages(self):
        with self.lock:
            return self._n_messages

    @n_messages.setter
    def n_messages(self, value):
        with self.lock:
            self._n_messages = value

    def reset_messages_counter(self):
        self._n_messages = 0


class SyslogUDPServer(socketserver.UDPServer):
    def __init__(self, server_address, RequestHandlerClass, bind_and_activate=True, logger=None,
                 store_messages_filepath=None):
        self.lock = threading.RLock()
        self.n_messages = 0
        self.received_messages = []
        self.logger = logger
        self.store_messages_filepath = store_messages_filepath
        socketserver.UDPServer.__init__(self, server_address, RequestHandlerClass, bind_and_activate=True)

    @property
    def n_messages(self):
        with self.lock:
            return self._n_messages

    @n_messages.setter
    def n_messages(self, value):
        self._n_messages = value

    def reset_messages_counter(self):
        self._n_messages = 0


class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        with self.server.lock:
            self.server.n_messages += 1
            if self.server.store_messages_filepath:
                data = bytes.decode(self.request[0].strip())
                self.server.logger.DEBUG(f"Received message: {data}")
                with open(self.server.store_messages_filepath, 'w+') as f:
                    f.write(f"{data}")


class SyslogTCPHandler(socketserver.StreamRequestHandler):
    def handle(self):
        with self.server.lock:
            self.server.n_messages += 1
            if self.server.store_messages_filepath:
                data = self.request.recv(8192).strip()
                self.server.logger.DEBUG(f"Received message: {data}")
                with open(self.server.store_messages_filepath, 'w+') as f:
                    f.write(f"{data}")


class SyslogServer:

    def __init__(self, protocol=TCP, port='514', host=HOST, store_messages_filepath=None, debug=False):
        self.protocol = protocol
        self.port = port
        self.store_messages_filepath = store_messages_filepath
        self.messages_list = []

        logger_name = 'SyslogServerLogger'
        self.logger = logging.getLogger(logger_name)
        self.logger.setLevel(logging.DEBUG if debug else logging.INFO)
        self.logger.addHandler(common_logger_handler)

        socketserver.TCPServer.allow_reuse_address = True
        if self.protocol == TCP:
            self.server = SyslogTCPServer((host, self.port), SyslogTCPHandler,
                                          store_messages_filepath=self.store_messages_filepath,
                                          logger=self.logger)
        else:
            self.server = SyslogUDPServer((host, self.port), SyslogUDPHandler,
                                          store_messages_filepath=self.store_messages_filepath,
                                          logger=self.logger)

    def get_total_messages(self):
        return self.server.n_messages

    def reset_messages_counter(self):
        return self.server.reset_messages_counter()

    @property
    def protocol(self):
        return self._protocol

    @property
    def port(self):
        return self._port

    @port.setter
    def port(self, p):
        if not (p >= 0 and p <= 65535):
            raise Exception(f"Port {p} is not valid")
        self._port = p

    @protocol.setter
    def protocol(self, p):
        if p.lower() not in [TCP, UDP]:
            raise Exception(f"Protocol {p} is not valid")
        self._protocol = p

    def start(self):

        server_thread = threading.Thread(target=self.server.serve_forever)

        self.logger.info("Starting syslog server")

        server_thread.start()

    def shutdown(self):
        self.logger.info("Shutting down server")
        self.server.shutdown()
