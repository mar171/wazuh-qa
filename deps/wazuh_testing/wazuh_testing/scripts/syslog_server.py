import sys
import logging
import time
import argparse
from datetime import datetime
from wazuh_testing.syslog import SyslogServer

TCP, UDP = 'tcp', 'udp'
HOST = "0.0.0.0"
common_logger_handler = logging.StreamHandler(sys.stdout)
common_logger_handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-p', '--protocol', metavar='<protocol>', type=str,
                            help='Protocol', required=False, default='udp', dest='protocol')

    arg_parser.add_argument('-P', '--port', metavar='<port>', type=int,
                            help='Port', required=False, default=514, dest='port')

    arg_parser.add_argument('-f', '--store-events-file', metavar='<store-events-file>', type=str,
                            help='File where store received events', required=False, default=None,
                            dest='file_store_events')

    arg_parser.add_argument('-i', '--interval', metavar='<interval>', type=int,
                            help='Set interval for data gathering', required=True, default=None, dest='interval')

    arg_parser.add_argument('-t', '--server-time', metavar='<server-time>', type=int,
                            help='Syslog server time', required=True, default=None, dest='server_time')

    arg_parser.add_argument('-d', '--debub', metavar='<debug>', type=bool,
                            help='Enable debug mode', required=False, default=False, dest='debug')

    return arg_parser.parse_args()


def main():
    n_messages_intervals = []
    parameters = get_parameters()

    time_limit = time.time() + parameters.server_time

    store_messages = parameters.file_store_events

    logger_name = 'MeasureSyslogEventsLogger'

    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG if parameters.debug else logging.INFO)
    logger.addHandler(common_logger_handler)

    syslog_server = SyslogServer(protocol=parameters.protocol, port=parameters.port,
                                 store_messages_filepath=store_messages,
                                 debug=parameters.debug)

    syslog_server.start()
    time_interval_previous = datetime.now()

    while True and time.time() < time_limit:
        time_interval_last = datetime.now()
        if (time_interval_last - time_interval_previous).total_seconds() >= parameters.interval:
            n_messages_intervals.append(syslog_server.get_total_messages())
            syslog_server.reset_messages_counter()
            time_interval_previous = time_interval_last

    syslog_server.shutdown()

    logger.info(f"Messages for interval {n_messages_intervals}")
    logger.info(f"Total messages {sum([n for n in n_messages_intervals])}")

    return n_messages_intervals


if __name__ == '__main__':
    main()
