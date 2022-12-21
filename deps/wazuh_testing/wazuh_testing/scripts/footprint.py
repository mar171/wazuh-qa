import argparse
import time
import os
import threading
import csv
from datetime import datetime

from wazuh_testing.syslog.syslog_server import SyslogServer
from wazuh_testing.tools.performance.binary import Monitor
from wazuh_testing.tools.file_stress import FileStress


WAZUH_METRICS = ['analysis']
WAZUH_STATISTICS_PROCESS = ['wazuh-analysisd', 'wazuh-syscheckd', 'wazuh-logcollector']
DATA_UNIT = 'B'
STATISTICS_PATH = os.path.join('/tmp', 'footprint')
EVENTS_CSV = 'events.csv'
HEADER_SYSLOG_DATA = ['timestamp', 'time', 'syslog_alerts']
DEFAULT_EVENT = 'TESTING-EVENT'


def write_csv_file(filename, data):
    with open(filename, 'a', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(data)


def process_script_parameters(args):
    if args.testing_time <= 0:
        raise ValueError('Testing time must be greater than 0')
    if args.interval <= 0:
        raise ValueError('Interval must be greater than 0')
    if not (os.path.exists(args.path) and os.path.isdir(args.path)):
        raise ValueError('Path must be a directory')


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', '--testing-time', metavar='<testing-time>', type=int,
                            help='Testing time', required=True, default=None, dest='testing_time')

    arg_parser.add_argument('-i', '--interval', metavar='<interval>', type=int,
                            help='Set interval for data gathering', required=False, default=1, dest='interval')

    arg_parser.add_argument('-d', '--debub', metavar='<debug>', type=bool,
                            help='Enable debug mode', required=False, default=False, dest='debug')

    arg_parser.add_argument('--syslog-server-protocol', metavar='<protocol>', type=str,
                            help='Syslog server protocol', required=False, default='udp', dest='syslog_server_protocol')

    arg_parser.add_argument('--syslog-server-port', metavar='<syslog-server-port>', type=int,
                            help='Syslog Server port', required=False, default=514, dest='syslog_server_port')

    arg_parser.add_argument('--path', metavar='<path>', type=str,
                            help='Path to file creation', required=False, default='/tmp/', dest='path')

    arg_parser.add_argument('--epi-file-creation', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file creation event type', dest='epi_file_creation')

    arg_parser.add_argument('--epi-file-update', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file update event type', dest='epi_file_update')

    arg_parser.add_argument('--epi-file-delete', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file delete event type', dest='epi_file_delete')

    arg_parser.add_argument('-f', '--filename-header', metavar='<filename>', type=str, default=None, required=False,
                            help='Filename header', dest='filename_header')

    return arg_parser.parse_args()


def main():

    parameters = get_parameters()
    process_script_parameters(parameters)

    time_limit = time.time() + parameters.testing_time

    syslog_server = SyslogServer(protocol=parameters.syslog_server_protocol, port=parameters.syslog_server_port,
                                 store_messages_filepath=None,
                                 debug=parameters.debug)

    # Init remote syslog server
    syslog_server.start()

    current_time = datetime.now()

    if not os.path.isdir(STATISTICS_PATH):
        os.mkdir(STATISTICS_PATH)

    # Get statistics of WAZUH_STATISTICS_PROCESS list
    wazuh_monitors = []
    for process in WAZUH_STATISTICS_PROCESS:
        for i, pid in enumerate(Monitor.get_process_pids(process)):
            p_name = process if i == 0 else f'{process}_child_{i}'
            monitor = Monitor(process_name=p_name, pid=pid, value_unit=DATA_UNIT, time_step=parameters.interval,
                              version=None, dst_dir=STATISTICS_PATH)
            monitor.start()
            wazuh_monitors.append(monitor)

    # Init file stress thread
    file_stress = FileStress(parameters.path, False)
    server_thread = threading.Thread(target=file_stress.start_file_stress, args=(parameters.epi_file_creation,
                                                                                 parameters.epi_file_update,
                                                                                 parameters.epi_file_delete,
                                                                                 DEFAULT_EVENT,
                                                                                 parameters.interval,))
    server_thread.start()

    counter_interval = 0
    interval_csv = counter_interval * parameters.interval

    # Set initial values - Get syslog total messages received in the interval
    syslog_messages = syslog_server.get_total_messages()
    syslog_server.reset_messages_counter()
    timestamp = str(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
    write_csv_file(EVENTS_CSV, HEADER_SYSLOG_DATA)
    write_csv_file(EVENTS_CSV, [timestamp, interval_csv, syslog_messages])

    # For each interval, get the total messages received in the interval and write it to the csv file
    while time.time() <= time_limit:
        time_interval_last = datetime.now()
        if (time_interval_last - current_time).total_seconds() >= parameters.interval:

            counter_interval += 1
            interval_csv = counter_interval*parameters.interval

            # Get syslog total messages received in the interval
            syslog_messages = syslog_server.get_total_messages()
            syslog_server.reset_messages_counter()
            timestamp = str(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))

            write_csv_file(EVENTS_CSV, [timestamp, interval_csv, syslog_messages])

            current_time = time_interval_last

    # Stop alerts generation
    file_stress.stop()

    # Wait for one extra interval to get the last messages

    time.sleep(parameters.interval)
    counter_interval += 1
    interval_csv = counter_interval*parameters.interval

    syslog_messages = syslog_server.get_total_messages()
    syslog_server.reset_messages_counter()
    timestamp = str(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))

    write_csv_file(EVENTS_CSV, [timestamp, interval_csv, syslog_messages])

    # Stop monitors
    for monitor in wazuh_monitors:
        monitor.shutdown()

    # Stop syslog server
    syslog_server.shutdown()

    # Remove statistics extra row.
    for file in os.listdir('/tmp/footprint'):
        with open(file, 'w+') as metric_file:
            lines = metric_file.readlines()
            lines = lines[:-1]

            cWriter = csv.writer(metric_file, delimiter=',')
            for line in lines:
                cWriter.writerow(line)


if __name__ == '__main__':
    main()
