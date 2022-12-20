import argparse
import time
import os
import threading
import csv
from datetime import datetime

from wazuh_testing.syslog.syslog_server import SyslogServer
from wazuh_testing.tools.performance.statistic import StatisticMonitor
from wazuh_testing.tools.performance.binary import Monitor
from wazuh_testing.tools.file_stress import FileStress


WAZUH_METRICS = ['analysis']
WAZUH_STATISTICS_PROCESS = ['wazuh-analysisd', 'wazuh-syscheckd', 'wazuh-logcollector']

DATA_UNIT = 'B'


def process_script_parameters(args):
    pass


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', '--testing-time', metavar='<testing-time>', type=int,
                            help='Testing time', required=True, default=None, dest='testing_time')

    arg_parser.add_argument('-i', '--interval', metavar='<interval>', type=int,
                            help='Set interval for data gathering', required=False, default=None, dest='interval')

    arg_parser.add_argument('-d', '--debub', metavar='<debug>', type=bool,
                            help='Enable debug mode', required=False, default=False, dest='debug')

    arg_parser.add_argument('--enable-syslog-server', metavar='<enable-syslog-server>', type=str,
                            help='Enable syslog server', required=False, default='yes', dest='enable_syslog_server')

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

    data_total = []
    parameters = get_parameters()

    process_script_parameters(parameters)

    time_limit = time.time() + parameters.testing_time

    syslog_server = SyslogServer(protocol=parameters.syslog_server_protocol, port=parameters.syslog_server_port,
                                 store_messages_filepath=None,
                                 debug=parameters.debug)

    # Init remote syslog server
    syslog_server.start()
    time_interval_previous = datetime.now()

    report_path = os.path.join('/tmp', 'footprint')
    if not os.path.isdir(report_path):
        os.mkdir(report_path)

    # monitor = StatisticMonitor(target=WAZUH_METRICS, time_step=parameters.interval, dst_dir=report_path)
    wazuh_monitors = []
    # Get the footprint (CPU/etc during the interval)
    for process in WAZUH_STATISTICS_PROCESS:
        for i, pid in enumerate(Monitor.get_process_pids(process)):
            p_name = process if i == 0 else f'{process}_child_{i}'
            monitor = Monitor(process_name=p_name, pid=pid, value_unit=DATA_UNIT, time_step=parameters.interval,
                              version=None, dst_dir=report_path)
            monitor.start()
            wazuh_monitors.append(monitor)

    file_stress = FileStress(parameters.path, False)
    server_thread = threading.Thread(target=file_stress.start_file_stress, args=(parameters.epi_file_creation,
                                                                                 parameters.epi_file_update,
                                                                                 parameters.epi_file_delete,
                                                                                 "Testing-Event",
                                                                                 parameters.interval,))
    server_thread.start()

    data = ['timestamp', 'time', 'syslog_alerts']
    interval_csv_row = []

    counter_interval = 0
    interval_csv = counter_interval * parameters.interval
    interval_csv_row.append(interval_csv)

    with open('events.csv', 'a', newline='') as f:
        syslog_messages = syslog_server.get_total_messages()
        syslog_server.reset_messages_counter()
        timestamp = str(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
        csv_writer = csv.writer(f)
        csv_writer.writerow(list(data))
        csv_writer.writerow([timestamp, interval_csv, syslog_messages])

    while time.time() <= time_limit:
        time_interval_last = datetime.now()
        if (time_interval_last - time_interval_previous).total_seconds() >= parameters.interval:
            counter_interval += 1
            interval_csv = counter_interval*parameters.interval
            interval_csv_row.append(interval_csv)

            # Get syslog total messages received in the interval
            syslog_messages = syslog_server.get_total_messages()
            syslog_server.reset_messages_counter()
            timestamp = str(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))

            with open('events.csv', 'a', newline='') as f:
                csv_writer = csv.writer(f)
                csv_writer.writerow([timestamp, interval_csv, syslog_messages])

            time_interval_previous = time_interval_last

    file_stress.stop()

    for i in range(3):
        time.sleep(parameters.interval)
        counter_interval += 1
        interval_csv = counter_interval*parameters.interval
        with open('events.csv', 'a', newline='') as f:
            syslog_messages = syslog_server.get_total_messages()
            syslog_server.reset_messages_counter()
            timestamp = str(datetime.now().strftime('%Y/%m/%d %H:%M:%S'))
            csv_writer = csv.writer(f)
            csv_writer.writerow([timestamp, interval_csv, syslog_messages])

    for monitor in wazuh_monitors:
        monitor.shutdown()
    syslog_server.shutdown()

    # Clean Metrics CSV
    for file in os.listdir('/tmp/footprint'):
        with open(file, 'w+') as metric_file:
            lines = metric_file.readlines()
            lines = lines[:-1]

            cWriter = csv.writer(f, delimiter=',')
            for line in lines:
                cWriter.writerow(line)


if __name__ == '__main__':
    main()
