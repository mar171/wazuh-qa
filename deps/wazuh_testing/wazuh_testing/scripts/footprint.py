import argparse
import time
import os
import threading
import csv
import warnings
from datetime import datetime

from wazuh_testing.syslog.syslog_server import SyslogServer
from wazuh_testing.tools.performance.binary import Monitor
from wazuh_testing.tools.file_stress import FileStress
from wazuh_testing.tools.test_local_mode.generate_charts import plot_syslog_alerts, plot_footprint


WAZUH_METRICS = ['analysis']
WAZUH_STATISTICS_PROCESS = ['wazuh-analysisd', 'wazuh-syscheckd', 'wazuh-logcollector']
DATA_UNIT = 'B'
STATISTICS_PATH = os.path.join('/tmp', 'footprint')
EVENTS_CSV = 'events.csv'
FOOTPRINT_CSV = 'footprint.csv'
HEADER_SYSLOG_DATA = ['timestamp', 'seconds', 'num_received_alerts']

# Default events
DEFAULT_BASIC_EVENT = 'TESTING-EVENT'
DEFAULT_JSON_EVENT = '{"testing": "event"}'
DEFAULT_SYSLOG_EVENT = "Dec 25 20:45:02 MyHost example[12345]: User 'admin' logged from '192.168.1.100'"

EXTRA_INTERVALS_TO_WAIT = 3
COUNTER_INTERVAL = 0


def clean_csv_previous_results():
    if not os.path.isdir(STATISTICS_PATH):
        os.mkdir(STATISTICS_PATH)
    else:
        for file in os.listdir(STATISTICS_PATH):
            os.remove(os.path.join(STATISTICS_PATH, file))

    if os.path.exists(FOOTPRINT_CSV):
        try:
            os.remove(FOOTPRINT_CSV)
        except OSError:
            pass
    try:
        os.remove(EVENTS_CSV)
    except OSError:
        pass

    # Write the header of the CSV events file
    write_csv_file(EVENTS_CSV, HEADER_SYSLOG_DATA)


def start_file_stress(path, epi_file_creation, epi_file_update, epi_file_delete, event, interval,
                      debug=False):

    file_stress = FileStress(path, debug)
    server_thread = threading.Thread(target=file_stress.start_file_stress, args=(epi_file_creation,
                                                                                 epi_file_update,
                                                                                 epi_file_delete,
                                                                                 event,
                                                                                 interval,))
    server_thread.start()
    return file_stress


def write_csv_file(filename, data):
    with open(filename, 'a', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(data)


def remove_csv_last_lines(csv_directory, lines_to_remove=1):
    for file in os.listdir(csv_directory):
        with open(file, 'w+') as metric_file:
            lines = metric_file.readlines()
            lines = lines[:-lines_to_remove]

            csv_writer = csv.writer(metric_file, delimiter=',')
            for line in lines:
                csv_writer.writerow(line)


def process_script_parameters(args):
    if args.testing_time <= 0:
        raise ValueError('Testing time must be greater than 0')
    if args.interval <= 0:
        raise ValueError('Interval must be greater than 0')
    if not (os.path.exists(args.path) and os.path.isdir(args.path)):
        raise ValueError('Path must be a directory')


def start_syslog_server(protocol, port, store_messages_filepath, debug):
    syslog_server = SyslogServer(protocol=protocol, port=port, store_messages_filepath=store_messages_filepath,
                                 debug=debug)
    syslog_server.start()

    return syslog_server


def write_csv_events_row(interval, syslog_server):
    global COUNTER_INTERVAL
    syslog_messages = reset_syslog_alerts(syslog_server)
    interval_csv = COUNTER_INTERVAL * interval
    COUNTER_INTERVAL += 1
    write_csv_file(EVENTS_CSV, [datetime.now().strftime('%Y-%m-%d %H:%M:%S'), interval_csv, syslog_messages])


def init_processes_monitoring(interval):
    wazuh_monitors = []
    for process in WAZUH_STATISTICS_PROCESS:
        for i, pid in enumerate(Monitor.get_process_pids(process)):
            p_name = process if i == 0 else f'{process}_child_{i}'
            monitor = Monitor(process_name=p_name, pid=pid, value_unit=DATA_UNIT, time_step=interval, version=None,
                              dst_dir=STATISTICS_PATH)
            monitor.start()
            wazuh_monitors.append(monitor)
    return wazuh_monitors


def reset_syslog_alerts(syslog_server):
    syslog_messages = syslog_server.get_total_messages()
    syslog_server.reset_messages_counter()
    return syslog_messages


def events_monitoring(time_limit, extra_interval, syslog_server, file_stress, interval):
    current_time = datetime.now()
    while time.time() <= time_limit:
        time_interval_last = datetime.now()
        if (time_interval_last - current_time).total_seconds() >= interval:

            # Get syslog total messages received in the interval
            write_csv_events_row(interval, syslog_server)

            current_time = time_interval_last

    # Stop alerts generation
    file_stress.stop()

    # Wait for extra interval to get the last messages
    for _ in range(extra_interval):
        time.sleep(interval)

        # Get syslog total messages received in the interval
        write_csv_events_row(interval, syslog_server)


def create_footprint_csv_file(interval):
    with open('footprint.csv', 'w+') as footprint_file:
        csv_writer = csv.writer(footprint_file, delimiter=',')
        file_content = {}

        for file in os.listdir(STATISTICS_PATH):
            if file.endswith('.csv'):
                with open(os.path.join(STATISTICS_PATH, file), 'r') as metric_file:
                    file_content[file] = metric_file.readlines()

        # seconds, wazuh-daemon, CPU(%), RSS(KB), VMS(KB), disk_read(B), disk_written(B), FD
        header = ['wazuh-daemon', 'seconds', 'CPU(%)', 'RSS(KB)', 'VMS(KB)', 'disk_read(B)', 'disk_written(B)', 'FD']
        csv_writer.writerow(header)

        # Remove header
        n_lines = len(list(file_content.values())[0])
        for i in range(1, n_lines):
            seconds = i * interval
            for key in file_content.keys():
                line = file_content[key][i]
                row_values = line.split(',')
                daemon = row_values[0].replace('wazuh', 'ossec')
                cpu = row_values[5]
                rss = row_values[7]
                vmss = row_values[6]
                dis_read = row_values[13]
                disk_written = row_values[14]
                fd = row_values[10]
                row = [daemon, seconds, cpu, rss, vmss, dis_read, disk_written, fd]
                csv_writer.writerow(row)


def generate_charts():
    # Mute annoying warnings
    warnings.filterwarnings('ignore')

    date_time = datetime.now().strftime("%Y%m%d%H%M%S")
    syslog_alerts_data = EVENTS_CSV

    # Generate the charts
    plot_syslog_alerts(syslog_alerts_data, f"{date_time}_received_syslog_alerts.png")
    plot_footprint(FOOTPRINT_CSV, f"{date_time}")


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', '--testing-time', metavar='<testing-time>', type=int,
                            help='Testing time', required=True, default=None, dest='testing_time')

    arg_parser.add_argument('-i', '--interval', metavar='<interval>', type=int,
                            help='Set interval for data gathering', required=False, default=1, dest='interval')

    arg_parser.add_argument('-d', '--debug', metavar='<debug>', type=bool,
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

    arg_parser.add_argument('--use-default-syslog-event', metavar='<syslog-event>', type=str, default=None,
                            required=False, help='Use syslog event', dest='use_syslog_event')

    arg_parser.add_argument('--use-default-json-event', metavar='<json-event>', type=str, default=None, required=False,
                            help='Use json event', dest='use_json_event')

    return arg_parser.parse_args()


def main():
    parameters = get_parameters()
    process_script_parameters(parameters)
    time_limit = time.time() + parameters.testing_time

    # Init remote syslog server
    syslog_server = start_syslog_server(protocol=parameters.syslog_server_protocol, port=parameters.syslog_server_port,
                                        store_messages_filepath=None, debug=parameters.debug)

    # Clean previous results and create new csv file with expected header
    clean_csv_previous_results()

    # Get statistics of WAZUH_STATISTICS_PROCESS list
    monitors = init_processes_monitoring(parameters.interval)

    # Init file stress thread
    file_stress_thread = start_file_stress(epi_file_creation=parameters.epi_file_creation,
                                           epi_file_update=parameters.epi_file_update,
                                           epi_file_delete=parameters.epi_file_delete,
                                           interval=parameters.interval, path=parameters.path,
                                           debug=parameters.debug, event=DEFAULT_SYSLOG_EVENT)

    # Set initial values - Get syslog total messages received in the interval
    write_csv_events_row(parameters.interval, syslog_server)

    # For each interval, get the total messages received in the interval and write it to the csv file
    events_monitoring(time_limit, EXTRA_INTERVALS_TO_WAIT, syslog_server, file_stress_thread, parameters.interval)

    # Stop monitors
    for monitor in monitors:
        monitor.shutdown()

    # Stop syslog server
    syslog_server.shutdown()

    remove_csv_last_lines(STATISTICS_PATH)

    # Create a csv file with the footprint data
    create_footprint_csv_file(parameters.interval)

    # Generating charts
    generate_charts()


if __name__ == '__main__':
    main()
