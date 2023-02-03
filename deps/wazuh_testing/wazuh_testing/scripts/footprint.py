import argparse
import time
import sched
import os
import threading
import logging
import sys
import csv
import warnings
from datetime import datetime, timedelta
from sys import getsizeof

from wazuh_testing.syslog.syslog_server import SyslogServer
from wazuh_testing.tools.performance.binary import Monitor
from wazuh_testing.tools.file_stress import FileStress
from wazuh_testing.tools.test_local_mode.generate_charts import plot_syslog_alerts, plot_footprint

common_logger_handler = logging.StreamHandler(sys.stdout)
common_logger_handler.setFormatter(logging.Formatter("%(asctime)s — FootPrint —  %(levelname)s — %(message)s"))


WAZUH_METRICS = ['analysis']
WAZUH_STATISTICS_PROCESS = ['ossec-analysisd', 'ossec-syscheckd', 'ossec-logcollector']
DATA_UNIT = 'KB'
STATISTICS_PATH = os.path.join('/tmp', 'footprint')
EVENTS_CSV = 'events.csv'
FOOTPRINT_CSV = 'footprint.csv'

# Default events
DEFAULT_BASIC_EVENT = 'TESTING-EVENT'
DEFAULT_JSON_EVENT = '{"testing": "event"}'
DEFAULT_SYSLOG_EVENT = "Dec 25 20:45:02 MyHost example[12345]: User 'admin' logged from '192.168.1.100'"
ALERTS_JSON = '/var/ossec/logs/alerts/alerts.json'

EXTRA_INTERVALS_TO_WAIT = 5
COUNTER_INTERVAL = 0

global N_ALERTS_JSON


def define_event(parameters):
    event_to_use = DEFAULT_SYSLOG_EVENT if parameters.event_type == 'syslog' else DEFAULT_JSON_EVENT
    if parameters.fixed_event_size:

        event_msg_size = getsizeof(event_to_use)
        dummy_message_size = parameters.fixed_event_size - event_msg_size
        if dummy_message_size < 0:
            raise ValueError('Fixed event size must be greater than the size of the event message')

        char_size = getsizeof(event_to_use[0]) - getsizeof('')

        if parameters.event_type == 'syslog':
            event_to_use += 'A' * (dummy_message_size//char_size)
        else:
            event_to_use = event_to_use.replace('event', 'event' + 'A' * (dummy_message_size//char_size))
    return event_to_use


def init_logger(debug=False, logger_name='Footprint'):
    logger = logging.getLogger(logger_name)
    logger.setLevel(logging.DEBUG if parameters.debug else logging.INFO)
    logger.addHandler(common_logger_handler)


def clean_csv_results():
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


def write_events_header(monitor_alerts=True, monitor_syslog=True):
    header = ['timestamp', 'seconds', 'epi']

    if monitor_alerts:
        header.append('num_alerts')
    if monitor_syslog:
        header.append('num_syslog')

    write_csv_file(EVENTS_CSV, header)


def start_file_stress(path, epi_file_creation, epi_file_update, epi_file_delete, event, interval,
                      debug=False, add_counter_to_events=True):

    file_stress = FileStress(path, debug)
    server_thread = threading.Thread(target=file_stress.start_file_stress, args=(epi_file_creation,
                                                                                 epi_file_update,
                                                                                 epi_file_delete,
                                                                                 event,
                                                                                 interval, 'file', False))
    server_thread.start()
    return file_stress


def write_csv_file(filename, data):
    with open(filename, 'a', newline='') as f:
        csv_writer = csv.writer(f)
        csv_writer.writerow(data)


def remove_csv_extra_lines(csv_directory):
    global EVENTS_CSV

    n_rows_events = 0
    with open(EVENTS_CSV, 'r') as events_file:
        n_rows_events = len(events_file.readlines())

    for file in os.listdir(csv_directory):
        filepath = os.path.join(csv_directory, file)
        new_file_content = None
        with open(filepath, 'r') as metric_file:
            current_data = metric_file.readlines()
            lines_to_remove = len(current_data) - n_rows_events
            if lines_to_remove > 0:
                new_file_content = current_data[:-lines_to_remove]
            else:
                new_file_content = current_data

        with open(filepath, 'w+') as metric_file:
            for line in new_file_content:
                metric_file.write(line)


def process_script_parameters(args):
    if args.testing_time <= 0:
        raise ValueError('Testing time must be greater than 0')
    if args.interval <= 0:
        raise ValueError('Interval must be greater than 0')

    path_list = args.path.split(',')

    for path in path_list:
        if not (os.path.exists(path) and os.path.isdir(path)):
            raise ValueError('Path must be a directory')

    if args.syscheck_envets and args.logcollector_events:
        raise ValueError('Only one type of events can be generated at the same time')


def start_syslog_server(protocol, port, store_messages_filepath, debug):
    syslog_server = SyslogServer(protocol=protocol, port=port, store_messages_filepath=store_messages_filepath,
                                 debug=debug)
    syslog_server.start()

    return syslog_server


def get_alert_json_lines():
    lines_counter = 0
    with open(ALERTS_JSON, 'r') as fp:
        for lines_counter, line in enumerate(fp):
            pass
    return lines_counter


def write_csv_events_row(interval, epi, alerts_monitoring=True, syslog_monitoring=True, syslog_server=None):
    global COUNTER_INTERVAL
    global N_ALERTS_JSON

    COUNTER_INTERVAL += 1
    current_date = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')

    if syslog_monitoring and not syslog_server:
        raise ValueError('Syslog server must be defined')

    if syslog_monitoring:
        syslog_messages = reset_syslog_alerts(syslog_server)
        interval_csv = COUNTER_INTERVAL * interval

    if alerts_monitoring:
        lines_counter = get_alert_json_lines()
        new_alerts = lines_counter - N_ALERTS_JSON
        N_ALERTS_JSON = lines_counter

    if alerts_monitoring and syslog_monitoring:
        write_csv_file(EVENTS_CSV, [current_date, epi, interval_csv, syslog_messages, new_alerts])
    else:
        if alerts_monitoring:
            write_csv_file(EVENTS_CSV, [current_date, epi, interval_csv, new_alerts])
        if syslog_monitoring:
            write_csv_file(EVENTS_CSV, [current_date, epi, interval_csv, syslog_messages])


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


def events_monitoring(time_limit, epi, extra_interval, syslog_server, file_stress, interval):
    start_time = datetime.now().replace(microsecond=0)
    scheduler = sched.scheduler(time.time, time.sleep)
    iteration = 1
    n_iterations = time_limit // interval

    while iteration <= n_iterations:
        new_interval = (start_time + timedelta(seconds=interval*iteration)).timestamp()
        s.enterabs(new_interval, 0, write_csv_events_row, (interval, epi, syslog_server,))
        scheduler.run()
        iteration += 1

    # Stop alerts generation
    file_stress.stop()

    # Wait for extra interval to get the last messages
    for _ in range(extra_interval):
        time.sleep(interval)

        # Get syslog total messages received in the interval
        write_csv_events_row(interval, epi, syslog_server)


def create_footprint_csv_file(interval, data_unit):
    with open('footprint.csv', 'w+') as footprint_file:
        csv_writer = csv.writer(footprint_file, delimiter=',')
        file_content = {}

        for file in os.listdir(STATISTICS_PATH):
            if file.endswith('.csv'):
                with open(os.path.join(STATISTICS_PATH, file), 'r') as metric_file:
                    file_content[file] = metric_file.readlines()

        # seconds, wazuh-daemon, CPU(%), RSS(KB), VMS(KB), disk_read(B), disk_written(B), FD
        header = ['wazuh-daemon', 'seconds', 'CPU(%)', f'RSS({data_unit})', f'VMS({data_unit})',
                  f'disk_read({data_unit})', f'disk_written({data_unit})', 'FD']
        csv_writer.writerow(header)

        # Remove header
        n_lines = len(list(file_content.values())[0])
        for i in range(1, n_lines):
            seconds = i * interval
            for key in file_content.keys():
                line = file_content[key][i]
                row_values = line.split(',')
                daemon = row_values[0].replace('wazuh', 'ossec')
                cpu = row_values[4]
                rss = row_values[6]
                vmss = row_values[5]
                dis_read = row_values[13]
                disk_written = row_values[14]
                fd = row_values[10]
                row = [daemon, seconds, cpu, rss, vmss, dis_read, disk_written, fd]
                csv_writer.writerow(row)


def generate_charts(parameters):
    global DATA_UNIT

    # Mute annoying warnings
    warnings.filterwarnings('ignore')

    date_time = datetime.now().strftime("%Y%m%d%H%M%S")
    syslog_alerts_data = EVENTS_CSV

    # Plot basic charts
    if parameters.footprint_monitoring:
        plot_footprint(FOOTPRINT_CSV, f"{date_time}", DATA_UNIT)

    plot_alerts(syslog_alerts_data, parameters.syslog_monitoring, alerts_monitoring)


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    # General parameters
    arg_parser.add_argument('-t', '--testing-time', metavar='<testing-time>', type=int,
                            help='Testing time', required=True, default=None, dest='testing_time')

    arg_parser.add_argument('-i', '--interval', metavar='<interval>', type=int,
                            help='Set interval for data gathering', required=False, default=1, dest='interval')

    arg_parser.add_argument('-d', '--debug', metavar='<debug>', action='store_true', default=False, dest='debug')

    # Syslog server parameters
    arg_parser.add_argument('--syslog-server-monitoring', metavar='<syslog-server-monitoring>',
                            action='store_true', default=False, dest='debug')

    arg_parser.add_argument('--syslog-server-protocol', metavar='<protocol>', type=str,
                            help='Syslog server protocol', required=False, default='udp', dest='syslog_server_protocol')

    arg_parser.add_argument('--syslog-server-port', metavar='<syslog-server-port>', type=int,
                            help='Syslog Server port', required=False, default=514, dest='syslog_server_port')

    arg_parser.add_argument('--alerts-monitoring', metavar='<alerts-monitoring>', action='store_true', default=False,
                            dest='debug')

    arg_parser.add_argument('--footprint-monitoring', metavar='<footprint-monitoring>', action='store_true',
                            default=False, dest='debug')

    # Events parameters Syscheck
    arg_parser.add_argument('--syscheck-events', metavar='<syscheck-events>', action='store_true', default=False)

    arg_parser.add_argument('--syscheck-path', metavar='<syscheck-path>', type=str,
                            help='Path to file creation for syscheck events',
                            required=False, default=None, dest='syscheck_path')

    arg_parser.add_argument('--syscheck-epi-file-creation', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file creation event type', dest='epi_file_creation')

    arg_parser.add_argument('--syscheck-epi-file-update', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file update event type', dest='epi_file_update')

    arg_parser.add_argument('--syscheck-epi-file-delete', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file delete event type', dest='epi_file_delete')

    # Events parameters Logcollector
    arg_parser.add_argument('--logcollector-events', metavar='<syscheck-events>', action='store_true', default=False)

    arg_parser.add_argument('--logcollector-path', metavar='<logcollector-path>', type=str,
                            help='Path to file creation for syscheck events',
                            required=False, default=None, dest='logcollector_path')

    arg_parser.add_argument('--logcollector-epi', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file delete event type', dest='epi_file_delete')

    arg_parser.add_argument('--logcollector-event-type', metavar='<event-type>', type=str, default='syslog',
                            required=False, help='Event type', dest='event_type')

    arg_parser.add_argument('--logcollector-fixed-event-size', metavar='<fixed-event-size>', type=int, default=None,
                            required=False, help='Use fixed event size', dest='fixed_event_size')

    # arg_parser.add_argument('-f', '--filename-header', metavar='<filename>', type=str, default=None, required=False,
    #                         help='Filename header', dest='filename_header')

    # Graphics parameters
    arg_parser.add_argument('--generate-footprint-graphics', action='store_true',
                            default=False, dest='generate_graphics')

    return arg_parser.parse_args()


def main():
    global N_ALERTS_JSON
    global DATA_UNIT

    parameters = get_parameters()
    process_script_parameters(parameters)
    logger = init_logger(parameters.debug)

    logger.info("Counting preliminary alerts")
    count = 0
    with open(ALERTS_JSON, 'r') as fp:
        for count, line in enumerate(fp):
            pass
    N_ALERTS_JSON = count

    time_limit = time.time() + parameters.testing_time

    # Defined used event
    if parameters.logcollector_events:
        event = define_event(parameters)
        logger.debug(f"Defined logcollector event: {event}")

    # Init remote syslog server
    if parameters.syslog_server_monitoring:
        logger.info("Init remote syslog server")
        syslog_server = start_syslog_server(protocol=parameters.syslog_server_protocol,
                                            port=parameters.syslog_server_port,
                                            store_messages_filepath=None, debug=parameters.debug)

    # Clean previous results and create new csv file with expected header
    logger.info("Clean previous footprint csv data")
    clean_csv_results()

    # Get statistics of WAZUH_STATISTICS_PROCESS list
    if parameters.footprint_monitoring:
        logger.info("Init processes monitoring")
        monitors = init_processes_monitoring(parameters.interval)

    # Init file stress thread
    logger.info("Init file stress thread")

    if parameters.logcollector_events:
        epi_file_update = parameters.logcollector_epi
    else:
        epi_file_update = parameters.syscheck_epi_file_update

    file_stress_thread = start_file_stress(epi_file_creation=parameters.syscheck_epi_file_create,
                                           epi_file_update=epi_file_update,
                                           epi_file_delete=parameters.syscheck_epi_file_delete,
                                           interval=parameters.interval, path=parameters.path.split(','),
                                           debug=parameters.debug, event=event, add_counter_to_events=False)

    if parameters.syslog_server_monitoring or parameters.alerts_monitoring:
        if parameters.logcollector_monitoring:
            epi = parameters.logcollector_epi
        else:
            epi = parameters.syscheck_epi_file_create + parameters.syscheck_epi_file_update + \
                parameters.syscheck_epi_file_delete

        write_events_header(parameters.alerts_monitoring, parameters.syslog_server_monitoring)
        # Set initial values - Get syslog total messages received in the interval

        write_csv_events_row(parameters.interval, epi, syslog_server)
        # For each interval, get the total messages received in the interval and write it to the csv file
        events_monitoring(parameters.testing_time, epi, EXTRA_INTERVALS_TO_WAIT, syslog_server, file_stress_thread,
                          parameters.interval)
    else:
        logger.info(f"Waiting for testing time to finish: {parameters.testing_time} seconds")
        time.sleep(parameters.testing_time)

    # Stop monitors
    if parameters.footprint_monitoring:
        logger.info("Shutting down monitors")
        for monitor in monitors:
            monitor.shutdown()

    # Stop syslog server
    if parameters.syslog_server_monitoring:
        logger.info("Shutting down syslog server")
        syslog_server.shutdown()

    # Create a csv file with the footprint data
    if parameters.footprint_monitoring:
        logger.info("Creating footpring csv")
        create_footprint_csv_file(parameters.interval, DATA_UNIT)

    # Generating charts
    if parameters.generate_graphics:
        logger.info("Generating charts")
        generate_charts(parameters)


if __name__ == '__main__':
    main()
