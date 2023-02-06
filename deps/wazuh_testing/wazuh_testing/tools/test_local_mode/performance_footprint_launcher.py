
import time
import signal
import os
import json
import shutil
import subprocess
import argparse

from wazuh_testing.tools import monitoring

scripts_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'deps/wazuh_testing/wazuh_testing/scripts')
analysis_script = os.path.join(scripts_path, 'footprint.py')
analysis_script = 'footprint.py'

MANAGER_CONFIGURATION_PATH = '/var/ossec/etc/ossec.conf'

# PYTHON_PATH = '/opt/freeware/bin/python3'

PYTHON_PATH = 'python3'
SYSLOG_SERVER_PROTOCOL = 'udp'
SYSLOG_SERVER_PORT = '1099'
EVENTS_CSV = 'events.csv'
FOOTPRINT_CSV = 'footprint.csv'


def wait_until_scan_is_over(file_monitor):
    file_monitor.start(timeout=600, callback=monitoring.make_callback("Ending syscheck scan", prefix=".*"))

def enable_syscheck(configuration, directory, interval):
    new_configuration = configuration
    new_configuration += '<ossec_config>\n' + '<syscheck>\n' + \
                         '<disabled>no</disabled>\n' + \
                         f'<directories check_all="yes">{directory}</directories>\n' + \
                         f'<scan_on_start>yes</scan_on_start>\n' + \
                         f'<frequency>{interval}</frequency>\n' + \
                         '</syscheck>\n' + '</ossec_config>\n'
    return new_configuration


def enable_logcollector(configuration, directory, protocol):
    def get_logcollector_files_path(directory):
        for dirpath, _, filenames in os.walk(directory):
            for f in filenames:
                yield os.path.abspath(os.path.join(dirpath, f))

    new_configuration = configuration
    for log_file in get_logcollector_files_path(directory):
        new_configuration += '<ossec_config>\n' + '<localfile>\n' + \
                         f'<log_format>{protocol}</log_format>\n' + \
                         f'<location>{log_file}</location>\n' + \
                         f'</localfile>' + \
                         '</ossec_config>\n'
    return new_configuration


def get_configuration():
    with open(MANAGER_CONFIGURATION_PATH) as f:
        return f.read()


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', '--test-cases', metavar='<test-cases-file>', type=str,
                            help='Test case JSON file', required=True, default=None, dest='tests_cases_file')

    args = arg_parser.parse_args()

    test_cases = {}
    if os.path.exists(args.tests_cases_file):
        with open(args.tests_cases_file) as f:
            test_cases = json.load(f)

    return test_cases


def main():

    # Truncate logs
    with open('/var/ossec/logs/ossec.log', 'w') as log_file:
        log_file.write('')

    tests_cases = get_parameters()
    original_configuration = get_configuration()

    for case in tests_cases['test_cases']:
        file_monitor = monitoring.FileMonitor('/var/ossec/logs/ossec.log')
        results_dir = case['name']

        # Create results directory
        shutil.rmtree(case['name'], ignore_errors=True)
        # if not os.path.exists(results_dir):
        os.mkdir(case['name'])
        # else:

        # Create testing directories
        if not os.path.isdir('/tmp/testing-logcollector'):
            os.mkdir('/tmp/testing-logcollector')
        if not os.path.isdir('/tmp/testing-syscheck'):
            os.mkdir('/tmp/testing-syscheck')

        # Gather test case parameters
        module = case.get('module', 'logcollector')
        event_size = case.get('events_size', 500)
        events_update = case.get('events_update', 0)
        events_create = case.get('events_create', 0)
        events_delete = case.get('events_delete', 0)
        syscheck_mode = case.get('syscheck_mode', 'realtime')
        interval = case.get('interval', 1)
        files = case.get('files', 1)
        test_time = case.get('time', 60)

        # Create files
        if module == 'logcollector' or module == 'syscheck' and (events_update > events_create):
            for index in range(files):
                os.system(f'touch /tmp/testing-{module}/file{index}')

        new_configuration = ''
        # Configure the manager
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plain_configuration.conf')) \
             as configuration_file:

            new_configuration = configuration_file.read()
            if module == 'syscheck':
                new_configuration = enable_syscheck(new_configuration, '/tmp/testing-syscheck', 60)
            else:
                new_configuration = enable_logcollector(new_configuration, '/tmp/testing-logcollector', 'syslog')

        with open(MANAGER_CONFIGURATION_PATH, 'w') as f:
            f.write(new_configuration)


        # Restart the manager
        restart_command = '/var/ossec/bin/ossec-control restart'
        process = subprocess.Popen(restart_command.split(), stdout=subprocess.PIPE)
        output, error = process.communicate()

        time.sleep(60)

        if module == 'syscheck':
            os.system('echo "Starting syscheck"')
            # Wait until first scan is over
            wait_until_scan_is_over(file_monitor)

        if module == 'logcollector' or (module=='syscheck' and syscheck_mode == 'realtime'):
            proc = None
            if module == 'logcollector':
                proc = subprocess.Popen([PYTHON_PATH, analysis_script, "-i", str(interval), "-t", str(test_time), '--logcollector-monitoring', '--logcollector-path', '/tmp/testing-logcollector', '--logcollector-epi', str(events_update), '--syslog-server-monitoring', '--syslog-server-port', str(1099), '--syslog-server-protocol', 'udp', '--logcollector-fixed-event-size', str(event_size), '--generate-footprint-graphics', '--alerts-monitoring', '--syslog-server-monitoring', '--footprint-monitoring', '--report-path', results_dir],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            elif module == 'syscheck':
                proc = subprocess.Popen([PYTHON_PATH, analysis_script, "-i", str(interval), "-t", str(test_time), '--syscheck-monitoring', '--syscheck-path', '/tmp/testing-syscheck', '--syscheck-epi-file-create', str(events_creation), '--syscheck-epi-file-update', str(events_update), '--syscheck-epi-file-delete', str(events_delete), '--syslog-server-monitoring', '--syslog-server-port', str(1099), '--syslog-server-protocol', 'udp',  '--generate-footprint-graphics', '--alerts-monitoring', '--syslog-server-monitoring', '--footprint-monitoring', '--report-path', results_dir],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            output, error = proc.communicate()
            if error:
                print("Something go wrong")
                print(f"Error: {error}")
            time.sleep(int(test_time) + 30)
        else:
            proc = subprocess.Popen([PYTHON_PATH, analysis_script, "-i", str(interval), "-t", str(2), '--syscheck-monitoring', '--syscheck-path', '/tmp/testing-syscheck', '--syscheck-epi-file-create', str(events_create), '--syscheck-epi-file-update', str(events_update), '--syscheck-epi-file-delete', str(events_delete),],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            output, error = proc.communicate()
            print("Launch monitor")

            proc2 = subprocess.Popen([PYTHON_PATH, analysis_script, "-i", str(interval), "-t", str(40000),'--syslog-server-monitoring', '--syslog-server-port', str(1099), '--syslog-server-protocol', 'udp',  '--generate-footprint-graphics', '--syscheck-path', '/tmp/testing-syscheck', '--alerts-monitoring', '--syslog-server-monitoring', '--footprint-monitoring', '--report-path', results_dir],
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            wait_until_scan_is_over(file_monitor)
            time.sleep(60)

            print("Killed process")
            os.kill(proc2.pid, signal.SIGINT)

        # shutil.copy(EVENTS_CSV, os.path.join(results_dir, EVENTS_CSV))
        # shutil.copy(FOOTPRINT_CSV, os.path.join(results_dir, FOOTPRINT_CSV))
        shutil.copy('/var/ossec/logs/ossec.log', os.path.join(results_dir, 'ossec.log'))

        # os.remove(EVENTS_CSV)
        # os.remove(FOOTPRINT_CSV)

        with open('/var/ossec/logs/ossec.log', 'w') as log_file:
            log_file.write('')

        shutil.rmtree(path='/tmp/testing-logcollector', ignore_errors=True)
        shutil.rmtree(path='/tmp/testing-logcollector', ignore_errors=True)

    with open(MANAGER_CONFIGURATION_PATH, 'w') as f:
        f.write(original_configuration)


if __name__ == '__main__':
    main()
