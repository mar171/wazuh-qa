import os
import sys
import argparse
import logging
import time
import threading
from datetime import datetime
from enum import Enum
from wazuh_testing.tools.file_stress import FileStress

common_logger_handler = logging.StreamHandler(sys.stdout)
common_logger_handler.setFormatter(logging.Formatter("%(asctime)s — %(levelname)s — %(message)s"))


def get_parameters():
    arg_parser = argparse.ArgumentParser()

    arg_parser.add_argument('-t', '--testing-time', metavar='<testing-time>', type=int, required=True,
                            default='30', help='Testing time interval', dest='duration')

    arg_parser.add_argument('-p', '--path', metavar='<path>', type=str, default=None, required=True,
                            help='Path to perform event creation', dest='path')

    arg_parser.add_argument('--epi-file-creation', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file creation event type', dest='epi_file_creation')

    arg_parser.add_argument('--epi-file-update', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file update event type', dest='epi_file_update')

    arg_parser.add_argument('--epi-file-delete', metavar='<path>', type=int, default=0, required=False,
                            help='EPS of the file delete event type', dest='epi_file_delete')

    arg_parser.add_argument('-f', '--filename-header', metavar='<filename>', type=str, default=None, required=False,
                            help='Filename header', dest='filename_header')

    arg_parser.add_argument('-i', '--interval', metavar='<interval>', type=int, default=1, required=False,
                            help='Interval', dest='interval')

    args = arg_parser.parse_args()
    return args


def __main__():
    args = get_parameters()

    time_limit = time.time() + args.duration
    file_stress = FileStress(args.path, False)

    server_thread = threading.Thread(target=file_stress.start_file_stress, args=(args.epi_file_creation,
                                                                          args.epi_file_update,
                                                                          args.epi_file_delete,
                                                                          "Testing-Event",
                                                                          args.interval,))

    server_thread.start()

    while time.time() < time_limit:
        time.sleep(1)

    file_stress.stop()


if __name__ == '__main__':
    __main__()
