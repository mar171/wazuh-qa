# Copyright (C) 2015-2022, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

import re
import json

from datetime import datetime
from wazuh_testing import logger, T_30, T_60, LOG_FILE_PATH
from wazuh_testing.tools.monitoring import generate_monitoring_callback, FileMonitor
from wazuh_testing.modules import fim

# Callback Messages
CB_FIM_PATH_CONVERTED = r".*fim_adjust_path.*Convert '(.*) to '(.*)' to process the FIM events."


# Callback functions
def callback_detect_event(line):
    """
    Detect an 'event' type FIM log.
    """
    msg = fim.CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        json_event = json.loads(match.group(1))
        if json_event['type'] == 'event':
            return json_event
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_end_scan(line):
    """ Callback that detects if a line in a log is an end of scheduled scan event
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    msg = fim.CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_end':
            return True
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_detect_scan_start(line):
    """ Callback that detects if a line in a log is the start of a scheduled scan or initial scan.
    Args:
        line (String): string line to be checked by callback in FileMonitor.
    """
    msg = fim.CB_DETECT_FIM_EVENT
    match = re.match(msg, line)
    if not match:
        return None

    try:
        if json.loads(match.group(1))['type'] == 'scan_start':
            return True
    except (json.JSONDecodeError, AttributeError, KeyError) as e:
        logger.warning(f"Couldn't load a log line into json object. Reason {e}")


def callback_connection_message(line):
    match = re.match(fim.CB_AGENT_CONNECT, line)
    if match:
        return True


def callback_detect_integrity_control_event(line):
    match = re.match(fim.CB_INTEGRITY_CONTROL_MESSAGE, line)
    if match:
        return json.loads(match.group(1))
    return None


def callback_integrity_message(line):
    if callback_detect_integrity_control_event(line):
        match = re.match(r"(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2}).*({.*?})$", line)
        if match:
            return datetime.strptime(match.group(1), '%Y/%m/%d %H:%M:%S'), json.dumps(match.group(2))


def callback_detect_registry_integrity_clear_event(line):
    event = callback_detect_integrity_control_event(line)
    if event and event['component'] == 'fim_registry' and event['type'] == 'integrity_clear':
        return True
    return None


def callback_disk_quota_limit_reached(line):
    match = re.match(fim.CB_FILE_EXCEEDS_DISK_QUOTA, line)

    if match:
        return match.group(2)


def callback_detect_file_added_event(line):
    """ Callback that detects if a line in a log is a file added event.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)

    if json_event is not None:
        if json_event['data']['type'] == 'added':
            return json_event

    return None


def callback_detect_file_modified_event(line):
    """ Callback that detects if a line in a log is a file modified event.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)

    if json_event is not None:
        if json_event['data']['type'] == 'modified':
            return json_event

    return None


def callback_detect_file_deleted_event(line):
    """ Callback that detects if a line in a log is a file deleted event.

    Args:
        line (String): string line to be checked by callback in FileMonitor.

    Returns:
        returns JSON string from log.
    """
    json_event = callback_detect_event(line)

    if json_event is not None:
        if json_event['data']['type'] == 'deleted':
            return json_event

    return None


# Event checkers
def check_fim_event(file_monitor=None, callback='', error_message=None, update_position=True,
                    timeout=T_60, accum_results=1, file_to_monitor=LOG_FILE_PATH):
    """Check if a analysisd event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        accum_results (int): Accumulation of matches.
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
                    error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=generate_monitoring_callback(callback), error_message=error_message)


def detect_initial_scan(file_monitor):
    """Detect initial scan when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=T_60, callback=callback_detect_end_scan,
                       error_message=fim.ERR_MSG_SCHEDULED_SCAN_ENDED)


def detect_initial_scan_start(file_monitor):
    """Detect initial scan start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=T_60, callback=callback_detect_scan_start,
                       error_message=fim.ERR_MSG_SCHEDULED_SCAN_STARTED)


def detect_realtime_start(file_monitor):
    """Detect realtime engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=T_60, callback=generate_monitoring_callback(fim.CB_FOLDERS_MONITORED_REALTIME),
                       error_message=fim.ERR_MSG_FOLDERS_MONITORED_REALTIME)


def detect_whodata_start(file_monitor):
    """Detect whodata engine start when restarting Wazuh.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
    """
    file_monitor.start(timeout=T_60, callback=generate_monitoring_callback(fim.CB_REALTIME_WHODATA_ENGINE_STARTED),
                       error_message=fim.ERR_MSG_WHODATA_ENGINE_EVENT)


def detect_windows_sacl_configured(file_monitor, file='.*'):
    """Detects when windows permision checks have been configured for a given file.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
        file: The path of the file that will be monitored
    """

    pattern = fr".*win_whodata.*The SACL of '({file})' will be configured"

    file_monitor.start(timeout=T_60, callback=generate_monitoring_callback(pattern),
                       error_message=fim.ERR_MSG_SACL_CONFIGURED_EVENT)


def detect_windows_whodata_mode_change(file_monitor, file='.*'):
    """Detects whe monitoring for a file changes from whodata to real-time.

    Args:
        file_monitor (FileMonitor): file log monitor to detect events
        file: The path of the file that will be monitored
    """

    pattern = fr".*set_whodata_mode_changes.*The '({file})' directory starts to be monitored in real-time mode."

    file_monitor.start(timeout=T_60, callback=generate_monitoring_callback(pattern),
                       error_message=fim.ERR_MSG_WHDATA_REALTIME_MODE_CHANGE_EVENT)
