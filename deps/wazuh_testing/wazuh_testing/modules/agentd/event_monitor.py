import re

from wazuh_testing import T_30
from wazuh_testing.modules.agentd import AGENTD_PREFIX
from wazuh_testing.tools.monitoring import FileMonitor
from wazuh_testing.tools import LOG_FILE_PATH


def make_agentd_callback(pattern, prefix=AGENTD_PREFIX, escape=False):
    """Create a callback function from a text pattern.

    It already contains the analsisd prefix.

    Args:
        pattern (str): String to match on the log.
        prefix (str): regular expression used as a prefix before the pattern.
        escape (bool): Flag to escape special characters in the pattern

    Returns:
        lambda: function that returns if there's a match in the file

    Examples:
        >>> callback_message = make_agentd_callback("Trying to connect to server")
    """
    if escape:
        pattern = re.escape(pattern)
    else:
        pattern = r'\s+'.join(pattern.split())
    regex = re.compile(r'{}{}'.format(prefix, pattern))

    return lambda line: regex.match(line) is not None


def check_agentd_event(file_monitor=None, callback='', error_message=None, update_position=True,
                       timeout=T_30, prefix=AGENTD_PREFIX, accum_results=1, file_to_monitor=LOG_FILE_PATH,
                       escape=False):
    """Check if a agentd event occurs

    Args:
        file_monitor (FileMonitor): FileMonitor object to monitor the file content.
        callback (str): log regex to check in Wazuh log
        error_message (str): error message to show in case of expected event does not occur
        update_position (boolean): filter configuration parameter to search in Wazuh log
        timeout (str): timeout to check the event in Wazuh log
        prefix (str): log pattern regex
        accum_results (int): Accumulation of matches.
        escape (bool): Flag to escape special characters in the pattern
    """
    file_monitor = FileMonitor(file_to_monitor) if file_monitor is None else file_monitor
    error_message = f"Could not find this event in {file_to_monitor}: {callback}" if error_message is None else \
        error_message

    file_monitor.start(timeout=timeout, update_position=update_position, accum_results=accum_results,
                       callback=make_agentd_callback(callback, prefix, escape), error_message=error_message)
