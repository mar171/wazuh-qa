'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.

           Created by Wazuh, Inc. <info@wazuh.com>.

           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

type: integration

brief: A Wazuh cluster is a group of Wazuh managers that work together to enhance the availability
       and scalability of the service. These tests will check the agent enrollment in a multi-server
       environment and how the agent manages the connections to the servers depending on their status.

components:
    - agentd

targets:
    - agent

daemons:
    - wazuh-agentd
    - wazuh-authd
    - wazuh-remoted

os_platform:
    - linux
    - windows


os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - Debian Buster
    - Red Hat 8
    - Ubuntu Focal
    - Ubuntu Bionic

references:
    - https://documentation.wazuh.com/current/user-manual/registering/index.html

tags:
    - enrollment
'''
import os
import pytest
from time import sleep

from wazuh_testing.tools import LOG_FILE_PATH
from wazuh_testing.tools.authd_sim import AuthdSimulator
from wazuh_testing.tools.configuration import load_wazuh_configurations
from wazuh_testing.tools.file import truncate_file
from wazuh_testing.tools.monitoring import QueueMonitor, FileMonitor
from wazuh_testing.tools.remoted_sim import RemotedSimulator
from wazuh_testing.tools.services import control_service
from wazuh_testing.agent import CLIENT_KEYS_PATH, SERVER_CERT_PATH, SERVER_KEY_PATH
from wazuh_testing.modules.agentd import event_monitor as evm
from wazuh_testing.tools.configuration import load_configuration_template, get_test_cases_data


# Marks
pytestmark = [pytest.mark.linux, pytest.mark.win32, pytest.mark.tier(level=0), pytest.mark.agent]

SERVER_ADDRESS = '127.0.0.1'
REMOTED_PORTS = [1514, 1516, 1517]
AUTHD_PORT = 1515
SERVER_HOSTS = ['testServer1', 'testServer2', 'testServer3']
tcase_timeout = 240

# Reference paths
TEST_DATA_PATH = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
CONFIGURATIONS_PATH = os.path.join(TEST_DATA_PATH, 'configuration_template')
TEST_CASES_PATH = os.path.join(TEST_DATA_PATH, 'test_cases')

# ------------------------------------------------ TEST_ACCEPTED_VALUES ------------------------------------------------
# Configuration and cases data
t1_configurations_path = os.path.join(CONFIGURATIONS_PATH, 'configuration_multi_server.yaml')
t1_cases_path = os.path.join(TEST_CASES_PATH, 'cases_multi_server.yaml')

# Accepted values test configurations (t1)
t1_configuration_parameters, t1_configuration_metadata, t1_case_ids = get_test_cases_data(t1_cases_path)
t1_configurations = load_configuration_template(t1_configurations_path, t1_configuration_parameters,
                                                t1_configuration_metadata)

local_internal_options = {'monitord.rotate_log': '0', 'windows.debug': '2'}

"""
How does this test work:

    - PROTOCOL: tcp/udp
    - CLEAN_KEYS: whatever start with an empty client.keys file or not
    - SIMULATOR_NUMBERS: Number of simulator to be instantiated, this should match wazuh_conf.yaml
    - SIMULATOR MODES: for each number of simulator will define a list of "stages"
    that defines the state that remoted simulator should have in that state
    Length of the stages should be the same for all simulators.
    Authd simulator will only accept one enrollment for stage
    - LOG_MONITOR_STR: (list of lists) Expected string to be monitored in all stages
"""

receiver_sockets, monitored_sockets = None, None  # Set in the fixtures

authd_server = AuthdSimulator(SERVER_ADDRESS, key_path=SERVER_KEY_PATH, cert_path=SERVER_CERT_PATH)
remoted_servers = []


@pytest.fixture(scope="module")
def add_hostnames(request):
    """Add to OS hosts file, names and IP's of test servers."""
    HOSTFILE_PATH = os.path.join(os.environ['SystemRoot'], 'system32', 'drivers', 'etc', 'hosts') \
        if os.sys.platform == 'win32' else '/etc/hosts'
    hostfile = None
    with open(HOSTFILE_PATH, "r") as f:
        hostfile = f.read()
    for server in SERVER_HOSTS:
        if server not in hostfile:
            with open(HOSTFILE_PATH, "a") as f:
                f.write(f'{SERVER_ADDRESS}  {server}\n')
    yield

    with open(HOSTFILE_PATH, "w") as f:
        f.write(hostfile)


@pytest.fixture(scope="function")
def configure_authd_server(request, metadata):
    """Initialize multiple simulated remoted connections.

    Args:
        metadata (fixture): Get configurations from the module.
    """
    global monitored_sockets
    monitored_sockets = QueueMonitor(authd_server.queue)
    authd_server.start()
    authd_server.set_mode('REJECT')
    global remoted_servers
    for i in range(0, metadata['simulator_number']):
        remoted_servers.append(RemotedSimulator(server_address=SERVER_ADDRESS, remoted_port=REMOTED_PORTS[i],
                                                protocol=metadata['protocol'],
                                                mode='CONTROLLED_ACK', client_keys=CLIENT_KEYS_PATH))
        # Set simulator mode for that stage
        if metadata['simulator_modes'][i][0] != 'CLOSE':
            remoted_servers[i].set_mode(metadata['simulator_modes'][i][0])

    yield
    # hearing on enrollment server
    for i in range(0, metadata['simulator_number']):
        remoted_servers[i].stop()
    remoted_servers = []
    authd_server.shutdown()


@pytest.fixture(scope="function")
def set_authd_id(request):
    """Set agent id to 101 in the authd simulated connection."""
    authd_server.agent_id = 101


@pytest.fixture(scope="function")
def clean_keys(request, metadata):
    """Clear the client.key file used by the simulated remoted connections.

    Args:
        metadata (fixture): Get configurations from the module.
    """
    if metadata.get('clean_keys', True):
        truncate_file(CLIENT_KEYS_PATH)
        sleep(1)
    else:
        with open(CLIENT_KEYS_PATH, 'w') as f:
            f.write("100 ubuntu-agent any TopSecret")
        sleep(1)


def restart_agentd():
    """Restart agentd daemon with debug mode active."""
    control_service('stop', daemon="wazuh-agentd")
    truncate_file(LOG_FILE_PATH)
    control_service('start', daemon="wazuh-agentd", debug_mode=True)


@pytest.mark.parametrize('configuration, metadata', zip(t1_configurations, t1_configuration_metadata), ids=t1_case_ids)
def test_agentd_multi_server(configuration, metadata, set_wazuh_configuration, configure_local_internal_options_module,
                            add_hostnames, configure_authd_server, set_authd_id, clean_keys,
                            restart_wazuh_daemon_function):
    '''
    description: Check the agent's enrollment and connection to a manager in a multi-server environment.
                 Initialize an environment with multiple simulated servers in which the agent is forced to enroll
                 under different test conditions, verifying the agent's behavior through its log files.

    wazuh_min_version: 4.2.0

    tier: 0

    parameters:
        - configuration:
            type: dict
            brief: Get configurations from the module.
        - metadata:
            type: dict
            brief: Get metadata from the module.
        - set_wazuh_configuration:
            type: fixture
            brief: Apply changes to the ossec.conf configuration.
        - configure_local_internal_options_module:
            type: fixture
            brief: Configure the local internal options file.
        - add_hostnames:
            type: fixture
            brief: Adds to the 'hosts' file the names and the IP addresses of the testing servers.
        - configure_authd_server:
            type: fixture
            brief: Initializes a simulated 'wazuh-authd' connection.
        - set_authd_id:
            type: fixture
            brief: Sets the agent id to '101' in the 'wazuh-authd' simulated connection.
        - clean_keys:
            type: fixture
            brief: Clears the 'client.keys' file used by the simulated remote connections.
        - restart_wazuh_daemon_function:
            type: fixture
            brief: Restart the wazuh service.

    assertions:
        - Agent without keys. Verify that all servers will refuse the connection to the 'wazuh-remoted' daemon
          but will accept enrollment. The agent should try to connect and enroll each of them.
        - Agent without keys. Verify that the first server only has enrollment available, and the third server
          only has the 'wazuh-remoted' daemon available. The agent should enroll in the first server and
          connect to the third one.
        - Agent without keys. Verify that the agent should enroll and connect to the first server, and then
          the first server will disconnect. The agent should connect to the second server with the same key.
        - Agent without keys. Verify that the agent should enroll and connect to the first server, and then
          the first server will disconnect. The agent should try to enroll in the first server again,
          and then after failure, move to the second server and connect.
        - Agent with keys. Verify that the agent should enroll and connect to the last server.
        - Agent with keys. Verify that the first server is available, but it disconnects, and the second and
          third servers are not responding. The agent on disconnection should try the second and third servers
          and go back finally to the first server.

    input_description: An external YAML file (configuration_multi_server.yaml) includes configuration settings for
                       the agent. Different test cases are found in the cases_multi_server.yaml file and include
                       parameters for the environment setup, the requests to be made, and the expected result.

    expected_output:
        - r'Requesting a key from server'
        - r'Valid key received'
        - r'Trying to connect to server'
        - r'Connected to enrollment service'
        - r'Received message'
        - r'Server responded. Releasing lock.'
        - r'Unable to connect to enrollment service at'

    tags:
        - simulator
        - ssl
        - keys
    '''
    log_monitor = FileMonitor(LOG_FILE_PATH)

    for stage in range(0, len(metadata['log_monitor_str'])):

        authd_server.set_mode(metadata['simulator_modes']['AUTHD'][stage])
        authd_server.clear()

        for i in range(0, metadata['simulator_number']):
            # Set simulator mode for that stage
            if metadata['simulator_modes'][i][stage] != 'CLOSE':
                remoted_servers[i].set_mode(metadata['simulator_modes'][i][stage])
            else:
                remoted_servers[i].stop()

        if stage == 0:
            # Restart at beginning of test
            restart_agentd()

        for index, log_str in enumerate(metadata['log_monitor_str'][stage]):
            error_message = f"Expected message '{log_str}' never arrived! Stage: {stage+1}, message number: {index+1}"
            log_str = log_str.replace('\"', '\'')
            callback_message = fr".*{log_str}.*"
            evm.check_agentd_event(file_monitor=log_monitor, callback=callback_message, error_message=error_message,
                                   timeout=tcase_timeout)

        for i in range(0, metadata['simulator_number']):
            # Clean after every stage
            if metadata['simulator_modes'][i][stage] == 'CLOSE':
                remoted_servers[i].start()

        authd_server.clear()
