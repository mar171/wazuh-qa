"""
copyright: Copyright (C) 2015-2021, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: Check that when FIM is activated, and the agent is running, the agent and manager are synchronization when
a change is performed in a monitored folder.
tier: 0
modules:
    - fim
components:
    - manager
    - agent
path: tests/system/test_fim/test_fim_synchronization/test_files_cud.py
daemons:
    - wazuh-syscheckd
os_platform:
    - linux
os_version:
    - Arch Linux
    - Amazon Linux 2
    - Amazon Linux 1
    - CentOS 8
    - CentOS 7
    - CentOS 6
    - Ubuntu Focal
    - Ubuntu Bionic
    - Ubuntu Xenial
    - Ubuntu Trusty
    - Debian Buster
    - Debian Stretch
    - Debian Jessie
    - Debian Wheezy
    - Red Hat 8
    - Red Hat 7
    - Red Hat 6
references:
    - https://github.com/wazuh/wazuh-qa/issues/2389
tags:
    - fim_basic_usage
"""

import os

import pytest
from wazuh_testing.tools.monitoring import HostMonitor
from wazuh_testing.tools.system import HostManager, clean_environment
from wazuh_testing.tools import WAZUH_LOGS_PATH
from system.test_fim import create_folder_file, wait_for_fim_scan_end

# Hosts
testinfra_hosts = ["wazuh-manager", "wazuh-agent1"]

# inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
#                               'provisioning', 'one_manager_agent', 'inventory.yml')
# host_manager = HostManager(inventory_path)
local_path = os.path.dirname(os.path.abspath(__file__))
messages_path = [os.path.join(local_path, 'data/messages.yml'),
                 os.path.join(local_path, 'data/delete_message.yml'),
                 os.path.join(local_path, 'data/wait_fim_scan.yml')]
tmp_path = os.path.join(local_path, 'tmp')
scheduled_mode = 'testdir1'


@pytest.mark.parametrize('case', ['add'])
@pytest.mark.parametrize('folder_path', ['testdir1'])
def test_file_cud(inventory, folder_path, case):
    host_manager = HostManager(inventory)

    # Restart Wazuh agent
    host_manager.control_service(host='wazuh-agent1', service='wazuh', state="restarted")
