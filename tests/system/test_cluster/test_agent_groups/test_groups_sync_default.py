'''
copyright: Copyright (C) 2015-2022, Wazuh Inc.
           Created by Wazuh, Inc. <info@wazuh.com>.
           This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
type: system
brief: These tests check that when a cluster has a series of agents registered and connecting one after the other,
       and it is unable to do a Sync, that after a expected time, a Sync is forced and the DB is Synched.
tier: 2
modules:
    - cluster
components:
    - manager
    - agent
daemons:
    - wazuh-db
    - wazuh-clusterd
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
    - https://github.com/wazuh/wazuh-qa/issues/2514
tags:
    - wazuh-db
'''
import os

import pytest
from wazuh_testing.tools.system.wazuh_environment import WazuhEnvironment


test_time = 20
sync_delay = 40

@pytest.fixture(scope='module')
def get_environment_handler(request):
    inventory_path = request.config.getoption('--inventory-path')

    if not inventory_path:
        raise ValueError('Inventory not specified')

    return WazuhEnvironment(inventory_path)


@pytest.fixture(scope='function')
def delete_agent(request, get_environment_handler):
    agent_list = get_environment_handler.get_agents()
    # Stop all agents
    get_environment_handler.stop_all_agents()
    # Remove agents


        # Remove agent in manager
        # Remove data in agent, client.keys and id

    pass


@pytest.fixture(scope='function')
def clean_environment(request, get_environment_handler):
    # Truncatelog?
    pass

# Tests
def test_agent_groups_sync_default(get_environment_handler, clean_environment, delete_agents, restore_environment):
    '''
    description: Check that after a long time when the manager has been unable to synchronize de databases, because
    new agents are being continually added, database synchronization is forced and the expected information is in
    all nodes after the expected sync time. For this, an agent is restarted and connects to the agent every roughly 10
    seconds, during 400 seconds. After all agents have been registered, it is checked that the wazuhDB has been synched
    in all the cluster nodes.
    wazuh_min_version: 4.4.0
    parameters:
        - agent_host:
            type: List
            brief: Name of the host where the agent will register in each case.
        - clean_enviroment:
            type: Fixture
            brief: Reset the wazuh log files at the start of the test. Remove all registered agents from master.
        - test_infra_managers
            type: List
            brief: List of manager hosts in enviroment.
        - test_infra_agents
            type: List
            brief: List of agent hosts in enviroment.
        - host_manager
            type: HostManager object
            brief: Handles connection the enviroment's hosts.
    assertions:
        - Verify that after registering and after starting the agent, the agent has the default group is assigned.
        - Assert that all Agents have been restarted
    expected_output:
        - The 'Agent_name' with ID 'Agent_id' belongs to groups: 'group_name'.
    '''
    agent_list = get_environment_handler.get_agents()
    # host_manager = get_host_manager
    # print("Init test properly")

    # # Register agents in manager
    # agent_data = []

    # for index, agent in enumerate(test_infra_agents):
    #     print(f"Registering agent {agent}")
    #     data = register_agent(agent, agent_host, host_manager)
    #     agent_data.append(data)

    # # get the time before all the process is started
    # end_time = time.time() + test_time
    # active_agent = 0
    # while time.time() < end_time:
    #     if active_agent < agents_in_cluster:
    #         print(f"Starting agent {active_agent}")
    #         host_manager.run_command(test_infra_agents[active_agent], f'{WAZUH_PATH}/bin/wazuh-control start')
    #         active_agent = active_agent + 1

    # assert active_agent == agents_in_cluster, f"Unable to restart all agents in the expected time. \
    #                                             Agents restarted: {active_agent}"

    # time.sleep(sync_delay)

    # # Check that agent has the expected group assigned in all nodes
    # print("Check agent group")
    # for agent in agent_data:
    #     print(f"Check agent group for agent {agent}")
    #     check_agent_groups(agent[1], "default", host_manager)
