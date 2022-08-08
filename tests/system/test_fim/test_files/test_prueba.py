import os

import pytest

# Hosts
testinfra_hosts = ["wazuh-manager", "wazuh-agent1"]

inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                              'provisioning', 'one_manager_agent', 'inventory.yml')


@pytest.mark.parametrize('case', ['add', 'modify', 'delete'])
@pytest.mark.parametrize('folder_path', ['testdir1', 'testdir2', 'testdir3'])
def test_file_cud(folder_path, case):
    print(inventory_path)