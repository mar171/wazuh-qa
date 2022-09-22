import pytest

from system import clean_cluster_logs, remove_cluster_agents


# Clean cluster logs
@pytest.fixture(scope='function')
def clean_environment(test_infra_agents, test_infra_managers, get_host_manager):
    host_manager = get_host_manager

    clean_cluster_logs(test_infra_agents + test_infra_managers, host_manager)

    yield
    # Remove the agent once the test has finished
    remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)




def pytest_addoption(parser):
    parser.addoption(
        '--inventory-path',
        action='store',
        metavar='INVENTORY_PATH',
        default=None,
        type=str,
        help='Inventory path',
    )
