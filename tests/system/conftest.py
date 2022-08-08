import pytest

from system import clean_cluster_logs, remove_cluster_agents


# Clean cluster logs
@pytest.fixture(scope='function')
def clean_environment(test_infra_agents, test_infra_managers, host_manager):

    clean_cluster_logs(test_infra_agents + test_infra_managers, host_manager)

    yield
    # Remove the agent once the test has finished
    remove_cluster_agents(test_infra_managers[0], test_infra_agents, host_manager)


def pytest_addoption(parser):
    import os
    inventory_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                      'provisioning', 'one_manager_agent', 'inventory.yml')
    parser.addoption(
        '--inventory',
        action='store',
        default=[inventory_path],
        help='Add inventory path'
    )


def pytest_generate_tests(metafunc):
    option_value = metafunc.config.option.name
    if 'inventory' in metafunc.fixturenames and option_value is not None:
        metafunc.parametrize("name", [option_value])

