import argparse
import os
import sys
from tempfile import gettempdir

from wazuh_testing.qa_ctl import QACTL_LOGGER
from wazuh_testing.qa_ctl.configuration.config_generator import QACTLConfigGenerator
from wazuh_testing.qa_ctl.provisioning import local_actions
from wazuh_testing.tools import file, github_checks
from wazuh_testing.tools.exceptions import QAValueError
from wazuh_testing.tools.github_api_requests import WAZUH_QA_REPO
from wazuh_testing.tools.logging import Logging
from wazuh_testing.tools.time import get_current_timestamp
from wazuh_testing.tools.s3_package import get_production_package_url, get_last_production_package_url
from wazuh_testing.qa_ctl.provisioning.ansible import playbook_generator
from wazuh_testing.qa_ctl.configuration.config_instance import ConfigInstance

TMP_FILES = os.path.join(gettempdir(), 'e2e_osquery_integration')
WAZUH_QA_FILES = os.path.join(TMP_FILES, 'wazuh-qa')
CHECK_FILES_TEST_PATH = os.path.join(WAZUH_QA_FILES, 'tests', 'system', 'e2e_osquery_integration')


logger = Logging(QACTL_LOGGER)
test_build_files = []
user_command = 'ping -c 4 www.google.com'


def get_parameters():
    """
    Returns:
        argparse.Namespace: Object with the user parameters.
    """
    parser = argparse.ArgumentParser()

    parser.add_argument('--os', '-o', type=str, action='store', required=False, dest='os_system',
                        choices=['centos_7', 'centos_8'], default='centos_8')

    parser.add_argument('--version', '-v', type=str, action='store', required=False, dest='wazuh_version',
                        help='Wazuh installation and tests version.')

    parser.add_argument('--debug', '-d', action='count', default=0, help='Run in debug mode. You can increase the debug'
                                                                         ' level with more [-d+]')

    parser.add_argument('--persistent', '-p', action='store_true',
                        help='Persistent instance mode. Do not destroy the instances once the process has finished.')

    parser.add_argument('--qa-branch', type=str, action='store', required=False, dest='qa_branch', default='master',
                        help='Set a custom wazuh-qa branch to download and run the tests files')

    parser.add_argument('--output-file-path', type=str, action='store', required=False, dest='output_file_path',
                        help='Path to store all test results')

    arguments = parser.parse_args()

    return arguments


def set_environment(parameters):
    """Prepare the local environment for the test run.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.

    """
    set_logger(parameters)

    # Download wazuh-qa repository to launch the check-files test files.
    local_actions.download_local_wazuh_qa_repository(branch=parameters.qa_branch, path=TMP_FILES)
    test_build_files.append(WAZUH_QA_FILES)

    # Create output file if it has been specified and it does not exist
    if parameters.output_file_path:
        file.recursive_directory_creation(parameters.output_file_path)


def set_logger(parameters):
    """Set the test logging.

    Args:
        parameters (argparse.Namespace): Object with the user parameters.
    """
    level = 'DEBUG' if parameters.debug >= 1 else 'INFO'
    logger.set_level(level)

    # Disable traceback if it is not run in DEBUG mode
    if level != 'DEBUG':
        sys.tracebacklimit = 0


def validate_parameters(parameters):
    """Validate input script parameters.

    Raises:
        QAValueError: If a script parameters has a invalid value.
    """
    def validate_deployment_info_data(data):
        """Check that all deployment data required parameters has been specified"""
        required_data = ['ansible_connection', 'ansible_user', 'ansible_port', 'ansible_python_interpreter', 'host',
                         'system']
        for key_data in required_data:
            if key_data not in data.keys():
                return False

        # Check for password data
        if 'ansible_password' not in data.keys() and 'ansible_ssh_private_key_file' not in data.keys():
            return False

        return True

    logger.info('Validating input parameters')

    # Check if QA branch exists
    if not github_checks.branch_exists(parameters.qa_branch, repository=WAZUH_QA_REPO):
        raise QAValueError(f"{parameters.qa_branch} branch does not exist in Wazuh QA repository.",
                           logger.error, QACTL_LOGGER)

    # Check version parameter
    if parameters.wazuh_version and len((parameters.wazuh_version).split('.')) != 3:
        raise QAValueError(f"Version parameter has to be in format x.y.z. You entered {parameters.wazuh_version}",
                           logger.error, QACTL_LOGGER)

    # Check if Wazuh has the specified version
    if parameters.wazuh_version and not github_checks.version_is_released(parameters.wazuh_version):
        raise QAValueError(f"The wazuh {parameters.wazuh_version} version has not been released. Enter a right "
                           'version.', logger.error, QACTL_LOGGER)

    # Check the deployment-info parameter
    if parameters.deployment_info:
        # Validate the file parameter
        if not os.path.isfile(parameters.deployment_info) or not os.path.exists(parameters.deployment_info):
            raise QAValueError('The specified deployment-info file does not exist.', logger.error, QACTL_LOGGER)

        # Read parameter file format
        if not file.validate_yaml_file(parameters.deployment_info):
            raise QAValueError(f"The deployment-info {parameters.deployment_info} is not in YAML format, or it has "
                               'wrong syntax', logger.error, QACTL_LOGGER)
        deployment_data = file.read_yaml(parameters.deployment_info)

        # Validate the data content
        for item in deployment_data:
            if not validate_deployment_info_data(item):
                raise QAValueError('Some necessary field is missing in the deployment-info file. The necessary one '
                                   'are as follows: [ansible_connection, ansible_user, ansible_port, '
                                   'ansible_python_interpreter, host, system] and (ansible_password | '
                                   'ansible_ssh_private_key_file)')

    logger.info('Input parameters validation has passed successfully')

def generate_qa_ctl_configuration(parameters, playbooks_path, qa_ctl_config_generator):
    """Generate the qa-ctl configuration according to the script parameters and write it into a file.
    Args:
        parameters (argparse.Namespace): Object with the user parameters.
        playbook_path (list(str)): List with the playbooks path to run with qa-ctl
        qa_ctl_config_generator (QACTLConfigGenerator): qa-ctl config generator object.
    Returns:
        str: Configuration file path where the qa-ctl configuration has been saved.
    """
    logger.info('Generating qa-ctl configuration')
    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    config_file_path = os.path.join(TMP_FILES, f"e2e_osquery_integration_{current_timestamp}.yaml")
    os_system = parameters.os_system
    # Add deployment section for local instances
    instance_name = f"e2e_osquery_integration_{os_system}_{current_timestamp}"
    instance = ConfigInstance(instance_name, os_system)
    # Generate deployment configuration
    deployment_configuration = qa_ctl_config_generator.get_deployment_configuration([instance])
    # Generate tasks configuration data
    tasks_configuration = qa_ctl_config_generator.get_tasks_configuration(playbooks_path, instances=[instance])
    # Generate qa-ctl configuration file
    qa_ctl_configuration = {**deployment_configuration, **tasks_configuration}
    file.write_yaml_file(config_file_path, qa_ctl_configuration)
    test_build_files.append(config_file_path)
    logger.info(f"The qa-ctl configuration has been created successfully in {config_file_path}")
    return config_file_path

def generate_test_playbooks(parameters):

    playbooks_info = {}
    manager_package = get_last_production_package_url("manager", parameters.os_system)
    agent_package = get_last_production_package_url("agent", parameters.os_system)
    manager_package_name = os.path.split(manager_package)[1]
    agent_package_name = os.path.split(agent_package)[1]
    expected_output = 'Active: active (running)'
    check_localfile_command = 'grep -Pzo " +(?s)<localfile>\n +<log_format>osquery.+?(?=localfile)localfile>" /var/ossec/etc/ossec.conf'
    os_platform = 'linux'
    package_destination = '/temp'

    manager_install_playbook_parameters = {
        'wazuh_target': 'manager',
        'package_name': manager_package_name,
        'package_destination': package_destination,
        'os_system': parameters.os_system,
        'os_platform': os_platform
    }

    agent_install_playbook_parameters = {
        'wazuh_target': 'agent',
        'package_name': agent_package_name,
        'package_destination': package_destination,
        'os_system': parameters.os_system,
        'os_platform': os_platform
    }

    run_osquery_integration_parameters = {
        'commands': [osquery_command],
        'playbook_parameters': {
            'become': True
        }
    }

    playbooks_info.update({'manager_install_playbook_parameters' : playbook_generator.install_wazuh(**manager_install_playbook_parameters)})
    playbooks_info.update({'agent_install_playbook_parameters': playbook_generator.install_wazuh(**agent_install_playbook_parameters)})
    playbooks_info.update({'run_osquery_integration': playbook_generator.run_linux_commands(**run_osquery_integration_parameters)})

    return(playbooks_info)


def main():
    """Run the check-files test according to the script parameters."""
    parameters = get_parameters()
    qa_ctl_config_generator = QACTLConfigGenerator()
    current_timestamp = str(get_current_timestamp()).replace('.', '_')
    test_output_path = parameters.output_file_path if parameters.output_file_path else \
        os.path.join(TMP_FILES, f"e2e_osquery_integration_result_{current_timestamp}")

    # Set logging and Download QA files
    set_environment(parameters)

    # Validate script parameters
    if not parameters.no_validation:
        validate_parameters(parameters)

    playbooks_info = generate_test_playbooks(parameters)
    test_build_files.extend([playbook_path for playbook_path in playbooks_info.values()])
    qa_ctl_config_file_path = generate_qa_ctl_configuration(parameters, playbooks_info, qa_ctl_config_generator)
    extra_args = '-p' if parameters.persistent else '' 
    local_actions.run_local_command_printing_output(f'qa-ctl -c {qa_ctl_config_file_path} {extra_args}'
    '--no-validation-logging')
    # Clean test build files
    if parameters and not parameters.persistent:
        logger.info('Deleting all test artifacts files of this build (config files, playbooks, data results ...)')
        for file_to_remove in test_build_files:
            file.remove_file(file_to_remove)


if __name__ == '__main__':
    main()