import pytest
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.firefox.options import Options
from time import sleep
from os.path import join
import yaml
import csv


# Dashboard credentials (replace when Jenkins automation)
username = "admin"
password = "+msfC1RkdQTrx?HnTDZIpkvb5K+2ZI?."
dashboard_ip = 'https://192.168.56.3'
policies_path = 'wazuh/ruleset/sca/windows'
csv_download_path = '/home/qa/Downloads'

supported_os = {
    'windows10': {
        'policies': [
            {
                'name': 'CIS Benchmark for Windows 10 Enterprise (Release 21H2)',
                'policy_name': 'cis_win10_enterprise'
            },
            {
                'name': 'Benchmark for Windows audit',
                'policy_name': 'sca_win_audit'
            }
        ]
    }
}


def selenium_login(driver):
    driver.get(dashboard_ip)
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "img[src='/ui/Wazuh-Logo.svg"))
    )

    driver.find_element(By.CSS_SELECTOR, "input[data-test-subj='user-name']").send_keys(username)
    driver.find_element(By.CSS_SELECTOR, "input[data-test-subj='password']").send_keys(password)
    driver.find_element(By.CSS_SELECTOR, "button[type='submit']").click()
    WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.CSS_SELECTOR, "img[src='/plugins/wazuh/assets/images/themes/light/logo.svg'"))
    )
    sleep(3)


def selenium_sca_policies_agent(driver, agent_name):
    element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//*[text()='Security configuration assessment']"))
    )
    element.click()
    sleep(3)
    element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//*[text()='Select agent']"))
    )
    element.click()

    sleep(3)
    print(agent_name)
    element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, f'//*[text()="{agent_name}"]'))
    )
    element.click()
    sleep(2)


def selenium_sca_policy(driver, policy_name):
    # CIS Benchmark for Windows 10 Enterprise (Release 21H2)
    element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, f"//div//td//span[text()='{policy_name}']"))
    )
    element.click()


def selenium_sca_policy_export(driver):
    element = WebDriverWait(driver, 10).until(
        EC.presence_of_element_located((By.XPATH, "//*[text()='Export formatted']"))
    )
    element.click()
    sleep(10)


@pytest.fixture(scope='function')
def get_exported_sca(policy):
    options = Options()
    options.accept_untrusted_certs = True
    driver = webdriver.Firefox(options=options)

    selenium_login(driver)
    selenium_sca_policies_agent(driver, 'windows')
    print(policy['name'])
    selenium_sca_policy(driver, policy['name'])
    selenium_sca_policy_export(driver)
    driver.close()
    yield f"{policy['name']}"


@pytest.mark.parametrize("policy", supported_os['windows10']['policies'])
def test_example(policy, get_exported_sca):
    policy_map = {}
    csv_dashboard_sca = []
    with open(join(policies_path, policy['policy_name'] + '.yml')) as yaml_policy:
        policy_map = yaml.safe_load(yaml_policy)

    with open(join(csv_download_path, policy['policy_name'] + '.csv')) as csv_policy:
        csv_dashboard_sca = list(csv.reader(csv_policy))

    index_id = -1
    index_rationale = -1
    index_description = -1
    index_remediation = -1
    index_title = -1
    index_status = -1
    index_result = -1
    index_policy_name = -1

    for index, field in enumerate(csv_dashboard_sca[0]):
        if field == 'ID':
            index_id = index
        if field == 'Title':
            index_title = index
        if field == 'Status':
            index_status = index
        if field == 'Remediation':
            index_remediation = index
        if field == 'Result':
            index_result = index
        if field == 'Description':
            index_description = index
        if field == 'Rationale':
            index_rationale = index
        if field == 'Policy ID':
            index_policy_name = index
    csv_index = 1
    for check in policy_map['checks']:
        id_status = int(check['id']) == int(csv_dashboard_sca[csv_index][index_id])
        status_status = True
        if csv_dashboard_sca[csv_index][index_status] == '':
            result_status = csv_dashboard_sca[csv_index][index_result] in ['passed', 'failed']
        elif csv_dashboard_sca[csv_index][index_status] != 'Not applicable':
            status_status = False

        policy_id_status = policy['policy_name'] == csv_dashboard_sca[csv_index][index_policy_name]
        description_status = check['description'] == csv_dashboard_sca[csv_index][index_description]
        rationale_status = check['rationale'] == csv_dashboard_sca[csv_index][index_rationale]
        remediation_status = check['remediation'] == csv_dashboard_sca[csv_index][index_remediation]
        title_status = check['title'] == csv_dashboard_sca[csv_index][index_title]

        csv_index += 1

        assert id_status and status_status and policy_id_status and remediation_status \
            and description_status and rationale_status and title_status and result_status
