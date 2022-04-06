from wazuh_testing.tools.file import validate_json_file, read_json_file
from wazuh_testing.tools.exceptions import QAValueError


def validate_metadata(data):
    n_agents = [data_set['metadata']['n_agents'] for data_set in data]
    n_workers = [data_set['metadata']['n_workers'] for data_set in data]
    i = 0
    while i < len(data) and i+1 != len(data):
        if n_agents[i] != n_agents[i+1]:
            raise QAValueError('The number of agents is different.')
        if n_workers[i] != n_workers[i+1]:
            raise QAValueError('The number of workers is different.')
        i += 1


def get_reports_data(reports):
    data = []

    for report in reports:
        if validate_json_file(report):
            file_data = read_json_file(report)
            data.append(file_data)
    validate_metadata(data)

    return data


def test_footprint_comparision(first_report, second_report):
    reports = [first_report, second_report]
    data = get_reports_data(reports)
