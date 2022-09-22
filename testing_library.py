from wazuh_testing.tools.system import WazuhEnvironment, HostManager

conf = ''
with open('/home/rebits/Wazuh/wazuh-qa/inventory.yaml') as f:
    conf = f.read()

we = WazuhEnvironment('inventory2.yaml')


address = "Example script"
configuration = {'wazuh-agent1': [{'section': 'client', 'elements': [{'server': {'elements':
                [{'address': {'value': f"{address}"}}]}}]}]}

we.change_configuration(configuration)