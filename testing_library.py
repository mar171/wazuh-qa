from wazuh_testing.tools.system import WazuhEnvironment, HostManager

"""
Should support:
- Change configuration (agent.conf, api.yaml and ossec.conf)
- Monitor logs (ossec.log, cluster.log, api.log, etc ... )
- Register agents (API and agent_authd)
- Start manager/agents
- Remove agent
- Clear environment  -> Remove agents, truncate logs
"""


conf = ''
with open('/home/rebits/Wazuh/wazuh-qa/inventory.yaml') as f:
    conf = f.read()

we = WazuhEnvironment('inventory2.yaml')


address = "Patatoide"
configuration = {'wazuh-agent1': [{'section': 'client', 'elements': [{'server': {'elements':
                [{'address': {'value': f"{address}"}}]}}]}]}

#we.change_configuration(configuration)

config_local_int = {'wazuh-agent1': {'remoted.debug': 2}}

#we.change_local_internal_option(config_local_int)

we.search_pattern('wazuh-agent1', ".*Analyzing file:.*", 30)
