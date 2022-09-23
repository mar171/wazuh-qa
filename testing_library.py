from wazuh_testing.tools.system.host_manager import HostManager
from wazuh_testing.tools.system.wazuh_environment import WazuhEnvironment
from wazuh_testing.tools.monitoring import HostMonitor
import time

from deps.wazuh_testing.wazuh_testing.api import make_api_call, get_token_login_api, get_api_details_dict
import testinfra

conf = ''
with open('/home/rebits/Wazuh/wazuh-qa/inventory2.yaml') as f:
    conf = f.read()


we = WazuhEnvironment('inventory2.yaml')


configuration = {'agent1': {'ossec.conf': [{'section': 'client', 'elements': [{'server': {'elements':
                [{'address': {'value': f"Ultimate"}}]}}]}]}, 'wazuh-manager1': {'testing:agent.conf': [{'section': 'client', 'elements': [{'server': {'elements':
                [{'address': {'value': f"testing_error_handling_2"}}]}}]}]}}

we.configure_environment(configuration)






# we.configure_environment(configuration)

# # config_local_int = {'wazuh-agent1': {'remoted.debug': 2}}

# #we.change_local_internal_option(config_local_int)






#we.restart_agents()
#print(we.get_host('agent1').check_output('hostname'))


# inventory_path = 'inventory2.yaml'

# print(we.get_managers())
# print(we.get_agents())
# print(we.get_hosts('.*real.*'))


# we.change_registered_manager_address(['wazuh-agent1', 'wazuh-agent2'], we.get_host_ip('wazuh-manager1'))


# backup = {
#     'wazuh-agent1': ['ossec.conf']
# }

# backup_restore = we.backup_configuration(backup)
# we.change_registered_manager_address(['wazuh-agent1'], 'TOMATOIDE')
# print("Edit temporal file")
# time.sleep(15)

# we.restore_backup_configuration(backup_restore)

#we.restart_environment()



# print(testinfra.get_host(f"ansible://wazuh-agent1?ansible_inventory={inventory_path}").ansible.get_variables())


address = "Patatoide444"
agent_conf = [{
    'section': 'localfile',
    'elements':  [
        {
           'log_format' : 'syslog',
           'location' : '/tmp/example',
        }
    ]
}]





# configuration = {'wazuh-manager1': {'ossec.conf': [{'section': 'client', 'elements': [{'server': {'elements':
#                 [{'address': {'value': f"{address}"}}]}}]}],
#                                   'agent.conf': [{'section': 'client', 'elements': [{'server': {'elements':
#                 [{'address': {'value': f"{address}"}}]}}]}]}}




# we.configure_environment(configuration)

# # config_local_int = {'wazuh-agent1': {'remoted.debug': 2}}

# #we.change_local_internal_option(config_local_int)



# search_pattern = {
#    'wazuh-agent2' : [
#        {
#            'regex': ".*FINAL99.*",
#            "path": "/var/ossec/logs/ossec.log",
#            "timeout": 5
#        },
#    ],
# }

# a = we.fast_log_multisearch(search_pattern)
# print(a)
# if(a):
#     print("WEEEEE")
# #a = we.log_search(search_pattern)

# # for key,value in a.items():
# #     print(f"{key}     {value}")

# # start = time.time()
# # we.multipattern_search(search_pattern)
# # end = time.time()

# # print(end - start)

# # time.sleep(10)
