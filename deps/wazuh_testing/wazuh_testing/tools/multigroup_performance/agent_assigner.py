import requests
import json
from requests.auth import HTTPBasicAuth


api_request_file = 'cluster_requets.json'
host = 'localhost'
port = '55000'
protocol = 'https'
wazuh_cred = HTTPBasicAuth('wazuh', 'wazuh')
list_of_api_request = None


def get_api_token():
    return requests.get(f"{protocol}://{host}:{port}/security/user/authenticate", auth=wazuh_cred, verify=False)

def set_agents_to_group(agent_id, group):
    headers = {
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {token}'
          }
    requests.put(f"{protocol}://{host}:{port}/agents/{agent_id}/group/{group}", verify=False, headers=headers)

with open(api_request_file) as requests_data:
  list_of_api_request = json.loads(requests_data.read())


token = json.loads(get_api_token().content.decode())['data']['token']

for i in range(600):
    id_formatted = f"{i:03d}"
    set_agents_to_group(id_formatted, f"Group{i}")
    set_agents_to_group( id_formatted,f"Group{(i+1)%200}")
    set_agents_to_group( id_formatted,f"Group{(i+2)%200}")
    set_agents_to_group(id_formatted, f"Group{(i+3)%200}")
    set_agents_to_group( id_formatted,f"Group{(i+4)%200}")
    set_agents_to_group(id_formatted, f"Group{(i+5)%200}")
    set_agents_to_group(id_formatted, f"Group{(i+6)%200}")
    set_agents_to_group(id_formatted, f"Group{(i+7)%200}")
    set_agents_to_group(id_formatted, f"Group{(i+8)%200}")
    set_agents_to_group(id_formatted, f"Group{(i+9)%200}")
    set_agents_to_group(id_formatted, f"Group{(i+10)%200}")
