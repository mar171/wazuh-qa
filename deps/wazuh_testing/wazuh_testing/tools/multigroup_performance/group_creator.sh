for i in {0..200}
do
    /var/ossec/bin/agent_groups -a -g "Group${i}" -q
    cat group_templates/agent.conf | tr GROUPNAME "Group${i}" > "/var/ossec/etc/shared/Group${i}/agent.conf"
    cp group_templates/cis_template.yaml "/var/ossec/etc/shared/Group${i}/Group${i}_template_yaml"
done