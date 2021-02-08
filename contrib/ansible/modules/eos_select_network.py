#!/usr/bin/env python
#  GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from ansible.module_utils.basic import AnsibleModule

ANSIBLE_METADATA = {
    'metadata_version': '0.1',
    'status': ['preview'],
    'supported_by': 'null'
}

DOCUMENTATION = '''
module: eos_select_network
version_added: 2.9
notes:
  - null
author:
  - null
short_description: select an appropriate vlan id based on arbitrary assumptions
description:
  - evaluates socrates network block, bonk prefix and existing eos_facts vlans and tries to select an appropriate vlan
'''


def main():
    module = AnsibleModule(
        argument_spec=dict(
            eos_vlans=dict(type='list', required=True),
            network=dict(type='dict', required=True),
            asset=dict(type='dict', required=True),
            strategy=dict(type='str', choices=['first', 'last'], default='first')
        ),
        supports_check_mode=True
    )
    switch_domain = module.params['asset']['switch']['domain']
    domains = module.params['network'].get('domains', {})

    if switch_domain not in domains.keys():
        module.fail_json(msg='switch domain: {0} not in network domains: {1}'.format(switch_domain, domains))

    network_name = domains[switch_domain]['name']
    check_vlan_id = [domains[k]['vlan_id'] for k in domains.keys() if domains[k].get('vlan_id', 0) != 0]
    if check_vlan_id:
        vlan_id = check_vlan_id[0]
        module.exit_json(msg='selected vlan_id {0}, previously set in other domain'.format(vlan_id), vlan_id=vlan_id, network_name=network_name)

    vlan_range = []
    for domain in domains:
        data = domains[domain].get('data')
        if not data:
            continue
        if 'vlan_min' not in data.keys() or 'vlan_max' not in data.keys():
            continue
        if vlan_range:
            module.fail_json(msg='network have more than one domain containing min_vlan, max_vlan keys: {0}'.format(domains))
        vlan_range = set([v for v in range(int(data['vlan_min']), int(data['vlan_max']) + 1)])

    if not vlan_range:
        module.fail_json(msg='no vlan_min/max from network.domains: {0}'.format(domains))
    eos_vlans = [d['vlan_id'] for d in module.params['eos_vlans']]
    valid_vlans = sorted(vlan_range.difference(eos_vlans))

    if module.params['strategy'] == 'first':
        vlan_id = valid_vlans[0]
    if module.params['strategy'] == 'last':
        vlan_id = valid_vlans[-1]

    module.exit_json(msg='vlan_id {0} selected'.format(vlan_id), vlan_id=vlan_id, network_name=network_name)


if __name__ == '__main__':
    main()
