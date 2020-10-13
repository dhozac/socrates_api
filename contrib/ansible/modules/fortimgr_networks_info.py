#!/usr/bin/env python
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortimanager.fortimanager import FortiManagerHandler
from ansible.module_utils.network.fortimanager.common import FMGBaseException
from ansible.module_utils.network.fortimanager.common import FMGRCommon
from ansible.module_utils.network.fortimanager.common import FMGRMethods
from ansible.module_utils.network.fortimanager.common import DEFAULT_RESULT_OBJ
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG
import json
import ipaddress


def get_interfaces(module, fmgr):
    '''
    return a filtered list of with the given device interfaces
    '''
    url = '/pm/config/device/{device_unique_name}/global/system/interface'.format(**module.paramgram)
    datagram = {
        'fields': ['name', 'vdom', 'vlanid', 'ip', 'type', 'dhcp-relay-service', 'dhcp-relay-ip', 'description'],
        'filter': [['status', '==', 1], '&&', ['ip', '!=', ['0.0.0.0', '0.0.0.0']]]
    }
    results = fmgr.process_request(url, datagram, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to get interfaces, fortimanager returned {0}'.format(results))
    return results[1]


def get_dynamic_interfaces(module, fmgr):
    results = DEFAULT_RESULT_OBJ
    url = '/pm/config/adom/{adom}/obj/dynamic/interface'.format(**module.paramgram)
    results = fmgr.process_request(url, {}, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to get interfaces, fortimanager returned {0}'.format(results))
    return results[1]


def main():
    module = AnsibleModule(
        argument_spec=dict(
            adom=dict(required=True, type='str'),
            device_unique_name=dict(required=True, type='str'),
            network_domain_name=dict(required=True, type='str'),
            vdom=dict(required=True, type='str')
        ),
        supports_check_mode=True
    )

    module.paramgram = {
        'adom': module.params['adom'],
        'device_unique_name': module.params['device_unique_name'],
    }
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = FMGRCommon()
    else:
        # fail with an un-helpful and error-masking generic response, thanks forti!
        module.fail_json(**FAIL_SOCKET_MSG)

    # only pick vlan interfaces with the correct vdom
    interfaces = [i for i in get_interfaces(module, fmgr) if module.params['vdom'] in i.get('vdom', []) and i['type'] == 'vlan']
    dyn_interfaces = get_dynamic_interfaces(module, fmgr)

    networks = []
    zones = {}
    for zone in dyn_interfaces:
        dynamic_maps = zone.get('dynamic_mapping', [])
        if not dynamic_maps:
            continue
        scope_id = (module.params['device_unique_name'], module.params['vdom'])
        for dm in dynamic_maps:
            if scope_id in [(s['name'], s['vdom']) for s in dm.get('_scope', [])]:
                local_intf = dm.get('local-intf', [])
                if isinstance(local_intf, str):
                    local_intf = [local_intf]

                for ifname in local_intf:
                    if not zones.get(module.params['vdom']):
                        zones[module.params['vdom']] = {}
                    zones[module.params['vdom']][ifname] = zone['name']

    for interface in interfaces:
        if 'vlanid' not in interface or interface['vlanid'] == 0 or interface['ip'][0] == '0.0.0.0':
            continue

        ip_interface_str = ipaddress.ip_interface('/'.join(interface['ip']))  # crappy py3/py2 compat fix, remove whenever py2 is gone
        ip_interface = ipaddress.ip_interface(u'{0}'.format(ip_interface_str))
        network_str = '{0}'.format(ip_interface.network.network_address)
        networks.append({
            'vrf': 0,
            'network': network_str,
            'length': ip_interface.network.prefixlen,
            'domains': {
                module.params['network_domain_name']: {
                    'vlan_id': interface['vlanid'],
                    'name': interface['name'],
                    'data': {
                        'zone': zones.get(interface['vdom'][0], {}).get(interface['name']),
                        'vdom': interface['vdom'][0],
                        'description': interface.get('description')
                    }
                }
            },
        })

    module.exit_json(msg='networks collected', changed=False, networks=networks)


if __name__ == '__main__':
    main()
