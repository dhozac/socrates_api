#!/usr/bin/env python
from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortimanager.fortimanager import FortiManagerHandler
from ansible.module_utils.network.fortimanager.common import FMGBaseException
from ansible.module_utils.network.fortimanager.common import FMGRCommon
from ansible.module_utils.network.fortimanager.common import FMGRMethods
from ansible.module_utils.network.fortimanager.common import DEFAULT_RESULT_OBJ
from ansible.module_utils.network.fortimanager.common import FAIL_SOCKET_MSG
import copy
import ipaddress
import json
import os
import re

__metaclass__ = type

ANSIBLE_METADATA = {
    'metadata_version': '0.1',
    'status': ['preview'],
    'supported_by': 'null'
}

DOCUMENTATION = '''
module: fmgr_select_network
version_added: 2.9
notes:
  - null
author:
  - null
short_description: select an appropriate network id based on arbitrary assumptions
description:
  - Get appropriate network id(s) from Fortimanager for Socrates
'''


def get_interfaces(module, fmgr):
    '''
    return a filtered list of with the given device interfaces
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: list of dictionaries containing interface information
    :rtype: list
    '''
    url = '/pm/config/device/{device_unique_name}/global/system/interface'.format(**module.paramgram)

    datagram = {
        'fields': ['name', 'vdom', 'vlanid', 'ip', 'type', 'dhcp-relay-service', 'dhcp-relay-ip', 'vrf', 'interface', 'description'],
        'filter': [['status', '==', 1], '&&', ['ip', '!=', ['0.0.0.0', '0.0.0.0']]]
    }
    results = fmgr.process_request(url, datagram, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to get interfaces, fortimanager returned {0}'.format(results))
    return results[1]


def get_dynamic_interfaces(module, fmgr):
    '''
    get a list of all dynamic interfaces from given adom (set in module parameters)
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: list of dictionaries containing dynamic interface information
    :rtype: list
    '''
    results = DEFAULT_RESULT_OBJ
    url = '/pm/config/adom/{adom}/obj/dynamic/interface'.format(**module.paramgram)
    results = fmgr.process_request(url, {}, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to get interfaces, fortimanager returned {0}'.format(results))
    return results[1]


def get_network_ids(module, fmgr):
    '''
    Shuffle together some info
    '''
    network_ids = {}
    module_network = module.params['network']
    cidr = u'{network}/{length}'.format(**module_network)  # py2/py3 compat fix, remove when py2 is gone
    network = ipaddress.ip_network(cidr)
    scope_id = (module.params['device_unique_name'], module.params['vdom'])
    dyn_interfaces = get_dynamic_interfaces(module, fmgr)
    interfaces = [i for i in get_interfaces(module, fmgr) if i['type'] == 'vlan' and module.params['vdom'] in i['vdom'] and module.params['vrf'] == i['vrf']]
    existing_vlan_ids = [i['vlanid'] for i in interfaces if i.get('vlanid')]

    vlan_id_from_network = sorted(set([x.get('vlan_id') for x in module_network['domains'].values() if x.get('vlan_id') and x.get('vlan_id') != 0]))
    if len(vlan_id_from_network) != 1:
        module.fail_json(msg='no valid ids or multiple vlan ids ({0}) in network asset: {1}'.format(vlan_id_from_network, module_network))
    vlan_id_from_network = vlan_id_from_network[0]

    network_ids['netmask'] = str(network.netmask)
    for interface in interfaces:
        if interface['ip'][0] == module_network['ipam']['gateway']:
            if interface['vlanid'] != vlan_id_from_network:
                module.fail_json('fortimanager interface vlan id {0} and socrates network vlan id {1} differ'.format(interface['vlanid'], vlan_id_from_network))
            network_ids['vlan_id'] = vlan_id_from_network
            network_ids['interface'] = interface['name']

    if network_ids.get('interface'):
        for zone in dyn_interfaces:
            if not zone.get('dynamic_mapping'):
                continue
            for dm in zone['dynamic_mapping']:
                if scope_id not in [(s['name'], s['vdom']) for s in dm.get('_scope', [])]:
                    continue
                if network_ids['interface'] in dm.get('local-intf', []):
                    network_ids['zone'] = zone['name']

    if not network_ids.get('interface'):
        interface_name = 'v{0}_{1}'.format(vlan_id_from_network, module.params['vdom'])
        if vlan_id_from_network in existing_vlan_ids:
            module.fail_json(msg='vlan id {0} exists in forti, check  network asset: {1}'.format(vlan_id_from_network, module_network))
        if len(interface_name) > 15:
            module.fail_json('interface name {0} above 15 characters (forti limit)'.format(interface_name))
        network_ids['interface'] = interface_name

    if not network_ids.get('zone'):
        network_ids['zone'] = network_ids['interface']

    if module.params['hostname']:
        network_ids['hostname'] = '{0}.{1}'.format(network_ids['interface'].replace('_', '-'), module.params['hostname'])

    if not network_ids.get('vlan_id'):
        network_ids['vlan_id'] = vlan_id_from_network

    return network_ids


def main():
    module = AnsibleModule(
        argument_spec=dict(
            device_unique_name=dict(required=True, type='str'),
            vdom=dict(type='str', required=True),
            adom=dict(type='str', required=True),
            vrf=dict(type='int', default=0),
            network=dict(type='dict', required=True),
            hostname=dict(type='str', required=False),
        ),
        supports_check_mode=True
    )

    # fortimanager module expects the module parameters duplicated
    # in a dict called paramgram, reasons unknown!
    module.paramgram = {
        'adom': module.params['adom'],
        'device_unique_name': module.params['device_unique_name'],
    }
    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = FMGRCommon()
    else:
        # fail with an un-helpful and error-masking generic response
        module.fail_json(**FAIL_SOCKET_MSG)

    network_ids = get_network_ids(module, fmgr)
    module.exit_json(msg='network id selected', network_ids=network_ids)


if __name__ == '__main__':
    main()
