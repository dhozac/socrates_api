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
module: fmgr_interface
version_added: 2.9
notes:
  - null
author:
  - null
short_description: Add, update and remove vlan interfaces
description:
  - Add, update and remove vlan interfaces in fortimanager. Seemingly basic functions which are
    missing from the official fortinet provided Ansible modules
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
        'fields': ['name', 'vdom', 'vlanid', 'ip', 'type', 'dhcp-relay-service', 'dhcp-relay-ip', 'vrf', 'interface', 'description', 'alias', 'allowaccess'],
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


def remove_vlan_interface(module, fmgr):
    '''
    remove existing vlan interfaces matching given name, returns a dict with changed state
    and removed interfaces
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: dict containing 'changed' (bool), 'interfaces' (dict), 'interfaces_before' (dict)
    :rtype: dict
    '''
    rv = {'changed': False, 'interface': {}}
    url = '/pm/config/device/{device_unique_name}/global/system/interface/'.format(**module.params)
    interfaces = [i for i in get_interfaces(module, fmgr) if module.params['vdom'] in i.get('vdom', []) and i['type'] == 'vlan' and i['name'] == module.params['interface']]

    if not interfaces:
        return rv

    if len(interfaces) > 1 and not module.params['force']:
        module.fail_json(msg='found more than one vlan interface with name (set force: true to remove all interfaces): {0}, fortimanager returned: {1}'.format(module.params['interface'], interfaces))

    for interface in interfaces:
        interface_url = os.path.join(url, module.params['interface'])
        if not module.check_mode:
            results = fmgr.process_request(interface_url, interface, FMGRMethods.DELETE)
            if results[0] != 0:
                module.fail_json(msg='failed to delete interface {0}, fortimanager returned {1}'.format(module.params['interface'], results))
        rv['changed'] = True
        rv['interface'][module.params['interface']] = interface
    return rv


def update_vlan_interface(module, fmgr):
    '''
    update existing or create a vlan interface, returns a dict with changed state
    and interface description
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: dict containing 'changed' (bool), 'interfaces' (dict), 'interfaces_before' (dict)
    :rtype: dict
    '''
    rv = {'changed': False, 'interfaces': {}, 'interfaces_before': {}}
    url = '/pm/config/device/{device_unique_name}/global/system/interface'.format(**module.params)
    dhcp_service = 'disable'
    default_access = ['ping']
    ip = [module.params['address'], module.params['netmask']]
    vlan_id = module.params['vlan_id']
    dhcp_relay_ip = sorted(module.params['dhcp_servers'])
    vrf = module.params['vrf']
    description = module.params['description'][:64]  # description is limited to 64 bytes

    if module.params['dhcp_servers']:
        dhcp_service = 'enable'
    interfaces = [i for i in get_interfaces(module, fmgr) if module.params['vdom'] in i.get('vdom', []) and i['type'] == 'vlan']
    for iface in interfaces:
        rv['interfaces_before'][iface['name']] = copy.deepcopy(iface)

    datagram = {
        'ip': ip,
        'dhcp-relay-ip': dhcp_relay_ip,
        'dhcp-relay-service': dhcp_service,
        'description': description,
        'name': module.params['interface'],
        'vdom': [module.params['vdom']],
        'vlanid': vlan_id,
    }

    if len(default_access) == 1:
        default_access = default_access[0]

    if not module.params['interface'] in [i['name'] for i in interfaces]:
        fm_method = FMGRMethods.ADD
        datagram.update({'type': 'vlan', 'allowaccess': default_access})
    else:
        fm_method = FMGRMethods.UPDATE
        for interface in interfaces:
            if interface['name'] != module.params['interface']:
                continue
            if not module.params['phys_intf']:
                phys_intf = sorted(interface['interface'])
            else:
                phys_intf = [module.params['phys_intf']]
            if interface['dhcp-relay-ip']:
                interface['dhcp-relay-ip'] = [re.sub('[^0-9|\\.]*', '', x) for x in interface['dhcp-relay-ip']]

            # only set allowaccess on existing interface(s) if it's unset
            if not interface.get('allowaccess'):
                interface['allowaccess'] = None
                datagram['allowaccess'] = default_access
            else:
                default_access = interface['allowaccess']

            # check for difference, return if no difference
            if all([ip == sorted(interface['ip']),
                    dhcp_relay_ip == sorted(interface['dhcp-relay-ip']),
                    description == interface['description'],
                    vlan_id == interface['vlanid'],
                    vrf == interface['vrf'],
                    phys_intf == sorted(interface['interface']),
                    default_access == interface['allowaccess']]):
                rv['interface'] = interface
                return rv
            else:
                rv['changed'] = True
                break

    if module.params['phys_intf']:
        datagram.update({'interface': [module.params['phys_intf']]})

    if module.check_mode:
        # fabricate an interface for check_mode and return
        rv['changed'] = True
        ifname = module.params['interface']
        rv['interfaces'] = copy.deepcopy(rv['interfaces_before'])
        if ifname in rv['interfaces_before'].keys():
            rv['interfaces'][ifname].update(datagram)
        else:
            rv['interfaces'][ifname] = copy.deepcopy(interfaces[0])
            rv['interfaces'][ifname].update(datagram)
        return rv

    results = fmgr.process_request(url, datagram, fm_method)
    if results[0] != 0:
        module.fail_json(msg='failed to set/update interface, fortimanager returned {0}'.format(results))

    # read interfaces after update and fetch given interface by name
    updated_interfaces = [i for i in get_interfaces(module, fmgr) if module.params['vdom'] in i.get('vdom', []) and i['type'] == 'vlan']
    check_ifname = [i for i in updated_interfaces if i['name'] == module.params['interface']]

    if not check_ifname:
        module.fail_json(msg='interface {0} not found after add/update, fortimanager: {1}'.format(module.params['interface'], results))

    for iface in updated_interfaces:
        rv['interfaces'][iface['name']] = iface
    return rv


def add_interface_to_zone(module, fmgr):
    '''
    add interface to a zone (dynamic interface)
    returns dict with state change and zone (if any)
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: dict containing keys 'changed' (bool), zones (dict) and zones_before (dict)
    :rtype: dict
    '''
    rv = {'changed': False, 'zones': {}, 'zones_before': {}}
    url = '/pm/config/adom/{adom}/obj/dynamic/interface'.format(**module.paramgram)
    s_id = (module.params['device_unique_name'], module.params['vdom'])
    dyn_interfaces = [i for i in get_dynamic_interfaces(module, fmgr) if i['name'] == module.params['zone']]

    for zone in dyn_interfaces:
        dynamic_maps = zone.get('dynamic_mapping', [])
        if not dynamic_maps:
            module.fail_json(msg='zone {0} missing dynamic_mapping attribute {1}'.format(zone['name'], zone))

        scope_lookup = [(s['name'], s['vdom']) for d in dynamic_maps for s in d.get('_scope', [])]
        if s_id not in scope_lookup:
            continue

        dm_update = []
        for dm in dynamic_maps:
            if not dm.get('_scope'):
                dm_update.append(dm)
                continue

            if s_id in [(s['name'], s['vdom']) for s in dm.get('_scope', [])]:
                rv['zones_before'][zone['name']] = copy.deepcopy(zone)
                if module.params['interface'] in dm.get('local-intf', []):
                    rv['zones'][zone['name']] = copy.deepcopy(zone)
                    continue

                if not dm.get('local-intf'):
                    dm['local-intf'] = [module.params['interface']]
                    rv['changed'] = True

                if module.params['interface'] not in dm['local-intf']:
                    dm['local-intf'].append(module.params['interface'])
                    rv['changed'] = True
                dm_update.append(dm)

        zone['dynamic_mapping'] = dm_update
        rv['zones'][zone['name']] = copy.deepcopy(zone)

        if not module.check_mode and zone['dynamic_mapping']:
            results = fmgr.process_request(url, zone, FMGRMethods.UPDATE)
            if results[0] != 0:
                module.fail_json(msg='failed to add {0} to zone {1}, fortimanager returned: {2}'.format(module.params['interface'], module.params['zone'], results))

    if not module.check_mode and rv['changed']:
        # read dynamic interfaces after update and return updated zone
        updated_dyn_interfaces = [i for i in get_dynamic_interfaces(module, fmgr) if i['name'] == module.params['zone']]
        for z in updated_dyn_interfaces:
            rv['zones'][z['name']] = z
    return rv


def remove_interface_from_zone(module, fmgr):
    '''
    remove interface reference from all dynamic interfaces (zones)
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: dict containing keys 'changed' (bool), zones (dict) and zones_before (dict)
    :rtype: dict
    '''
    rv = {'changed': False, 'zones': {}, 'zones_before': {}}
    url = '/pm/config/adom/{adom}/obj/dynamic/interface'.format(**module.paramgram)
    s_id = (module.params['device_unique_name'], module.params['vdom'])
    dyn_interfaces = get_dynamic_interfaces(module, fmgr)

    for zone in dyn_interfaces:
        scopes = [(s['name'], s['vdom']) for d in zone.get('dynamic_mapping', []) for s in d.get('_scope', [])]
        if s_id not in scopes:
            continue

        updated_dm = []
        dm_changed = False
        for dm in zone.get('dynamic_mapping', []):
            if isinstance(dm['local-intf'], str) and module.params['interface'] == dm['local-intf']:
                rv['zones_before'][zone['name']] = copy.deepcopy(zone)
                dm['local-intf'] = None
                dm_changed = True
            if module.params['interface'] in dm['local-intf']:
                rv['zones_before'][zone['name']] = copy.deepcopy(zone)
                dm['local-intf'].remove(module.params['interface'])
                if not dm['local-intf']:
                    dm['local-intf'] = None  # fortimanager does not tolerate empty lists
                dm_changed = True
            updated_dm.append(dm)
        if dm_changed:
            zone['dynamic_mapping'] = updated_dm
            rv['zones'][zone['name']] = zone
            rv['changed'] = True
            if not module.check_mode:
                url = os.path.join(url, zone['name'])
                results = fmgr.process_request(url, zone, FMGRMethods.UPDATE)
                if results[0] != 0:
                    module.fail_json(msg='failed to remove interface {0} from zone: {1}, fortimanager returned: {2}, data sent {3}'.format(module.params['interface'], zone['name'], results, zone))
    return rv


def _interface_present(module, fmgr):
    '''
    update or add vlan interface through Fortimanager
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: changed (bool), diff (dict), msg (str)
    :rtype: tuple
    '''
    if (not module.params['address']
            or not module.params['netmask']
            or not module.params['vlan_id']):
        module.fail_json(msg='address, netmask and vlan_id required when state == present')

    changed = False
    diff = {'before': {}, 'after': {}}

    updated_interface = update_vlan_interface(module, fmgr)
    changed = updated_interface['changed']
    diff['before']['interfaces'] = updated_interface['interfaces_before']
    diff['after']['interfaces'] = updated_interface['interfaces']

    if module.params['zone']:
        zone_update = add_interface_to_zone(module, fmgr)
        if zone_update['changed']:
            changed = zone_update['changed']
            diff['before']['zones'] = zone_update['zones_before']
            diff['after']['zones'] = zone_update['zones']

    if not changed:
        return changed, diff, 'no change'

    return changed, diff, 'interface and/or zone updated'


def _interface_absent(module, fmgr):
    '''
    remove vlan interface from Fortimanager
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: changed (bool), diff (dict), msg (str)
    :rtype: tuple
    '''
    diff = {'before': {'interfaces': {}, 'zones': {}}, 'after': {'interfaces': {}, 'zones': {}}}
    changed = False
    interfaces = [i for i in get_interfaces(module, fmgr) if module.params['vdom'] in i.get('vdom', []) and i['type'] == 'vlan' and i['name'] == module.params['interface']]

    for interface in interfaces:
        rv_zones = remove_interface_from_zone(module, fmgr)
        if rv_zones['changed']:
            changed = True
            diff['before']['zones'] = rv_zones['zones_before']
            diff['after']['zones'] = rv_zones['zones']

    rv_interface = remove_vlan_interface(module, fmgr)
    if rv_interface['changed']:
        changed = True
        diff['before']['interfaces'] = rv_interface['interface']

    if not changed:
        return changed, diff, 'no change'

    return changed, diff, 'interface removed and/or zone(s) updated'


def main():
    module = AnsibleModule(
        argument_spec=dict(
            device_unique_name=dict(required=True, type='str'),
            vdom=dict(type='str', required=True),
            adom=dict(type='str', required=True),
            interface=dict(type='str', requred=True),
            state=dict(type='str', required=True, choices=['present', 'absent']),
            address=dict(type='str', required=False),
            netmask=dict(type='str', required=False),
            vlan_id=dict(type='int', required=False),
            phys_intf=dict(type='str', requried=False),
            zone=dict(type='str', required=False),
            dhcp_servers=dict(type='list', default=[]),
            vrf=dict(type='int', default=0),
            force=dict(type='bool', default=False),
            description=dict(type='str', required=False)
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

    if module.params['state'] == 'present':
        changed, diff, msg = _interface_present(module, fmgr)

    if module.params['state'] == 'absent':
        changed, diff, msg = _interface_absent(module, fmgr)

    module.exit_json(changed=changed, diff=diff, msg=msg)


if __name__ == '__main__':
    main()
