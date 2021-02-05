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
module: fortimgr_remove_all_policies
version_added: 2.9
notes:
  - null
author:
  - null
short_description: remove or update all policies associated to given zone
description:
  - this alters your system, perhaps in bad ways.
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


def get_policy_packages(module, fmgr):
    url = '/pm/config/adom/{adom}/_package/status'.format(**module.params)
    results = fmgr.process_request(url, {}, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to fetch packages, fortimanager returned: {0}'.format(results))
    return results[1]


def get_associated_policies(module, fmgr, pkg):
    url = '/pm/config/adom/{0}/pkg/{1}/firewall/policy'.format(module.params['adom'], pkg)
    datagram = {
        'filter': [
            ['srcintf', 'contain', module.params['zone']],
            '||',
            ['dstintf', 'contain', module.params['zone']]
        ],
        'fields': ['policyid', 'uuid', 'name', 'srcintf', 'dstintf', '_last_session', 'srcaddr', 'dstaddr']
    }
    results = fmgr.process_request(url, datagram, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to fetch policies for {0}, fortimanager returned: {1}'.format(module.params['zone'], results))

    return results[1]


def rm_update_policy(module, fmgr, policy, pkg):
    '''
    remove policy if srcintf or dstintf only contain
    given zone, otherwise remove zone from list(s) and
    update the policy.
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :param policy: dict with policy
    :param pkg: package name as string
    :return: uuid and modified policy (updated or empty when deleted)
    :rtype: dict
    '''
    url = '/pm/config/adom/{0}/pkg/{1}/firewall/policy/{2}'.format(module.params['adom'], pkg, policy['policyid'])
    zone = module.params['zone']

    if zone in policy['srcintf']:
        policy['srcintf'].remove(zone)

    if zone in policy['dstintf']:
        policy['dstintf'].remove(zone)

    if not policy['srcintf'] or not policy['dstintf']:
        fm_method = FMGRMethods.DELETE
        rv = {}
    else:
        fm_method = FMGRMethods.UPDATE
        rv = policy

    del policy['obj seq']
    del policy['_last_session']

    if not module.check_mode:
        results = fmgr.process_request(url, policy, fm_method)
        if results[0] != 0:
            module.fail_json(msg='failed to remove interface from policy {0}, fortimanager returned: {1}'.format(policy['policyid'], results), rv=rv)

    return rv


def remove_associated_policies(module, fmgr):
    rv = {'changed': False, 'before': {}, 'after': {}}
    device = module.params['device_unique_name']
    vdom = module.params['vdom']
    pkg = [p for p in get_policy_packages(module, fmgr) if (device, vdom) == (p['dev'], p['vdom'])]
    if not pkg:
        module.fail_json(msg=pkg)
        return rv
    if len(pkg) > 1:
        module.fail_json(msg='more than one policy package?! {0}'.format(pkg))
    pkg = pkg[0]

    policies = get_associated_policies(module, fmgr, pkg['pkg'])
    for policy in policies:
        rv['before'][policy['uuid']] = copy.deepcopy(policy)
        rv['after'][policy['uuid']] = rm_update_policy(module, fmgr, policy, pkg['pkg'])
        if rv['before'][policy['uuid']] != rv['after'][policy['uuid']]:
            rv['changed'] = True

    return rv


def validate_zone(module, fmgr):
    rv = {'valid': False, 'msg': ''}
    zone = [z for z in get_dynamic_interfaces(module, fmgr) if z['name'] == module.params['zone']]
    if not zone:
        rv['msg'] = 'zone {0} does not exist'.format(module.params['zone'])
        return rv

    if len(zone) > 1:
        module.fail_json(msg='multiple zones with name {0} found, something is wrong'.format(module.params['zone']))

    zone = zone[0]
    scope_id = (module.params['device_unique_name'], module.params['vdom'])
    if not zone.get('dynamic_mapping'):
        rv['msg'] = 'zone {0} missing dynamic_mapping attribute: {1}'.format(module.params['zone'], zone)
        return rv

    if scope_id not in [(s['name'], s['vdom']) for d in zone.get('dynamic_mapping', []) for s in d.get('_scope', [])]:
        rv['msg'] = 'scope {0},{1} not found in zone {2}: {3}'.format(scope_id[0], scope_id[1], module.params['zone'], zone)
        return rv

    for dm in zone['dynamic_mapping']:
        if scope_id not in [(s['name'], s['vdom']) for s in dm['_scope']]:
            continue
        if isinstance(dm['local-intf'], str):
            if dm['local-intf'] != module.params['interface']:
                rv['msg'] = 'interface {0} does not match the interface {1} in zone: {2}'.format(module.params['interface'], dm['local-intf'], zone)
                return rv

            dm['local-intf'] = [
                dm['local-intf']
            ]
        if len(dm['local-intf']) > 1:
            rv['msg'] = 'zone {0} contain multiple interfaces: {1}'.format(module.params['zone'], dm['local-intf'])
            return rv

        if module.params['zone'] not in dm['local-intf']:
            rv['msg'] = 'interface {0} not in zone: {1}'.format(module.params['interface'], zone)
            return rv
        else:
            rv['valid'] = True
            return rv


def main():
    module = AnsibleModule(
        argument_spec=dict(
            device_unique_name=dict(required=True, type='str'),
            vdom=dict(type='str', required=True),
            adom=dict(type='str', required=True),
            interface=dict(type='str', requred=True),
            zone=dict(type='str', required=False),
            vrf=dict(type='int', default=0)
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
        # fail with an un-helpful and error-masking generic response
        module.fail_json(**FAIL_SOCKET_MSG)

    zone = validate_zone(module, fmgr)
    if not zone['valid']:
        if not zone['msg']:
            zone['msg'] = 'invalid zone'
        module.exit_json(msg=zone['msg'], changed=False, skipped=True)

    outd = remove_associated_policies(module, fmgr)
    msg = 'no change'
    if outd['changed']:
        msg = 'associated policies removed/updated'
    diff = {'before': outd['before'], 'after': outd['after']}

    module.exit_json(changed=outd['changed'], diff=diff, msg=msg)


if __name__ == '__main__':
    main()
