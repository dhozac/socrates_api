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
module: fmgr_zone
version_added: 2.9
notes:
  - null
author:
  - null
short_description: Add and remove zones in fortimanager
description:
  - Add, and remove zones (dynamic interfaces) in fortimanager. Seemingly basic functions which are missing from the official fortinet provided Ansible modules. This module is dumb as a rock and does exactly 1 comparison before creating/deleting a zone: does the zone previously exist?
options:
  device_unique_name:
    description: managed fortigate unique name usually something like FG9A0ABC12345678
    type: string
    vdom:
      description: vdom name
      type: string
    adom:
      description: adom name
      type: string
    state:
      choices:
        - present
        - absent
      default: present
      description:
        - zone state
        - when C(state=present) given zone will be created
        - when C(state=absent) given zone will be deleted
      type: string
'''


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


def remove_dynamic_interface(module, fmgr):
    '''
    remove dynamic interface/zone, the function will always return True
    unless it fails, in which case it will try and exit. Function expects
    interface to be present
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: True
    :rtype: bool
    '''
    rv = True
    url = '/pm/config/adom/{adom}/obj/dynamic/interface/{zone}'.format(**module.params)
    if not module.check_mode:
        results = fmgr.process_request(url, {}, FMGRMethods.DELETE)
        if results[0] != 0:
            module.fail_json(msg='failed to delete dynamic interface/zone {0}, fortimanager returned: {1}'.format(module.params['zone'], results))
    return rv


def create_dynamic_interface(module, fmgr):
    '''
    create dynamic interface/zone. Given interface is expected to be
    absent.
    :param module: Ansible module object
    :param fmgr: Fortimanager object
    :return: changed state and zone information
    :rtype: dict
    '''
    rv = {'changed': False}
    scope = {'name': module.params['device_unique_name'], 'vdom': module.params['vdom']}
    url = '/pm/config/adom/{adom}/obj/dynamic/interface'.format(**module.params)
    zone = {
        'name': module.params['zone'],
        'single-intf': True,
        'dynamic_mapping': [
            {
                '_scope': [scope],
                'local-intf': []
            },
        ]
    }
    if not module.check_mode:
        results = fmgr.process_request(url, zone, FMGRMethods.ADD)
        if results[0] != 0:
            module.fail_json(msg='failed to create zone {0}, fortimanager returned {1}'.format(module.params['zone'], results))
        zone = [z for z in get_dynamic_interfaces(module, fmgr) if module.params['zone'] == z['name']]
        if not zone:
            module.fail_json(msg='could not find newly created zone {0}, something may be wrong (or eventually consistent)'.format(module.params['zone']))
        zone = zone[0]
    rv['zone'] = zone
    rv['changed'] = True
    return rv


def _zone_present(module, fmgr):
    changed = False
    msg = 'no change, zone is present'
    diff = {'before': {}, 'after': {}}
    zone = [z for z in get_dynamic_interfaces(module, fmgr) if module.params['zone'] == z['name']]

    if zone:
        diff['before'] = zone[0]
        diff['after'] = zone[0]
        return changed, diff, msg

    zone = create_dynamic_interface(module, fmgr)
    changed = zone['changed']
    diff['after'] = zone['zone']
    msg = 'zone {0} created'.format(module.params['zone'])
    return changed, diff, msg


def _zone_absent(module, fmgr):
    changed = False
    msg = 'no change, zone is absent'
    diff = {'before': {}, 'after': {}}
    present_zones = get_dynamic_interfaces(module, fmgr)

    zone = [z for z in present_zones if module.params['zone'] == z['name']]

    if not zone:
        return changed, diff, msg

    diff['before'] = zone[0]
    changed = remove_dynamic_interface(module, fmgr)
    msg = 'zone/dynamic interface deleted'
    return changed, diff, msg


def main():
    module = AnsibleModule(
        argument_spec=dict(
            device_unique_name=dict(required=True, type='str'),
            vdom=dict(type='str', required=True),
            adom=dict(type='str', required=True),
            state=dict(type='str', required=True, choices=['present', 'absent']),
            zone=dict(type='str', required=True),
            force=dict(type='bool', default=False)
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
        changed, diff, msg = _zone_present(module, fmgr)

    if module.params['state'] == 'absent':
        changed, diff, msg = _zone_absent(module, fmgr)

    module.exit_json(changed=changed, diff=diff, msg=msg)


if __name__ == '__main__':
    main()
