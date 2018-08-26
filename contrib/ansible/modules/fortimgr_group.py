#!/usr/bin/python -tt

import Forti
import netaddr
import re

def length_to_netmask(length):
    return str(netaddr.IPNetwork("0.0.0.0/%d" % length).netmask)

def main():
    module = AnsibleModule(
        argument_spec = dict(
            state = dict(type='str', choices=['present', 'absent'], default='present'),
            endpoint = dict(type='str', required=True),
            username = dict(type='str', required=True),
            password = dict(type='str', required=True, no_log=True),
            adom = dict(type='str', required=True),
            group = dict(type='dict', required=True),
        ),
        supports_check_mode = True,
    )

    results = []

    f = Forti.FortiMgr(module.params['endpoint'])
    r = f.login(module.params['username'], module.params['password'])
    results.append(r)
    if not r[0]:
        module.fail_json(msg="Failed to login: %r" % r)

    name = "g-" + module.params['group']['name'].replace('/', '\\/')

    addresses = dict((address['subnet'][0], address) for address in
        f.get_data(
            api_endpoint="pm/config/adom/" + module.params['adom'] + "/obj/firewall/address",
            method="get"
        ).json()['result'][0]['data']
        if 'subnet' in address
    )

    members = []
    for member in module.params['group']['addresses']:
        if 'address' in member:
            # FIXME: IPv4
            if 'length' in member and member['length'] < 32:
                address = 'n-%s/%s' % (member['address'], member['length'])
            else:
                address = 'h-%s' % member['address']
            netmask = length_to_netmask(member.get('length', 32))
            if member['address'] in addresses and addresses[member['address']]['subnet'][1] == netmask:
                members.append(addresses[member['address']]['name'])
            else:
                changed = True
                members.append(address)
                if not module.check_mode:
                    result = f.create_address(module.params['adom'], address, member['address'], netmask)
                    results.append(result)
        elif 'address_group' in member:
            members.append("g-%s" % member['address_group'])

    result = f.get_data(api_endpoint="pm/config/adom/" + module.params['adom'] + "/obj/firewall/addrgrp/" + name, method="get").json()
    results.append(result)
    if 'data' in result['result'][0]:
        existing = result['result'][0]['data']
    else:
        existing = None

    changed = False
    if module.params['state'] == 'present':
        if existing is None:
            changed = True
            if not module.check_mode:
                result = f.create_group(module.params['adom'], name, members)
                results.append(result)
                if not result[0]:
                    module.fail_json(msg="Failed to create group", results=results)
        else:
            if not isinstance(existing['member'], (list, tuple)):
                existing['member'] = [existing['member']]
            if len(set(members).symmetric_difference(set(existing['member']))) > 0:
                changed = True
                if not module.check_mode:
                    result = f.get_data(api_endpoint="pm/config/adom/" + module.params['adom'] + "/obj/firewall/addrgrp/" + name, method="update", data={"member": members}).json()
                    results.append(result)
                    if result['result'][0]['code'] != 0:
                        module.fail_json(msg="Failed to update members", results=results)

        module.exit_json(msg="Group present", changed=changed, results=results)

    elif module.params['state'] == 'absent':
        if existing is not None:
            changed = True
            if not module.check_mode:
                result = f.delete_group(module.params['adom'], name)
                results.append(result)
                if not result[0]:
                    module.fail_json(msg="Failed to delete group", results=results)
        module.exit_json(msg="Group absent", changed=changed, results=results)

# import module snippets
from ansible.module_utils.basic import *
if __name__ == "__main__":
    main()
