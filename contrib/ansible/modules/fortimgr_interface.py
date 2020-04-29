#!/usr/bin/env python
# Author: oscar.kene@klarna.com
#
# Manages interfaces on fortigates in fortimanager
from ansible.module_utils.basic import AnsibleModule
import requests
import json
from Forti import FortiMgr
import socket


def main():
    module = AnsibleModule(
        argument_spec=dict(
            username=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True),
            endpoint=dict(type='str', required=True),
            vdom=dict(type='str', required=True),
            adom=dict(type='str', required=True),
            interface=dict(type='str', requred=True),
            device=dict(type='str', required=True),
            state=dict(type='str', required=True, choices=['present', 'absent']),
            address=dict(type='str', required=False),
            netmask=dict(type='str', required=False),
            vlan_id=dict(type='int', required=False),
            phys_intf=dict(type='str', requried=False),
            zone=dict(type='str', required=False),
            dhcp_servers=dict(type='list', required=False),
        ),
    )

    # required attributes
    name = module.params['interface']
    device = module.params['device']
    vdom = module.params['vdom']
    adom = module.params['adom']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']
    zone = module.params['zone']
    vlan_id = module.params['vlan_id']
    address = module.params['address']
    netmask = module.params['netmask']
    phys_intf = module.params['phys_intf']
    changed = False
    result = []

    if 0 >= vlan_id >= 4095:
        module.fail_json(msg="VLAN id out of range %s." % vlan_id)

    # check if ip / mask is valid
    if state == "present":
        try:
            socket.inet_aton(address)
            socket.inet_aton(netmask)
        except socket.error:
            module.fail_json(msg="Address/netmask only used when state is 'present'.")

    # Login
    f = FortiMgr(module.params['endpoint'])
    r = f.login(username, password=password)
    result.append(r)
    if not r[0]:
        module.fail_json(msg="Failed to log in %s." % username)

    # Make changes
    if state == "present" and vlan_id is not None and address is not None and netmask is not None:
        kwargs = {}
        if module.params['dhcp_servers']:
            kwargs['dhcp_servers'] = module.params['dhcp_servers']
        r = f.create_interface("vlan", name, address, netmask, device, vdom, vlanid=vlan_id, phys_intf=phys_intf, **kwargs)
        result.append(r)
        if r[0]:
            if zone is not None:
                r = f.add_intf_to_zone(adom, device, vdom, name, zone)
                result.append(r)

                # true if mapping was created or already existing. There is no way to differentiate
                # So it will return as changed even though nothing really changed
                # TODO: fix this
                if r[0]:
                    changed = True
                else:
                    module.fail_json(msg="Zone %s does not exist." % zone)

    elif state == "absent":
        # Check if interface has a zone mapping and remove it
        z = f.get_zone_from_intf(adom, device, name)
        if z is not None:
            if not f.delete_intf_to_zone(adom, device, vdom, name, z):
                module.fail_json(msg="Unmapping zone failed.")
            else:
                changed = True

        # delete interface
        r = f.delete_interface(device, vdom, name)
        result.append(r)

        if r[0]:
            changed = True
        else:
            module.fail_json(msg="Deleting interface %s failed." % name)

    if changed:
        for package in f.get_policy_packages(module.params['adom'])['result'][0]['data']:
            if (package['dev'] == module.params['device']
                    and package['vdom'] == module.params['vdom']):
                break
        else:
            module.fail_json(msg="Failed to find policy package")
        f.policy_package_install(module.params['adom'], module.params['device'],
                                 package['pkg'], preview=False)

    f.logout()
    module.exit_json(changed=changed, result=result)


if __name__ == "__main__":
    main()
