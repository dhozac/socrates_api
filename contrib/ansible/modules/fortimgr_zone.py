#!/usr/bin/env python
# Author: oscar.kene@klarna.com
#
# Manages zones on fortigates in fortimanager

from ansible.module_utils.basic import AnsibleModule
import requests
import json
from Forti import FortiMgr

def main():
    module = AnsibleModule(
        argument_spec=dict(
            username=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True),
            endpoint=dict(type='str', required=True),
            adom=dict(type='str', required=True),
            state=dict(type='str', required=True, choices=['present', 'absent']),
            zone=dict(type='str', required=True)
        ),
    )

    # required attributes
    adom = module.params['adom']
    username = module.params['username']
    password = module.params['password']
    state = module.params['state']
    zone = module.params['zone']
    changed = False
    result = []

    f = FortiMgr(module.params['endpoint'])
    r = f.login(username, password=password)
    result.append(r)

    if not r[0]:
        module.fail_json(msg="Failed to log in %s." % username)

    if state == "present":
        try:
            r = f.create_zone(adom, zone)
            result.append(r)
            if f.is_success(r[1], [0]):
                changed = True
            elif not f.is_success(r[1], [-2]):
                # if result code is not 0 or -2 raise an exception
                raise
        except:
            module.fail_json(msg="Failed to create zone %s." % zone, result=result)

    elif state == "absent":
        try:
            r = f.delete_zone(adom, zone)
            result.append(r)
            if f.is_success(r[1], [0]):
                changed = True
            elif not f.is_success(r[1], [-3]):
                # if result code is not 0 or -3 raise an exception
                raise
        except:
            module.fail_json(msg="Failed to delete zone %s." % zone, result=result)

    f.logout()
    module.exit_json(changed=changed, result=result)


if __name__ == "__main__":
    main()
