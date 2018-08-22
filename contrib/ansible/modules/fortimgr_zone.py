# Author: oscar.kene@klarna.com
#
# Manages zones on fortigates in fortimanager

import requests
import json
from Forti import FortiMgr

def main() :
  module = AnsibleModule(
        argument_spec = dict(
            username = dict(type='str', required=True),
            password = dict(type='str', required=True, no_log=True),
            endpoint = dict(type='str', required=True),
            adom = dict(type='str', required=True),
            state = dict(type='str', required=True, choices=['present', 'absent']),
            zone = dict(type='str', required=True)
        ),
    )

  # required attributes
  adom = module.params['adom']
  username = module.params['username']
  password = module.params['password']
  state = module.params['state']
  zone = module.params['zone']

  # other vars
  changed = False
  result = []

  # Login
  f = FortiMgr(module.params['endpoint'])
  r = f.login(username, password=password)
  result.append(r)

  if r[0] == False:
    module.fail_json(msg="Failed to log in %s." % username)

  # Make changes
  if state == "present":
    try:
      r = f.create_zone (adom, zone)
      result.append(r)
      if f.is_success(r[1], [0]):
        changed = True
      elif not f.is_success(r[1], [-2]):
        raise # if result code is not 0 or -2 raise an exception 
    except:
      module.fail_json(msg="Failed to create zone %s." % zone, result=result)

  elif state == "absent":
    try:
      r = f.delete_zone (adom, zone)
      result.append(r)
      if f.is_success(r[1], [0]):
        changed = True
      elif not f.is_success(r[1], [-3]):
        raise # if result code is not 0 or -3 raise an exception 
    except:
      module.fail_json(msg="Failed to delete zone %s." % zone, result=result)

  # Logout
  try:
    f.logout()
  except:
    pass

  module.exit_json(changed=changed, result=result)

# import module snippets
from ansible.module_utils.basic import AnsibleModule
if __name__ == "__main__":
    main()
