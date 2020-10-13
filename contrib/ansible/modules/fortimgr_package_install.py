#!/usr/bin/python

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.network.fortimanager.fortimanager import FortiManagerHandler
from ansible.module_utils.network.fortimanager.common import *


def main():
    module = AnsibleModule(
        argument_spec=dict(
            adom=dict(required=False, type="str", default="root"),
            device=dict(required=True, type="str"),
            vdom=dict(required=True, type="str"),
        ),
        supports_check_mode=True,
    )

    if module._socket_path:
        connection = Connection(module._socket_path)
        fmgr = FortiManagerHandler(connection, module)
        fmgr.tools = FMGRCommon()
    else:
        module.fail_json(**FAIL_SOCKET_MSG)

    # Fetch list of packages
    response = fmgr.process_request("/pm/pkg/adom/{0}".format(module.params['adom']), {}, FMGRMethods.GET)
    if response[0] != 0:
        module.fail_json(msg="Failed to list packages", response=response)
    packages = dict([((pkg['scope member'][0]['name'], pkg['scope member'][0]['vdom']), pkg['name']) for pkg in response[1] if 'scope member' in pkg])
    if (module.params['device'], module.params['vdom']) not in packages:
        module.fail_json(msg="Failed to find package", device=module.params['device'], vdom=module.params['vdom'])
    package = packages[(module.params['device'], module.params['vdom'])]

    if not module.check_mode:
        response = fmgr.process_request("/securityconsole/install/package", {"adom": module.params['adom'], "pkg": package}, FMGRMethods.EXEC)
        if response[0] != 0:
            module.fail_json(msg="Failed to install package", response=response)

    module.exit_json(changed=True, package=package)


if __name__ == "__main__":
    main()
