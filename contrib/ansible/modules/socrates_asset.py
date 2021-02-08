#!/usr/bin/env python
from ansible.module_utils.basic import *
import requests
import copy
import datetime
import json
import uuid


def has_nones(d, prefix=""):
    fields = []
    for key, value in d.items():
        if isinstance(value, dict):
            fields.extend(has_nones(value, prefix="%s.%s" % (prefix, key)))
        if value is None:
            fields.append(key)
    return fields


def remove_nones(d):
    ret = {}
    for key, value in d.items():
        if isinstance(value, dict):
            ret[key] = remove_nones(value)
        elif value is not None:
            ret[key] = value
    return ret


def dict_diff(d1, d2):
    for key, val in d1.items():
        if isinstance(val, dict):
            if dict_diff(val, d2.get(key, {})):
                return True
            continue
        if val != d2.get(key, None):
            return True
    return False


class RequestException(Exception):
    pass


class Asset(object):
    wait_event_create = None
    wait_event_update = None
    wait_event_delete = None

    def __init__(self, module):
        self.module = module
        self.req_args = {
            'auth': (module.params['username'], module.params['password']),
            'headers': {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
            },
        }

    def discover_service_tag(self):
        return None

    def request(self, method, path, data=None):
        method_fun = getattr(requests, method)
        exc = None
        for server in self.module.params['servers']:
            try:
                url = "https://%s%s" % (server, path)
                if data:
                    response = method_fun(url, json=data, **self.req_args)
                else:
                    response = method_fun(url, **self.req_args)
                if response.status_code >= 500 and response.status_code < 600:
                    raise RequestException("returned %d: %s" % (response.status_code, response.text))
                else:
                    return response
            except requests.exceptions.RequestException as e:
                exc = e
            except RequestException as e:
                exc = e
        self.module.fail_json(msg="Failed to talk to socrates: %s" % exc)

    def is_changed(self, current_asset, desired_asset):
        return len(self.get_update(current_asset, desired_asset)) > 2

    def get_update(self, current_asset, desired_asset, subupdate=False):
        if subupdate:
            update = {}
        else:
            update = {'log': self.module.params['log'], 'version': current_asset['version']}
        for field in desired_asset.keys():
            if field not in current_asset:
                update[field] = desired_asset[field]
            else:
                if isinstance(desired_asset[field], dict):
                    update[field] = self.get_update(current_asset[field], desired_asset[field], True)
                    if len(update[field]) == 0:
                        del update[field]
                elif current_asset[field] != desired_asset[field]:
                    update[field] = desired_asset[field]
        return update

    def get_create(self, asset):
        create = {'log': self.module.params['log'], 'version': 1}
        create.update(asset)
        return create

    def run(self):
        if not self.module.params['service_tag']:
            self.module.params['service_tag'] = self.discover_service_tag()
            if self.module.params['service_tag'] is None:
                self.module.fail_json(msg='service_tag is required')

        start_time = datetime.datetime.utcnow()
        wait_event = None
        response = self.request('get', '/asset/%s' % self.module.params['service_tag'])
        if self.module.params['state'] == 'present':
            asset = remove_nones(self.asset_definition())
            asset['asset_type'] = self.asset_type
            if response.status_code == 404:
                changed = True
                changes = self.get_create(asset)
                old_asset = {}
                wait_event = self.wait_event_create
                if not self.module.check_mode:
                    response = self.request('post', '/asset/', changes)
                    if response.status_code not in (200, 201):
                        self.module.fail_json(msg="Failed to create asset: %d %s" % (response.status_code, response.content))
                    asset = response.json()

            elif response.status_code == 200:
                old_asset = response.json()
                changed = self.is_changed(old_asset, asset)
                changes = self.get_update(old_asset, asset)
                if changed and not self.module.check_mode:
                    wait_event = self.wait_event_update
                    response = self.request('patch', '/asset/%s' % old_asset['service_tag'], changes)
                    if response.status_code not in (200, 201):
                        self.module.fail_json(msg="Failed to update asset: %d %s" % (response.status_code, response.content))
                    asset = response.json()
                elif not changed:
                    asset = old_asset
                    if asset.get('provisioning'):
                        wait_event = self.wait_event_create

            else:
                self.module.fail_json(msg="Unexpected return code from Socrates: %d %s" % (response.status_code, response.content))

        elif self.module.params['state'] == 'absent':
            changes = {}
            if response.status_code == 200:
                changed = True
                old_asset = response.json()
                asset = {'id': old_asset['id']}
                wait_event = self.wait_event_delete
                if not self.module.check_mode:
                    response = self.request('delete', '/asset/%s' % old_asset['service_tag'], {'log': self.module.params['log']})
                    if response.status_code != 204:
                        self.module.fail_json(msg="Failed to delete asset: %d %s" % (response.status_code, response.content))

            elif response.status_code == 404:
                changed = False
                old_asset = {}
                asset = {}

            else:
                self.module.fail_json(msg="Unexpected return code from Socrates: %d %s" % (response.status_code, response.content))

        if not self.module.check_mode and self.module.params['wait'] and wait_event:
            path = '/event/feed/'
            event_found = False
            while not event_found:
                response = self.request('get', path)
                if response.status_code == 204:
                    continue
                elif response.status_code != 200:
                    module.fail_json(msg="Failed to get events %d: %s" % (response.status_code, response.content))
                events = json.loads(response.content)
                for event in events:
                    if (event['asset_id'] == asset['id'] and
                        event['event'] == wait_event and
                        datetime.datetime.strptime(event['timestamp'], "%Y-%m-%dT%H:%M:%S.%fZ") >= start_time):
                        event_found = True
                path = '/event/feed/?id=%s' % events[-1]['id']

        return {'changed': changed, 'changes': changes, 'diff': {'before': old_asset, 'after': asset}, 'asset': asset}


class ProvisionedAsset(Asset):
    wait_event_create = 'provisioned'
    wait_event_update = 'reprovisioned'
    wait_event_delete = 'deleted'

    def asset_definition(self):
        vlans = []
        for vlan in self.module.params['vlans']:
            if isinstance(vlan, dict):
                vlans.append(vlan)
            else:
                vlans.append({'cidr': vlan})
        vlan = {}
        if isinstance(self.module.params['vlan'], dict):
            vlan = self.module.params['vlan']
        else:
            vlan = {'cidr': self.module.params['vlan']}

        return {
            'owner_can_login': self.module.params['owner_can_login'],
            'owner': self.module.params['owner'],
            'managers': self.module.params['managers'],
            'users': self.module.params['users'],
            'provision': {
                'os': self.module.params['os'],
                'hostname': self.module.params['hostname'],
                'vlan': vlan,
                'vlans': vlans,
                'storage': self.module.params['storage'],
                'aliases': self.module.params['aliases'],
                'ldaplocal': self.module.params['ldaplocal'],
            },
            'url': self.module.params['url'],
            'network': self.module.params['network'],
            'tags': self.module.params['tags'],
         }

    def get_create(self, asset):
        create = super(ProvisionedAsset, self).get_create(asset)
        create['provisioning'] = True
        return create

    def get_update(self, current_asset, desired_asset, subupdate=False):
        update = super(ProvisionedAsset, self).get_update(current_asset, desired_asset, subupdate)
        if not subupdate:
            update['provisioning'] = True
        # vlans being a list that is modified by the system needs some special care
        desired_asset = copy.deepcopy(desired_asset)
        if 'provision' in update and 'vlans' in update['provision']:
            del update['provision']['vlans']
            new_vlans = []
            for index, vlan in enumerate(desired_asset['provision'].get('vlans', [])):
                if len(current_asset.get('provision', {}).get('vlans', [])) <= index or dict_diff(vlan, current_asset.get('provision', {}).get('vlans', [])[index]):
                    new_vlans.append(vlan)
                else:
                    new_vlans.append(current_asset['provision']['vlans'][index])
            if new_vlans != current_asset.get('provision', {}).get('vlans', []):
                update['provision']['vlans'] = new_vlans
            else:
                if len(update['provision']) == 0:
                    del update['provision']
        return update

    def is_changed(self, current_asset, desired_asset):
        return len(self.get_update(current_asset, desired_asset)) > 3


class ServerAsset(ProvisionedAsset):
    asset_type = 'server'
    def asset_definition(self):
        asset = super(ServerAsset, self).asset_definition()
        asset['provision']['hyperthreading'] = self.module.params['hyperthreading']
        asset['provision']['use_port_channel'] = self.module.params['use_port_channel']
        asset['provision']['additional_vlans'] = self.module.params['additional_vlans']
        return asset


class VMAsset(ProvisionedAsset):
    asset_type = 'vm'
    def discover_service_tag(self):
        response = self.request('get', '/asset/?provision__hostname=%s' % self.module.params['hostname'])
        if response.status_code != 200:
            self.module.fail_json(msg='Unable to determine service tag: %d %s' % (response.status_code, response.content))
        data = response.json()
        for asset in data:
            if asset['state'] in ('ready', 'in-use'):
                return asset['service_tag']
        else:
            return "service-" + str(uuid.uuid4())

    def asset_definition(self):
        asset = super(VMAsset, self).asset_definition()

        for name, value in asset['provision']['storage'].items():
            try:
                asset['provision']['storage'][name]['size'] = int(asset['provision']['storage'][name]['size'])
            except ValueError:
                module.fail_json(msg='storage.%s.size=%r is not a valid integer' % (name, asset['provision']['storage'][name]['size']))

        asset['provision']['ram'] = self.module.params['ram']
        asset['provision']['cpus'] = self.module.params['cpus']
        return asset

    def get_create(self, asset):
        create = super(VMAsset, self).get_create(asset)
        create['service_tag'] = self.discover_service_tag()
        create['state'] = 'ready'
        create['parent'] = self.module.params['parent']
        return create


class VMClusterAsset(Asset):
    asset_type = 'vmcluster'
    def asset_definition(self):
        return {
            'state': 'in-use',
            'asset_type': self.module.params['asset_type'],
            'asset_subtype': self.module.params['asset_subtype'],
            'service_tag': self.module.params['service_tag'],
            'parent': self.module.params['parent'],
            'owner': self.module.params['owner'],
            'managers': self.module.params['managers'],
            'storage': [self.module.params['storage']],
            'hypervisors': self.module.params['hypervisors'],
            'url': self.module.params['url'],
            'nics': self.module.params['nics'],
            'tags': self.module.params['tags'],
        }


class LBClusterAsset(Asset):
    asset_type = 'lbcluster'
    def asset_definition(self):
        return {
            'state': 'in-use',
            'asset_type': self.module.params['asset_type'],
            'service_tag': self.module.params['service_tag'],
            'owner': self.module.params['owner'],
            'url': self.module.params['url'],
            'composed_of': self.module.params['composed_of'],
            'vendor': self.module.params['vendor'],
            'model': self.module.params['model'],
            'tags': self.module.params['tags'],
        }


def all_subclasses(cls):
    return set(cls.__subclasses__()).union(
        [s for c in cls.__subclasses__() for s in all_subclasses(c)])
ASSET_CLASSES = all_subclasses(Asset)


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', default='present', choices=['present', 'absent']),
            servers=dict(type='list', default=['socrates.in.qliro.net']),
            username=dict(type='str', required=True),
            password=dict(type='str', required=True, no_log=True),
            service_tag=dict(type='str'),
            asset_type=dict(type='str', choices=['server', 'vm', 'vmcluster', 'lbcluster'], required=True),
            parent=dict(type='str', required=False),
            log=dict(type='str', required=False),
            owner=dict(type='str', required=False),
            owner_can_login=dict(type='bool', default=True),
            managers=dict(type='list', required=False, default=[]),
            users=dict(type='list', required=False),
            hyperthreading=dict(type='bool', default=False),
            os=dict(type='str', required=False),
            vlan=dict(type='raw', required=False),
            vlans=dict(type='list', default=[]),
            hostname=dict(type='str', required=False),
            ram=dict(type='int', required=False),
            cpus=dict(type='int', required=False),
            storage=dict(type='dict', required=False),
            ldaplocal=dict(type='bool', default=False),
            wait=dict(type='bool', default=True),
            wait_event=dict(type='str', default=None),
            aliases=dict(type='list', default=[]),
            tasksequence=dict(type='str'),
            mdtcust=dict(type='str'),
            asset_subtype=dict(type='str', required=False),
            nics=dict(type='list', default=[]),
            hypervisors=dict(type='list', default=[]),
            url=dict(type='str'),
            additional_vlans=dict(type='list', default=[]),
            network=dict(type='dict', required=False),
            use_port_channel=dict(type='bool', default=False),
            composed_of=dict(type='list', required=False),
            vendor=dict(type='str', required=False),
            model=dict(type='str', required=False),
            tags=dict(type='dict', required=False),
        ),
        supports_check_mode=True
    )

    for subclass in ASSET_CLASSES:
        if hasattr(subclass, 'asset_type') and module.params['asset_type'] == subclass.asset_type:
            break
    else:
        subclass = Asset

    instance = subclass(module)
    module.exit_json(**instance.run())


if __name__ == "__main__":
    main()
