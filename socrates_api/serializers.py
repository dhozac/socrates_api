# Copyright 2015-2018 Klarna Bank AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
from __future__ import division
import time
import jsonpath_rw_ext
import datetime
import re
import uuid
from celery import chain
from django.utils import timezone
from django.conf import settings
from django.contrib.auth.models import Group
from django.core.validators import URLValidator
from rest_framework import serializers
from rest_framework.reverse import reverse
from django_rethink import r, RethinkSerializer, RethinkObjectNotFound, RethinkMultipleObjectsFound, HistorySerializerMixin, PermissionsSerializer, ReviewSerializer, HistorySerializerMixin, NeedsReviewMixin, HistorySerializer, validate_group_name, validate_username
from socrates_api.models import SocratesUser

ASSET_STATES = ['new', 'ready', 'in-use', 'deleted']
ASSET_TYPES = ['server', 'blade-chassis', 'rack', 'zone', 'site', 'vm', 'vmcluster', 'storage', 'network', 'misc', 'lbcluster']
ASSET_SUB_TYPES = ['rackmount', 'blade', 'vmware', 'ovirt', 'libvirt', 'switch', 'patchpanel', 'cablemanagement', 'fibrechannel', 'iscsi', 'fibrechannel-switch', 'das', 'firewall', 'loadbalancer', 'router', 'ups', 'kvm', 'pdu']

def dict_merge(dict1, dict2):
    if dict1 is None:
        return dict2.copy()
    elif dict2 is None:
        return dict1.copy()
    elif not isinstance(dict1, dict) or not isinstance(dict2, dict):
        raise Exception("Attempting to dict_merge non-dicts: %r %r" % (dict1, dict2))
    d = dict1.copy()
    for key in dict2:
        if key in d and isinstance(d[key], dict):
            d[key] = dict_merge(d[key], dict2[key])
        else:
            d[key] = dict2[key]
    return d

def dict_differences(new, old):
    ret = {}
    for key, val in new.items():
        if key not in old:
            ret[key] = val
            continue
        if isinstance(val, dict) and isinstance(old[key], dict):
            ret[key] = dict_differences(val, old[key])
            if len(ret[key]) == 0:
                del ret[key]
        elif isinstance(val, datetime.datetime) and isinstance(old[key], datetime.datetime):
            if val.strftime("%Y-%m-%dT%H:%M:%S") != old[key].strftime("%Y-%m-%dT%H:%M:%S"):
                ret[key] = val
        else:
            if val != old[key]:
                ret[key] = val
    for key in set(old.keys()).difference(set(new.keys())):
        ret[key] = None
    return ret

class AssetRawSerializer(RethinkSerializer):
    class Meta(RethinkSerializer.Meta):
        table_name = 'assets_raw'
        slug_field = 'service_tag'
        indices = ['service_tag']

class WarrantyEntitlementSerializer(serializers.Serializer):
    description = serializers.CharField()
    end_date = serializers.DateTimeField()

class WarrantySerializer(serializers.Serializer):
    valid = serializers.BooleanField(default=False)
    shipping_date = serializers.DateTimeField(required=False)
    next_end_date = serializers.DateTimeField(required=False, allow_null=True)
    order_number = serializers.CharField(required=False, allow_null=True)
    entitlements = serializers.DictField(required=False, child=WarrantyEntitlementSerializer())

class AssetSerializer(NeedsReviewMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False)
    state = serializers.ChoiceField(choices=ASSET_STATES, required=True)
    asset_type = serializers.ChoiceField(choices=ASSET_TYPES, required=True)
    asset_subtype = serializers.ChoiceField(choices=ASSET_SUB_TYPES, required=False, allow_null=True)
    version = serializers.IntegerField(default=1, min_value=1)
    service_tag = serializers.CharField(required=True)
    positions = serializers.IntegerField(required=False, allow_null=True)
    parent = serializers.CharField(required=False, allow_null=True)
    parent_position = serializers.ListField(required=False)
    owner = serializers.CharField(required=False, validators=[validate_group_name])
    owner_can_login = serializers.BooleanField(required=False)
    managers = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False)
    users = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False)
    provision = serializers.DictField(required=False)
    url = serializers.CharField(required=False)
    connected_to = serializers.ListField(child=serializers.CharField(), required=False)
    composed_of = serializers.ListField(child=serializers.CharField(), required=False)
    hypervisors = serializers.ListField(child=serializers.CharField(), required=False)
    has_problems = serializers.BooleanField(required=False)
    provisioning = serializers.BooleanField(required=False)
    decommissioning = serializers.BooleanField(required=False)
    maintenance = serializers.BooleanField(required=False)
    needs_review = serializers.BooleanField(required=False)
    latest_action = serializers.CharField(required=False)
    additional_ids = serializers.DictField(required=False)
    inventory_id = serializers.CharField(required=False)
    tags = serializers.DictField(required=False)
    # Fields generated from intake
    cpu = serializers.ListField(required=False)
    ram = serializers.DictField(required=False)
    vendor = serializers.CharField(required=False)
    supportvendor = serializers.CharField(required=False)
    model = serializers.CharField(required=False)
    oob = serializers.DictField(required=False)
    nics = serializers.ListField(child=serializers.DictField(), required=False)
    storage = serializers.ListField(child=serializers.DictField(), required=False)
    switch = serializers.DictField(required=False)
    network = serializers.DictField(required=False)
    cards = serializers.ListField(child=serializers.DictField(), required=False)
    efi = serializers.BooleanField(required=False)
    # Field generated from warranty API
    warranty = WarrantySerializer(required=False)

    class Meta(HistorySerializerMixin.Meta):
        abstract = False
        table_name = 'assets'
        slug_field = 'service_tag'
        indices = [
            'service_tag',
            'owner',
            'parent',
            ('managers', {'multi': True}),
            ('users', {'multi': True}),
        ]
        log_required = True
        needs_review_field = 'needs_review'

    def has_read_permission(self, user, user_groups=None):
        if user_groups is None:
            user_groups = set(user.groups.all().values_list('name', flat=True))
        if self.has_write_permission(user, user_groups):
            return True
        if user.is_global_readonly:
            return True
        return 'owner' in self.instance and self.instance['owner'] in user_groups

    def has_write_permission(self, user, user_groups=None):
        if user.is_superuser:
            return True
        if 'owner' not in self.instance:
            return False
        if user_groups is None:
            user_groups = set(user.groups.all().values_list('name', flat=True))
        managers = set(self.instance.get('managers', []))
        return ((self.instance['owner'] in user_groups and
                 self.instance.get('owner_can_login', True)) or
                len(user_groups.intersection(managers)) > 0)

    def get_reviewers(self, instance, data):
        reviewers = []
        if instance is not None:
            if 'owner' in instance and instance.get('owner_can_login', True):
                reviewers.append(instance['owner'])
            reviewers.extend(instance.get('managers', []))
        return reviewers

    def to_representation(self, instance):
        ret = super(AssetSerializer, self).to_representation(instance)
        if ('request' in self.context and
            self.context['request'].user is not None and
            not self.context['request'].user.is_superuser):
            user_groups = set(self.context['request'].user.groups.all().values_list('name', flat=True))
            if (((isinstance(self.instance, dict) and
                  not self.has_write_permission(self.context['request'].user, user_groups)) or
                 not self.__class__(instance).has_write_permission(self.context['request'].user, user_groups))
                or not self.context['request'].user.is_console_user):
                ret.pop('oob', None)
        return ret

    def _get_instance(self, validated_data):
        data = dict(validated_data)
        data.pop('log', None)
        return data

    def create(self, validated_data):
        data = self._get_instance(validated_data)
        asset = super(AssetSerializer, self).create(data)
        if asset['asset_type'] == 'vm' and asset['state'] == 'ready':
            from socrates_api.tasks import provision_vm, add_to_dns, ipmi_poweron
            task = provision_vm.s() | add_to_dns.s() | ipmi_poweron.s()
            task.apply_async((asset,))
        return asset

    def update(self, instance, validated_data):
        update = self._get_instance(validated_data)
        if self.partial:
            new_asset = dict_merge(instance, update)
        else:
            new_asset = update
        diff = dict_differences(new_asset, instance)
        if not diff and 'latest_action' not in validated_data:
            return instance

        asset = super(AssetSerializer, self).update(instance, validated_data)
        old_asset = instance

        # Handle all provisions and reprovisions
        if not old_asset.get('provisioning', False) and asset.get('provisioning', False):
            # Shortcut for managing network changes online
            if asset['state'] == 'in-use' and set(['vlan', 'vlans', 'aliases']).issuperset(set(diff.get('provision', {}).keys())):
                from socrates_api.tasks import reconfigure_network_port, add_to_dns, asset_update, event_emit
                task = add_to_dns.s(old_asset) | asset_update.s({'provisioning': False, 'log': 'Reconfigured networking'}) | reconfigure_network_port.s() | event_emit.s('reprovisioned')
                task.apply_async((asset,))
            # Shortcut for managing VM disk changes online
            elif (asset['state'] == 'in-use' and asset['asset_type'] == 'vm' and list(diff.get('provision', {}).keys()) == ['storage'] and
                  all([list(x.keys()) == ['size'] for x in diff['provision']['storage'].values()])):
                from socrates_api.tasks import provision_vm, asset_update, event_emit
                task = provision_vm.s() | asset_update.s({'provisioning': False, 'log': 'Extended disks'}) | event_emit.s('reprovisioned')
                task.apply_async((asset,))
            else:
                if asset['asset_type'] == 'server':
                    from socrates_api.tasks import ipmi_reboot, ipmi_boot_pxe, reconfigure_network_port, add_to_dns, event_emit
                    task = add_to_dns.s(old_asset) | ipmi_boot_pxe.s() | reconfigure_network_port.s() | ipmi_reboot.s()
                    if asset['state'] == 'in-use':
                        task = task | event_emit.s('reprovisioned')
                    task.apply_async((asset,))
                elif asset['asset_type'] == 'vm':
                    from socrates_api.tasks import provision_vm, add_to_dns, asset_update, event_emit, ipmi_shutdown, ipmi_poweron
                    task = ipmi_shutdown.s() | provision_vm.s() | add_to_dns.s(old_asset) | asset_update.s({'provisioning': False, 'log': 'Reprovisioning complete'}) | ipmi_poweron.s() | event_emit.s('reprovisioned')
                    task.apply_async((asset,))

        # This handles the case of reprovisioning servers
        if old_asset.get('provisioning', False) and not asset.get('provisioning', False) and old_asset['state'] == 'in-use':
            from socrates_api.tasks import reconfigure_network_port
            reconfigure_network_port.apply_async((asset,))

        if not old_asset.get('maintenance', False) and asset.get('maintenance', False):
            from socrates_api.tasks import reconfigure_network_port, begin_maintenance, ipmi_ping
            task = begin_maintenance.s() | ipmi_ping.s() | reconfigure_network_port.s()
            task.apply_async((asset,))
        elif old_asset.get('maintenance', False) and not asset.get('maintenance', False):
            from socrates_api.tasks import reconfigure_network_port, end_maintenance, ipmi_ping
            task = end_maintenance.s() | ipmi_ping.s() | reconfigure_network_port.s()
            task.apply_async((asset,))
        if old_asset['state'] == 'new' and asset['state'] == 'ready':
            from socrates_api.tasks import event_emit
            event_emit.apply_async((asset, 'ready'))
        if (old_asset.get('owner', None) != asset.get('owner', None) or
            old_asset.get('managers', []) != asset.get('managers', []) or
            old_asset.get('users', []) != asset.get('users', [])):
            from socrates_api.tasks import run_playbook
            run_playbook.apply_async(args=(asset, 'reassign-owners.yml'), kwargs={'extra_vars': {'old_asset': old_asset}})
        # Added hypervisors
        if asset['asset_type'] == 'vmcluster':
            from socrates_api.tasks import asset_get, add_cluster_networks, reconfigure_network_port
            new_hypervisors = set(asset.get('hypervisors', [])).difference(set(old_asset.get('hypervisors', [])))
            if len(new_hypervisors) > 0:
                task = add_cluster_networks.s(asset)
                for service_tag in new_hypervisors:
                    task = task | asset_get.si(service_tag) | reconfigure_network_port.s()
                task.apply_async()

        return asset

    def delete(self):
        from socrates_api.tasks import remove_from_dns, reconfigure_network_port, ipmi_shutdown, remove_vm, event_emit, remove_hypervisor_from_cluster, asset_drop_provision, run_playbook, remove_from_load_balancers, asset_update
        data = self.context['request'].data
        if 'log' not in data:
            raise serializers.ValidationError("'log' field is required when deleting an asset")
        log = data['log']
        physically = data.get('physically', False) and self.context['request'].user.is_superuser
        username = self.context['request'].user.username

        if self.instance.get('decommissioning', False):
            raise serializers.ValidationError("delete is already in progress")
        if self.instance.get('needs_review', False):
            raise serializers.ValidationError("'needs_review' field cannot be set when deleting an asset")

        task = ipmi_shutdown.s()
        if 'hostname' in self.instance.get('provision', {}):
            task = task | remove_from_dns.s() | remove_from_load_balancers.s()
        new_state = 'deleted'
        if self.instance['asset_type'] == "vm":
            task = task | remove_vm.s()
        elif self.instance['asset_type'] == "server":
            task = task | remove_hypervisor_from_cluster.s() | reconfigure_network_port.s()
            if not physically:
                new_state = 'ready'
        task = task | asset_update.s({'decommissioning': False, 'state': new_state, 'log': 'Decommissioning complete'}) | event_emit.s('deleted') | run_playbook.s('deleted.yml')
        if self.instance['asset_type'] == "server":
            task = task | asset_drop_provision.s(physically)
            if not physically:
                task = task | event_emit.s('ready')
        self.partial = True
        asset = self.update(self.instance, {
               'version': self.instance['version'],
               'decommissioning': True,
               'provisioning': False,
           })
        task.apply_async((asset,))
        return True

    def validate_parent(self, value):
        if value is not None:
            try:
                self.parent_asset = AssetSerializer.get(service_tag=value)
            except RethinkObjectNotFound:
                raise serializers.ValidationError('parent="%s" does not exist' % value)
        return value

    def validate_service_tag(self, value):
        if self.instance is None:
            try:
                asset = AssetSerializer.get(service_tag=value)
                raise serializers.ValidationError('service_tag="%s" is a duplicate' % value)
            except RethinkObjectNotFound:
                pass
        return value

    def validate_version(self, value):
        if self.instance is not None:
            if self.instance['version'] != value:
                raise serializers.ValidationError('version=%d is not the expected %d' % (value, self.instance['version']))
        return value

    def validate(self, data):
        from socrates_api.tasks import get_ipam, ipv4_network_contains
        if 'log' not in data:
            raise serializers.ValidationError("'log' is required")
        if 'version' not in data:
            raise serializers.ValidationError("'version' is required")
        if self.partial:
            new_asset = dict_merge(self.instance, data)
        else:
            new_asset = data
        if self.instance is not None:
            diff = dict_differences(new_asset, self.instance)
        else:
            diff = new_asset
        username = self.get_username()
        if self.instance is not None and username is not None:
            if self.instance.get('maintenance', False) and data.get('provisioning', False):
                raise serializers.ValidationError("cannot provision asset while maintenance is set to True")
            if self.instance.get('provisioning', False) and not data.get('provisioning', True):
                raise serializers.ValidationError("cannot update asset until provisioning completes")
            if self.instance.get('decommissioning', False) and 'decommissioning' not in data:
                raise serializers.ValidationError("cannot update asset until decommission completes")
            read_only_fields = []
            if self.instance['asset_type'] == 'server':
                read_only_fields.extend(['cpu', 'ram', 'vendor', 'model', 'oob', 'nics', 'storage', 'warranty'])
                if 'request' not in self.context or not self.context['request'].user.is_superuser:
                    read_only_fields.extend(['state'])
            elif self.instance['asset_type'] == 'vm':
                read_only_fields.extend(['cpu', 'ram', 'parent', 'nics', 'storage'])
            if 'request' not in self.context or not self.context['request'].user.is_superuser:
                read_only_fields.extend(['asset_type', 'asset_subtype', 'service_tag', 'parent', 'parent_position', 'connected_to', 'switch'])
            for field in read_only_fields:
                if self.instance.get(field, None) != new_asset.get(field, None):
                    raise serializers.ValidationError("cannot change field '%s' manually" % field)
        if new_asset['state'] == 'ready' and 'owner' not in new_asset:
            raise serializers.ValidationError("state='ready' invalid without an owner")
        if new_asset['state'] == 'ready' and 'parent' not in new_asset:
            raise serializers.ValidationError("state='ready' invalid without a parent")
        if 'parent' in new_asset:
            self.validate_parent(new_asset['parent'])
        if hasattr(self, 'parent_asset'):
            if ((new_asset['asset_type'] in ('server', 'storage') and self.parent_asset['asset_type'] not in ("blade-chassis", "rack")) or
                (new_asset['asset_type'] == 'rack' and self.parent_asset['asset_type'] != 'zone') or
                (new_asset['asset_type'] == 'zone' and self.parent_asset['asset_type'] != 'site') or
                (new_asset['asset_type'] == 'vm' and self.parent_asset['asset_type'] not in ('vmcluster', 'server'))
               ):
                raise serializers.ValidationError("parent='%s' is invalid with asset_type='%s'" % (new_asset['parent'], new_asset['asset_type']))
            if 'users' in self.parent_asset:
                if new_asset['owner'] not in self.parent_asset['users']:
                    raise serializers.ValidationError("owner='%s' does not have permission for parent='%s'" % (new_asset['owner'], new_asset['parent']))
        if username is not None and 'hypervisors' in new_asset:
            for service_tag in new_asset['hypervisors']:
                hv_asset = AssetSerializer.get(service_tag=service_tag)
                if new_asset['owner'] != hv_asset['owner']:
                    raise serializers.ValidationError("hypervisors='%s' does not have the same owner" % service_tag)
        if new_asset.get('provisioning', False):
            if 'provision' not in new_asset:
                raise serializers.ValidationError("'provision' is required when provisioning is set")
            if (getattr(settings, 'SOCRATES_INVENTORY_ID_REQUIRED', False) and
                    'inventory_id' not in new_asset):
                raise serializers.ValidationError("'inventory_id' is required when provisioning is set")

            required_keys = ['hostname', 'vlan']
            if new_asset['asset_type'] not in ('network', 'storage'):
                required_keys.extend(['os', 'storage'])
            for key in required_keys:
                if key not in new_asset['provision']:
                    raise serializers.ValidationError("provision__%s is required" % key)

            if not re.match(settings.SOCRATES_HOSTNAME_PATTERN, new_asset['provision']['hostname']):
                raise serializers.ValidationError("provision__hostname is invalid")

            for alias in new_asset['provision'].get('aliases', []):
                if not re.match(settings.SOCRATES_ALIAS_PATTERN, alias):
                    raise serializers.ValidationError("provision__aliases='%s' is invalid" % alias)

            if 'os' in new_asset['provision']:
                try:
                    os = OperatingSystemSerializer.get(name=new_asset['provision']['os'])
                except RethinkObjectNotFound:
                    raise serializers.ValidationError("'%s' is not a valid choice for provision__os" % new_asset['provision']['os'])

            if new_asset['asset_type'] == 'vm':
                remote_domain = new_asset['parent']
            else:
                remote_domain = jsonpath_rw_ext.parse('$.nics[*].remote.domain').find(new_asset)[0].value

            with_ports = ['ports' in vlan for vlan in [new_asset['provision']['vlan']] + new_asset['provision'].get('vlans', [])]
            if any(with_ports) and not all(with_ports):
                raise serializers.ValidationError("provision__vlan(s)__ports has to be present on all or no VLANs")

            ipam = get_ipam(new_asset, username=username)
            for key, vlans in [('vlan', [new_asset['provision']['vlan']]), ('vlans', new_asset['provision'].get('vlans', []))]:
                for vlan in vlans:
                    if 'cidr' not in vlan:
                        raise serializers.ValidationError("provision__%s__cidr is required" % (key))
                    try:
                        address, length = vlan['cidr'].split("/", 1)
                        length = int(length)
                        network = NetworkSerializer.get(vrf=vlan.get('vrf', 0), network=address, length=length)
                    except RethinkObjectNotFound:
                        raise serializers.ValidationError("cidr='%s' is not a valid choice for provision__%s" % (vlan['cidr'], key))
                    except ValueError:
                        raise serializers.ValidationError("cidr='%s' is invalid, not a CIDR value" % vlan['cidr'])
                    if remote_domain not in network['domains']:
                        raise serializers.ValidationError("domain='%s' cidr='%s' is not a valid choice for provision__%s" % (remote_domain, vlan['cidr'], key))
                    if new_asset['owner'] not in network.get('permissions', {}).get('create', []) + network.get('permissions', {}).get('write', []):
                        raise serializers.ValidationError("owner='%s' does not have permission for network domain='%s' cidr='%s'" % (new_asset['owner'], remote_domain, vlan['cidr']))
                    if key == 'vlan' or 'suffix' in vlan:
                        kwargs = {}
                        if 'ip' in vlan and ipv4_network_contains(vlan['cidr'], vlan['ip']):
                            kwargs['ip'] = vlan['ip']
                        shortname, domain = new_asset['provision']['hostname'].split(".", 1)
                        hostname = "%s%s.%s" % (shortname, vlan.get('suffix', ''), domain)
                        try:
                            ipam.ip_address_validate(network, new_asset, hostname, **kwargs)
                        except Exception as e:
                            raise serializers.ValidationError("cidr='%s' is not allocatable: %s" % (vlan['cidr'], str(e)))

            if new_asset['asset_type'] == 'vm':
                for name, disk in new_asset['provision']['storage'].items():
                    for field in ('class', 'by_id', 'size'):
                        if field not in disk:
                            raise serializers.ValidationError("provision__storage__%s__%s is required" % (name, field))
                    if ('storage' not in self.parent_asset or
                        len(self.parent_asset['storage']) < 1 or
                        disk['class'] not in self.parent_asset['storage'][0]['datastores']):
                        raise serializers.ValidationError("provision__storage__%s__class='%s' is not a valid choice (%s)" %
                            (name, disk['class'], ", ".join(self.parent_asset['storage'][0]['datastores'].keys())))
                    if not isinstance(disk['size'], int):
                        raise serializers.ValidationError("provision__storage__%s__size=%r is not an integer" % (name, disk['size']))

                if 'owner' in new_asset and self.parent_asset['owner'] != new_asset['owner']:
                    try:
                        quotas = QuotaSerializer.get(group=new_asset['owner'])
                    except RethinkObjectNotFound:
                        quotas = QuotaSerializer.get(group="_default_")
                    vms = list(AssetSerializer.filter(lambda asset: ((asset['owner'] == new_asset['owner']) & (asset['asset_type'] == 'vm') & (asset['state'] != 'deleted')) & (r.table("assets").get_all(asset['parent'], index="service_tag").nth(0)['owner'] != asset['owner'])))
                    if self.instance is None:
                        if len(vms) >= quotas['vms']:
                            raise serializers.ValidationError("You have exceeded your VM quota of %s (%d VMs)" % (quotas['vms'], len(vms)))
                        old_vcpus = 0
                        old_ram = 0
                        old_disk = 0
                    else:
                        old_vcpus = len(self.instance.get('cpu', ['vCPU']))
                        old_ram = self.instance.get('ram', {}).get('total', 0)
                        old_disk = sum([x['capacity'] for x in self.instance.get('storage', [])])
                    total_vcpus = sum([len(vm.get('cpu', ['vCPU'])) for vm in vms])
                    total_ram = sum([vm.get('ram', {}).get('total', 0) for vm in vms])
                    total_disk = sum([sum([x['capacity'] for x in vm.get('storage', [])]) for vm in vms])
                    if 'provision' in data and data['provision'].keys() != ['hostname']:
                        for key in ('cpus', 'ram'):
                            if key not in new_asset['provision']:
                                raise serializers.ValidationError("provision__%s is required" % key)
                            if not isinstance(new_asset['provision'][key], int):
                                raise serializers.ValidationError("provision__%s is not an integer" % key)

                        vm_disk = sum([x['size'] for x in new_asset['provision']['storage'].values()])
                        if new_asset['provision']['cpus'] > quotas['vm_vcpus']:
                            raise serializers.ValidationError("You are limited to %s vCPUs per VM" % quotas['vm_vcpus'])
                        if new_asset['provision']['ram'] > quotas['vm_ram']:
                            raise serializers.ValidationError("You are limited to %s RAM per VM" % quotas['vm_ram'])
                        if vm_disk > quotas['vm_disk']:
                            raise serializers.ValidationError("You are limited to %s GB disk per VM" % (quotas['vm_disk'] / 1000000000))
                        if (total_vcpus - old_vcpus + new_asset['provision']['cpus']) > quotas['total_vcpus']:
                            raise serializers.ValidationError("You have exceeded your vCPU quota of %s (%d used)" % (quotas['total_vcpus'], total_vcpus))
                        if (total_ram - old_ram + new_asset['provision']['ram']) > quotas['total_ram']:
                            raise serializers.ValidationError("You have exceeded your vRAM quota of %s (%d used)" % (quotas['total_ram'], total_ram))
                        if (total_disk - old_disk + vm_disk) > quotas['total_disk']:
                            raise serializers.ValidationError("You have exceeded your disk quota of %s (%d used)" % (quotas['total_disk'], total_disk))
                        if (new_asset['provision']['ram'] % (4*1024*1024)) != 0:
                            raise serializers.ValidationError("RAM amount not divisible by 4 MiB")

                        minimum_ram = os.get('minimums', {}).get('ram', 0)
                        minimum_disk = os.get('minimums', {}).get('storage', 0)
                        if minimum_ram > new_asset['provision']['ram']:
                            raise serializers.ValidationError("RAM amount is less than the minimum %d" % minimum_ram)
                        if minimum_disk > new_asset['provision']['storage']['os']['size']:
                            raise serializers.ValidationError("Disk size is less than the minimum %d" % minimum_disk)

            elif new_asset['asset_type'] == 'server':
                pdisks = dict([(controller['id'], [pdisk['id'] for pdisk in controller['pdisks']]) for controller in new_asset['storage']])
                for name, disk in new_asset['provision']['storage'].items():
                    for field in ('raid', 'pdisks'):
                        if field not in disk:
                             raise serializers.ValidationError("provision__storage__%s__%s is required" % (name, field))
                    if not all(['controller_id' in pdisk for pdisk in disk['pdisks']]) and 'controller_id' not in disk:
                        raise serializers.ValidationError("provision__storage__%s__controller_id is required" % (name))
                    for pdisk in disk['pdisks']:
                        controller_id = pdisk.get('controller_id', disk.get('controller_id'))
                        if controller_id not in pdisks:
                            raise serializers.ValidationError("provision__storage__%s__controller_id='%s' is not a valid choice (%s)" %
                                (name, controller_id, ", ".join(pdisks.keys())))
                        if 'id' not in pdisk:
                            raise serializers.ValidationError("provision__storage__%s__pdisks__id is required" % name)
                        if pdisk['id'] not in pdisks[controller_id]:
                            raise serializers.ValidationError("provision__storage__%s__pdisks__id='%s' is not a valid choice" %
                                (name, pdisk['id']))
                        # This ensures the same disk can only be used once
                        pdisks[controller_id].remove(pdisk['id'])
        else:
            if 'provision' in diff and new_asset['state'] == "in-use" and self.instance is not None and (new_asset['asset_type'] != "vm" or username is not None) and not self.instance.get('provisioning', False) and not new_asset.get('provisioning', False) and not new_asset.get('decommissioning', False):
                raise serializers.ValidationError("cannot update 'provision' without provisioning set")
        return data

    def create_link(self, instance):
        return reverse('socrates_api:asset_detail_id', kwargs={'id': instance['id']}, request=self.context.get('request'))


class OperatingSystemSerializer(RethinkSerializer):
    id = serializers.CharField(required=False)
    name = serializers.CharField(required=True)
    ipxe_script = serializers.CharField(required=True, trim_whitespace=False)
    kickstart = serializers.CharField(required=False, trim_whitespace=False)
    ids = serializers.DictField(required=False)
    minimums = serializers.DictField(required=False)
    tags = serializers.DictField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'os'
        slug_field = 'name'
        indices = ['name']

    def create_link(self, instance):
        return reverse('socrates_api:os_detail', kwargs={'slug': instance['name']}, request=self.context.get('request'))

class FirewallAddressSerializer(serializers.Serializer):
    negated = serializers.BooleanField(required=False)
    vrf = serializers.IntegerField(required=False)
    address = serializers.IPAddressField(required=False)
    length = serializers.IntegerField(required=False)
    address_group = serializers.CharField(required=False)
    fqdn = serializers.CharField(required=False)
    user_groups = serializers.ListField(child=serializers.CharField(validators=[validate_group_name]), required=False)

    def validate_address_group(self, address_group):
        if address_group:
            try:
                FirewallAddressGroupSerializer.get(name=address_group)
            except RethinkObjectNotFound:
                raise serializers.ValidationError("address_group='%s' does not exist" % address_group)
        return address_group

    def validate(self, data):
        data = super(FirewallAddressSerializer, self).validate(data)
        address_types = sum([x in data for x in ['address', 'address_group', 'fqdn', 'user_groups']])
        if address_types == 0:
            raise serializers.ValidationError("address, address_group, fqdn, or user_groups is required")
        if address_types > 1:
            raise serializers.ValidationError("only one of address, address_group, fqdn, and user_groups can be set")
        return data

class FirewallAddressGroupSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False)
    name = serializers.CharField(required=True)
    addresses = serializers.ListField(child=FirewallAddressSerializer(), required=True)
    permissions = PermissionsSerializer(required=False)
    tags = serializers.DictField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'firewall_address_group'
        slug_field = 'name'
        unique = ['name']
        indices = [
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]

    def create(self, validated_data):
        from socrates_api.tasks import firewall_add_group
        group = super(FirewallAddressGroupSerializer, self).create(validated_data)
        firewall_add_group.apply_async((group,))
        return group

    def update(self, instance, validated_data):
        from socrates_api.tasks import firewall_update_group
        group = super(FirewallAddressGroupSerializer, self).update(instance, validated_data)
        firewall_update_group.apply_async((group,))
        return group

    def delete(self):
        from socrates_api.tasks import firewall_remove_group
        firewall_remove_group.apply_async((self.instance,))
        return super(FirewallAddressGroupSerializer, self).delete()

    def create_link(self, instance):
        return reverse('socrates_api:firewall_addressgroup_detail', kwargs={'slug': instance['name']}, request=self.context.get('request'))

def validate_port_number(port):
    if 0 < port <= 65535:
        return True
    raise serializers.ValidationError('{0} is outside valid port numbers 0, 65535'.format(port))

def validate_firewall_ports(ports):
    for port in ports:
        if not isinstance(port, (dict, int)):
            raise serializers.ValidationError('Invalid type for port {0}'.format(port))
        if isinstance(port, int):
            validate_port_number(port)
            continue
        if isinstance(port, dict):
            for s in ['start', 'end']:
                if s not in port.keys():
                    raise serializers.ValidationError('{0} missing in port range'.format(s))
            if not all([isinstance(port['start'], int), isinstance(port['end'], int)]):
                raise serializers.ValidationError('Invalid type in {0}'.format(port))
            if all([validate_port_number(port['start']), validate_port_number(port['end'])]):
                if port['start'] >= port['end']:
                    raise serializers.ValidationError('start port cannot be higher than end port')
                continue
            raise serializers.ValidationError('{0} is invalid'.format(port))
    return ports

class FirewallRuleSerializer(serializers.Serializer):
    type = serializers.ChoiceField(required=True, choices=['ingress', 'egress'])
    expiration = serializers.DateTimeField(required=False)
    protocol = serializers.ChoiceField(required=True, choices=['icmp', 'tcp', 'udp'])
    action = serializers.ChoiceField(required=False, choices=['accept', 'deny'])
    source_addresses = serializers.ListField(child=FirewallAddressSerializer(), required=False)
    source_ports = serializers.ListField(validators=[validate_firewall_ports], required=False)
    destination_addresses = serializers.ListField(child=FirewallAddressSerializer(), required=False)
    destination_ports = serializers.ListField(validators=[validate_firewall_ports], required=False)

def validate_ruleset_name(name):
    try:
        FirewallRuleSetSerializer.get(name=name)
    except RethinkObjectNotFound:
        raise serializers.ValidationError("ruleset '%s' does not exist" % name)
    return name

class FirewallRuleSetSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False)
    name = serializers.CharField(required=True)
    public = serializers.BooleanField(required=False)
    permissions = PermissionsSerializer(required=False)
    rulesets = serializers.ListField(child=serializers.CharField(validators=[validate_ruleset_name]), required=False)
    rules = serializers.ListField(child=FirewallRuleSerializer(), required=True)
    tags = serializers.DictField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'firewall_rule_set'
        slug_field = 'name'
        unique = ['name']
        indices = [
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]

    def update(self, instance, data):
        from socrates_api.tasks import firewall_apply_all
        ruleset = super(FirewallRuleSetSerializer, self).update(instance, data)
        firewall_apply_all.apply_async()
        return ruleset

    def create_link(self, instance):
        return reverse('socrates_api:firewall_ruleset_detail', kwargs={'slug': instance['name']}, request=self.context.get('request'))

class NetworkDomainSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    vlan_id = serializers.IntegerField(required=True)
    data = serializers.DictField(required=False)

class NetworkSerializer(NeedsReviewMixin, HistorySerializerMixin):
    id = serializers.CharField(required=False)
    vrf = serializers.IntegerField(required=True)
    network = serializers.IPAddressField(required=True)
    length = serializers.IntegerField(required=True)
    is_installation_net = serializers.BooleanField(required=False)
    permissions = PermissionsSerializer(required=False)
    needs_review = serializers.BooleanField(required=False)
    domains = serializers.DictField(child=NetworkDomainSerializer(), required=True)
    ruleset = serializers.CharField(validators=[validate_ruleset_name], required=False)
    tags = serializers.DictField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'networks'
        slug_field = 'vrf_network_length'
        indices = [
            ('vrf_network_length', (r.row['vrf'], r.row['network'], r.row['length'])),
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]
        unique_together = [
            ('vrf', 'network', 'length'),
        ]
        needs_review_field = 'needs_review'

    def create(self, validated_data):
        from socrates_api.tasks import add_network
        network = super(NetworkSerializer, self).create(validated_data)
        if 'domains' in validated_data:
            self._manage_network_domains(network, validated_data['domains'].keys(), add_network)
        return network

    def update(self, instance, validated_data):
        from socrates_api.tasks import add_network, remove_network, asset_get, reconfigure_network_port, firewall_apply
        network = super(NetworkSerializer, self).update(instance, validated_data)
        if 'domains' in validated_data and instance['domains'] != network['domains']:
            old_domains = set(instance['domains'].keys())
            new_domains = set(network['domains'].keys())
            # Added domains
            self._manage_network_domains(network, new_domains - old_domains, add_network)
            # Removed domains
            self._manage_network_domains(instance, old_domains - new_domains, remove_network)
        if 'ruleset' in validated_data and instance.get('ruleset', None) != network['ruleset']:
            for domain in network.get('domains', {}).keys():
                try:
                    asset = next(AssetSerializer.filter({
                        'state': 'in-use',
                        'asset_type': 'network',
                        'asset_subtype': 'firewall',
                        'network': {'device': domain},
                    }))
                except:
                    pass
                else:
                    firewall_apply.apply_async((asset,))
        return network

    def delete(self):
        from socrates_api.tasks import remove_network
        if 'domains' in self.instance:
            self._manage_network_domains(self.instance, self.instance['domains'].keys(), remove_network)
        return super(NetworkSerializer, self).delete()

    def _manage_network_domains(self, network, domains, task=None):
        from socrates_api.tasks import asset_get, reconfigure_network_port
        from django_rethink.tasks import rethinkdb_lock, rethinkdb_unlock
        if not hasattr(self, 'vmclusters'):
            self.vmclusters = dict(map(lambda x: (x['service_tag'], x), AssetSerializer.filter(state='in-use', asset_type='vmcluster')))
        if not hasattr(self, 'switches'):
            self.switches = {}
            for switch in AssetSerializer.filter(r.row.has_fields({'switch': {'domain': True}})):
                if switch['switch']['domain'] not in self.switches:
                    self.switches[switch['switch']['domain']] = []
                self.switches[switch['switch']['domain']].append(switch)
        if not hasattr(self, 'firewalls'):
            self.firewalls = {}
            for firewall in AssetSerializer.filter(r.row.has_fields({'network': {'device': True}, 'url': True})):
                if firewall['network']['device'] not in self.firewalls:
                    self.firewalls[firewall['network']['device']] = []
                self.firewalls[firewall['network']['device']].append(firewall)

        token = str(uuid.uuid4())
        pre_tasks = [rethinkdb_lock.si("network-management", token=token)]
        tasks = []
        post_tasks = []
        for domain in domains:
            if domain in self.vmclusters:
                tasks.append(task.si(self.vmclusters[domain], network))
                for hypervisor in self.vmclusters[domain]['hypervisors']:
                    tasks.append(asset_get.si(hypervisor))
                    tasks.append(reconfigure_network_port.s())
            elif domain in self.switches:
                t = task.si(self.switches[domain][0], network)
                if task.__name__ == 'remove_network':
                    post_tasks.append(t)
                else:
                    pre_tasks.append(t)
                for switch in self.switches[domain]:
                    if 'nics' in switch:
                        tasks.append(reconfigure_network_port.si(switch))
            elif domain in self.firewalls:
                for firewall in self.firewalls[domain]:
                    tasks.append(task.si(firewall, network))
                    tasks.append(reconfigure_network_port.si(firewall))

        post_tasks.append(rethinkdb_unlock.si(name="network-management", token=token))

        tasks = pre_tasks + tasks + post_tasks

        if len(tasks) > 2:
            chain(*tasks).apply_async()

    def validate_domains(self, value):
        if len(value) == 0:
            raise serializers.ValidationError("no domains specified!")
        for domain in value.keys():
            for g in [
                    lambda d: AssetSerializer.get(asset_type="vmcluster", service_tag=d),
                    lambda d: AssetSerializer.get({"switch": {"domain": d}}),
                    lambda d: AssetSerializer.get({"network": {"device": d}}),
                ]:
                try:
                    g(domain)
                    break
                except RethinkObjectNotFound:
                    continue
                except RethinkMultipleObjectsFound:
                    break
            else:
                raise serializers.ValidationError("domain=%r is unknown" % domain)
        return value
    @classmethod
    def get_by_domain_install(cls, domain):
        ret = cls.get(lambda network: network['domains'].has_fields(domain) & network['is_installation_net'])
        try:
            ret['asset_domain'] = ret['domains'][domain]
            ret['asset_name'] = ret['asset_domain']['name']
        except IndexError:
            pass
        return ret

    @classmethod
    def get_by_domain_id(cls, domain, vlan_id):
        return cls.get(lambda network: network['domains'][domain]['vlan_id'] == vlan_id)
    @classmethod
    def get_by_asset_vlan(cls, asset=None, vlan=None, domain=None):
        if domain is None:
            domain = jsonpath_rw_ext.parse('$.nics[*].remote.domain').find(asset)[0].value
        if 'cidr' in vlan:
            address, length = vlan['cidr'].split("/")
            length = int(length)
            ret = cls.get(vrf=vlan.get('vrf', 0), network=address, length=length)
        else:
            raise Exception("unable to find network for vlan %r" % vlan)
        try:
            ret['asset_domain'] = ret['domains'][domain]
            ret['asset_name'] = ret['asset_domain']['name']
        except KeyError:
            pass
        return ret

    @classmethod
    def get_by_ip(cls, ip):
        return cls.get(lambda n:
            r.ip_prefix_contains(
                r.ip_prefix(n['network'], n['length']),
                r.ip_address(ip)
            )
        )

    def create_link(self, instance):
        return reverse('socrates_api:network_detail', kwargs={
            'vrf': instance['vrf'],
            'network': instance['network'],
            'length': instance['length']
        }, request=self.context.get('request'))

class QuotaSerializer(RethinkSerializer):
    id = serializers.CharField(required=False)
    group = serializers.CharField(required=True, validators=[validate_group_name])
    vms = serializers.IntegerField(required=True)
    vm_vcpus = serializers.IntegerField(required=True)
    total_vcpus = serializers.IntegerField(required=True)
    vm_ram = serializers.IntegerField(required=True)
    total_ram = serializers.IntegerField(required=True)
    vm_disk = serializers.IntegerField(required=True)
    total_disk = serializers.IntegerField(required=True)
    tags = serializers.DictField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'quotas'
        slug_field = 'group'
        indices = ['group']

    def create_link(self, instance):
        return reverse('socrates_api:quota_detail', kwargs={'slug': instance['group']}, request=self.context.get('request'))

EVENT_TYPES = ['ready', 'provisioned', 'maintenance_start', 'maintenance_end', 'deleted', 'reprovisioned']
class EventSerializer(RethinkSerializer):
    id = serializers.CharField(required=False)
    event = serializers.ChoiceField(choices=EVENT_TYPES, required=True)
    asset_id = serializers.CharField(required=True)
    service_tag = serializers.CharField(required=True)
    timestamp = serializers.DateTimeField(required=True)
    class Meta(RethinkSerializer.Meta):
        table_name = 'events'
        indices = ['service_tag', 'asset_id']

class CeleryTaskResultSerializer(RethinkSerializer):
    id = serializers.CharField(read_only=True)
    status = serializers.CharField()
    result = serializers.ReadOnlyField()
    date_done = serializers.DateTimeField(read_only=True)
    traceback = serializers.CharField(allow_null=True, default=None, read_only=True)
    children = serializers.ListField(required=False, read_only=True)
    ops_acked = serializers.BooleanField(required=False)
    task = serializers.ReadOnlyField()

    class Meta(RethinkSerializer.Meta):
        table_name = 'celery_taskmeta'

class CeleryTaskQueueSerializer(RethinkSerializer):
    id = serializers.CharField(read_only=True)
    queue = serializers.CharField(read_only=True)
    timestamp = serializers.DateTimeField(read_only=True)
    payload = serializers.DictField(read_only=True)
    claimed_by = serializers.ListField(child=serializers.CharField(), required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'celery_taskqueue'

LOAD_BALANCING_METHODS = [
    "round_robin", "ratio_member", "least_connection_member",
    "observed_member", "predictive_member", "ratio_node_address",
    "least_connection_node_address", "fastest_node_address",
    "observed_node_address", "predictive_node_address", "dynamic_ratio",
    "fastest_app_response", "least_sessions", "dynamic_ratio_member",
    "l3_addr", "weighted_least_connection_member",
    "weighted_least_connection_node_address", "ratio_session",
    "ratio_least_connection_member", "ratio_least_connection_node_address",
    "first",
]

class LoadBalancerMemberSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    port = serializers.IntegerField(required=True)
    ratio = serializers.IntegerField(required=False)
    priority = serializers.IntegerField(required=False)
    group = serializers.CharField(required=False)

class LoadBalancerIRulePoolSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    members = serializers.ListField(child=LoadBalancerMemberSerializer(), required=True)
    monitors = serializers.ListField(child=serializers.CharField(), required=False)
    lb_method = serializers.ChoiceField(choices=LOAD_BALANCING_METHODS, required=False)

class LoadBalancerIRuleSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False)
    name = serializers.CharField(required=True)
    code = serializers.CharField(required=True)
    pools = serializers.ListField(child=LoadBalancerIRulePoolSerializer(), required=False)
    permissions = PermissionsSerializer(required=False)
    tags = serializers.DictField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'load_balancer_irule'
        slug_field = 'name'
        unique = [
            'name',
        ]
        indices = [
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]

    def update(self, instance, data):
        from socrates_api.tasks import update_load_balancer
        load_balancer_irule = super(LoadBalancerIRuleSerializer, self).update(instance, data)
        load_balancers = LoadBalancerSerializer.filter(
            lambda lb: lb.has_fields('irules') &
                lb['irules'].contains(instance['name'])
        )
        for load_balancer in load_balancers:
            update_load_balancer.apply_async((load_balancer,))
        return load_balancer_irule

    def create_link(self, instance):
        return reverse('socrates_api:loadbalancer_irule_detail', kwargs={'slug': instance['name']}, request=self.context.get('request'))

def validate_irule_name(name):
    try:
        LoadBalancerIRuleSerializer.get(name=name)
    except RethinkObjectNotFound:
        raise serializers.ValidationError("irule '%s' not found" % name)
    return name

def validate_load_balancer_profile(value):
    if not re.match(getattr(settings, 'SOCRATES_LB_PROFILE_RE', '.'), value):
        raise serializers.ValidationError("invalid profile specified: %s" % value)
    return value

def validate_load_balancer_monitor(value):
    if not re.match(getattr(settings, 'SOCRATES_LB_MONITOR_RE', '.'), value):
        raise serializers.ValidationError("invalid monitor specified: %s" % value)
    return value

class LBURLValidator(URLValidator):
    from django.core.validators import _lazy_re_compile
    hostname_re = '(' + URLValidator.hostname_re + '|*)'
    # The below is from URLValidator
    regex = _lazy_re_compile(
        r'^(?:[a-z0-9\.\-\+]*)://'  # scheme is validated separately
        r'(?:[^\s:@/]+(?::[^\s:@/]*)?@)?'  # user:pass authentication
        r'(?:' + URLValidator.ipv4_re + '|' + URLValidator.ipv6_re + '|' + URLValidator.host_re + ')'
        r'(?::\d{2,5})?'  # port
        r'(?:[/?#][^\s]*)?'  # resource path
        r'\Z', re.IGNORECASE)

class LoadBalancerGroupSerializer(serializers.Serializer):
    name = serializers.CharField(required=True)
    ratio = serializers.IntegerField(min_value=0, max_value=100, required=True)

class LoadBalancerSerializer(HistorySerializerMixin):
    id = serializers.CharField(required=False)
    cluster = serializers.CharField(required=True)
    name = serializers.CharField(required=True)
    members = serializers.ListField(child=LoadBalancerMemberSerializer(), required=True)
    protocol = serializers.ChoiceField(choices=['http', 'tcp', 'udp'], required=True)
    ip = serializers.IPAddressField(required=False)
    port = serializers.IntegerField(min_value=1, max_value=65535, required=False)
    endpoints = serializers.ListField(child=serializers.CharField(validators=[LBURLValidator]), required=False)
    profiles = serializers.ListField(child=serializers.CharField(validators=[validate_load_balancer_profile]), required=False)
    monitors = serializers.ListField(child=serializers.CharField(validators=[validate_load_balancer_monitor]), required=False)
    irules = serializers.ListField(child=serializers.CharField(validators=[validate_irule_name]), required=False)
    default_persistence_profile = serializers.CharField(required=False)
    fallback_persistence_profile = serializers.CharField(required=False)
    lb_method = serializers.ChoiceField(choices=LOAD_BALANCING_METHODS, required=False)
    permissions = PermissionsSerializer(required=False)
    groups = serializers.ListField(child=LoadBalancerGroupSerializer(), required=False)
    tags = serializers.DictField(required=False)

    class Meta(RethinkSerializer.Meta):
        table_name = 'load_balancer'
        slug_field = 'name'
        unique = [
            'name'
        ]
        indices = [
            ('ip_protocol_port', (r.row['ip'], r.row['protocol'], r.row['port'])),
            ('cluster_endpoint', lambda lb: lb['endpoints'].map(lambda ep: [lb['cluster'], ep]), {'multi': True}),
            ('permissions_read', r.row['permissions']['read'], {'multi': True}),
            ('permissions_create', r.row['permissions']['create'], {'multi': True}),
            ('permissions_write', r.row['permissions']['write'], {'multi': True}),
        ]

    def validate_cluster(self, value):
        try:
            AssetSerializer.get(asset_type="lbcluster", service_tag=value)
        except RethinkObjectNotFound:
            raise serializers.ValidationError("cluster='%s' was not found" % value)
        return value

    def validate_ip(self, value):
        from socrates_api.tasks import get_ipam
        ipam = get_ipam(None, username=self.get_username())
        try:
            ipam.ip_address_get({}, None, value)
        except Exception as e:
            raise serializers.ValidationError("unable to find reservation for service IP: %s" % str(e))
        return value

    def validate_name(self, value):
        if self.instance is not None and self.instance['name'] != value:
            raise serializers.ValidationError("you cannot change the name (was %s, new %s)" % (self.instance['name'], value))
        return value

    def validate(self, data):
        if data.get('protocol', self.instance.get('protocol', None) if self.instance is not None else None) == 'http':
            cluster = data.get('cluster', self.instance.get('cluster', None) if self.instance is not None else None)
            endpoints = [[cluster, ep] for ep in data.get('endpoints', self.instance.get('endpoints', None) if self.instance is not None else None)]
            query = r.table(self.Meta.table_name).get_all(*endpoints, index='cluster_endpoint')
            msg = "combination of cluster, protocol, and endpoints is not unique"
        else:
            destination = [data.get(field, self.instance.get(field, None) if self.instance is not None else None) for field in ('ip', 'protocol', 'port')]
            query = r.table(self.Meta.table_name).get_all(destination, index='ip_protocol_port')
            msg = "combination of ip, protocol, and port is not unique"

        if self.instance is not None:
            query = query.filter(r.row[self.Meta.pk_field] != self.instance[self.Meta.pk_field])
        matched = query.count().run(self.conn)
        if matched > 0:
            raise serializers.ValidationError(msg)
        return data

    def create(self, data):
        from socrates_api.tasks import add_load_balancer
        load_balancer = super(LoadBalancerSerializer, self).create(data)
        add_load_balancer.apply_async((load_balancer,))
        return load_balancer

    def update(self, instance, data):
        from socrates_api.tasks import update_load_balancer
        load_balancer = super(LoadBalancerSerializer, self).update(instance, data)
        update_load_balancer.apply_async((load_balancer,))
        return load_balancer

    def delete(self):
        from socrates_api.tasks import remove_load_balancer
        remove_load_balancer.apply_async((self.instance,))
        return super(LoadBalancerSerializer, self).delete()

    def create_link(self, instance):
        return reverse('socrates_api:loadbalancer_detail', kwargs={'slug': instance['name']}, request=self.context.get('request'))
