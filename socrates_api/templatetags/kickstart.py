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
from django import template
from django.template.defaulttags import URLNode, url
from netaddr import IPNetwork
import requests
import logging
from socrates_api.serializers import *
from socrates_api.tasks import get_ipam

register = template.Library()
logger = logging.getLogger("socrates_api.templatetags.kickstart")

@register.filter
def short_hostname(value):
    return value.split(".", 1)[0]

class AbsoluteURL(str):
    pass

class AbsoluteURLNode(URLNode):
    def render(self, context):
        asvar, self.asvar = self.asvar, None
        path = super(AbsoluteURLNode, self).render(context)
        request_obj = context['request']
        abs_url = AbsoluteURL(request_obj.build_absolute_uri(path))

        if not asvar:
            return str(abs_url)
        else:
            if path == request_obj.path:
                abs_url.active = 'active'
            else:
                abs_url.active = ''
            context[asvar] = abs_url
            return ''

@register.tag
def absurl(parser, token):
    node = url(parser, token)
    return AbsoluteURLNode(
        view_name=node.view_name,
        args=node.args,
        kwargs=node.kwargs,
        asvar=node.asvar
        )

@register.simple_tag
def split_field(string, splitter, field_no):
    return string.split(splitter)[int(field_no)]

@register.filter
def software_raid_disks(asset):
    result = []
    for pdisk in asset['provision']['storage']['os']['pdisks']:
        for controller in asset['storage']:
            if controller['id'] == pdisk.get('controller_id', asset['provision']['storage']['os'].get('controller_id')):
                for disk in controller['pdisks']:
                    if disk['id'] == pdisk['id']:
                        result.append(disk)
                        break
                break
    return result

@register.filter
def cidr_to_netmask(cidr):
    net = IPNetwork(cidr)
    return str(net.netmask)

@register.filter
def bonding_config(asset):
    interfaces = {}
    bonds = []
    vlans = []
    switch = None
    for nic in asset['nics']:
        if 'remote' in nic and nic['remote']:
            interfaces[nic['name']] = dict(nic)
    ipam = get_ipam(asset, False)
    for vlan in [asset['provision']['vlan']] + asset['provision'].get('vlans', []):
        ports = vlan.get('ports', list(interfaces.keys()))
        ports.sort()
        for port in ports:
            if 'bond' not in interfaces[port]:
                interfaces[port]['bond'] = "bond%d" % len(bonds)
        if ports not in bonds:
            bonds.append(ports)
        if 'ip' in vlan:
            v = dict(vlan)
            v['network'] = NetworkSerializer.get_by_asset_vlan(asset, v)
            v['network']['ipam'] = ipam.ip_prefix_get(v['network'])
            base_if = interfaces[ports[0]]['bond']
            if len(ports) == 1:
                base_if = ports[0]
            if v.get('native', False) or len(vlans) == 0:
                v['config'] = base_if
            else:
                v['config'] = "%s.%d" % (base_if, v['network']['asset_domain']['vlan_id'])
            v['first'] = len(vlans) == 0
            vlans.append(v)

    for nic in interfaces.keys():
        if 'remote' in interfaces[nic].keys() and asset['asset_type'] == 'server':
            switch = next(AssetSerializer.filter(switch={'domain': interfaces[nic]['remote']['domain']}))
            break

    return {'interfaces': interfaces, 'vlans': vlans, 'switch': switch}

@register.simple_tag
def fetch_url(url, **kwargs):
    try:
        response = requests.get(url, params=kwargs)
        logger.info("Requesting URL %s returned %s" % (response.url, response.status_code))
        return response.status_code
    except Exception as e:
        logger.error("Failed to fetch URL %s with %r: %s" % (url, kwargs, e))
        return 500

@register.simple_tag
def http_request(url, method, params={}, json=None, headers={}):
    try:
        response = getattr(requests, method.lower())(url, params=params, json=json, headers=headers)
        logger.info("Requesting URL %s returned %s" % (response.url, response.status_code))
        return {
            'status_code': response.status_code,
            'data': response.text,
        }
    except Exception as e:
        logger.error("Failed to fetch URL %s: %s" % (url, e))
        return {
            'status_code': 500,
            'data': None,
        }

@register.simple_tag
def make_dict(**kwargs):
    return kwargs

@register.filter
def split(value, splitter):
    return value.split(splitter)
