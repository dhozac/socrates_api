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
import requests
import netaddr

class IPAMIPNotFoundException(Exception):
    pass

class IPAM(object):
    def __init__(self, settings):
        self.settings = settings

    def ip_prefix_get(self, network):
        raise Exception("must define ip_prefix_get")

    def ip_address_validate(self, network, asset, hostname, mac=None, ip=None):
        raise Exception("must define ip_address_validate")

    def ip_address_allocate(self, network, asset, hostname, mac=None, ip=None):
        raise Exception("must define ip_address_allocate")

    def ip_address_get(self, network, asset, ip):
        raise Exception("must define ip_address_get")

    def ip_address_remove(self, network, asset, hostname, ip):
        raise Exception("must define ip_address_remove")

    def ip_address_update(self, network, asset, hostname, ip):
        raise Exception("must define ip_address_update")

    def cname_add(self, asset, hostname, destination):
        raise Exception("must define cname_add")

    def cname_remove(self, asset, hostname):
        raise Exception("must define cname_remove")

    def commit(self):
        pass

class BonkIPAM(IPAM):
    def __init__(self, settings, username):
        self.url = settings.BONK_URL
        self.auth = settings.BONK_AUTH
        self.username = username

    def _make_request(self, method, path, data=None, params=None):
        response = getattr(requests, method.lower())(
            self.url + path,
            auth=self.auth,
            json=data,
            params=params,
            headers={'X-On-Behalf-Of': self.username},
        )
        return response

    def ip_prefix_get(self, network):
        response = self._make_request('GET', "/prefix/%d/%s/%d/" % (
            network.get('vrf', 0), network['network'], network['length']))
        if response.status_code != 200:
            raise Exception("failed to get prefix from bonk %d: %r" % (response.status_code, response.json()))
        prefix = response.json()
        if 'dhcp' in prefix and 'server_set' in prefix['dhcp']:
            response = self._make_request('GET', "/dhcpserverset/%s/" %
                prefix['dhcp']['server_set'])
            if response.status_code != 200:
                raise Exception("failed to get DHCP server set from bonk %d: %r" %
                    (response.status_code, response.json()))
            prefix['dhcp']['servers'] = response.json()['servers']
        return prefix

    def ip_address_validate(self, network, asset, hostname, mac=None, ip=None):
        return self.ip_address_allocate(network, asset, hostname, mac, ip, True)

    def ip_address_allocate(self, network, asset, hostname, mac=None, ip=None, dryrun=False):
        data = {
            'state': 'allocated',
            'name': hostname,
            'reference': asset['service_tag'],
            'permissions': {
                'write': asset.get('managers', []) + ([asset['owner']] if asset.get('owner_can_login', True) else [])
            },
        }
        if mac is not None:
            data['dhcp_mac'] = mac
        if ip is not None:
            data['ip'] = ip
        if dryrun:
            data['dryrun'] = True
        response = self._make_request('GET',
            "/address/", params={
                'name': hostname
            })
        if response.status_code != 200:
            raise Exception("failed to check bonk for name %d: %r" %
                            (response.status_code, response.content))
        existing = response.json()
        if ip:
            response = self._make_request('GET', "/address/%d/%s/" %
                                          (network.get('vrf', 0), ip))
            if response.status_code == 200:
                existing.append(response.json())
            elif response.status_code == 404:
                pass
            else:
                raise Exception("failed to check bonk for address %d: %r" %
                                (response.status_code, response.content))
        if len(existing) > 0:
            if 'reference' in existing[0] and existing[0]['reference'] == data['reference']:
                ip = existing[0]['ip']
                if netaddr.IPAddress(ip) in netaddr.IPNetwork("%s/%d" % (network['network'], network['length'])):
                    return ip
                if not dryrun:
                    response = self._make_request('DELETE',
                        "/address/%d/%s" % (existing[0]['vrf'], existing[0]['ip']),
                        data={}
                    )
                    if response.status_code != 204:
                        raise Exception("failed to delete %s from bonk %d: %s" %
                                        (existing[0]['ip'], response.status_code,
                                         response.content))
                else:
                    data['id'] = existing[0]['id']
            else:
                raise Exception("%s is already in use, reference set to %s" %
                                (hostname, existing[0].get('reference', None)))

        response = self._make_request('POST',
            "/prefix/%d/%s/%d/allocate/" % (
                network.get('vrf', 0),
                network['network'],
                network['length'],
            ), data=data)
        if dryrun and response.status_code == 204:
            return True
        if response.status_code != 201:
            raise Exception("failed to allocate IP address in bonk %d: %r" % (response.status_code, response.content))
        return response.json()['ip']

    def ip_address_get(self, network, asset, ip):
        response = self._make_request('GET',
            "/address/%d/%s/" % (
                network.get('vrf', 0),
                ip,
            ))
        if response.status_code == 200:
            return response.json()
        elif response.status_code == 404:
            raise IPAMIPNotFoundException(ip)
        else:
            raise Exception("failed to get IP address from bonk %d: %r" % (response.status_code, response.content))

    def ip_address_remove(self, network, asset, hostname, ip):
        response = self._make_request('GET',
            "/address/", params={
                'name': hostname
            })
        if response.status_code != 200:
            raise Exception("failed to check bonk for address %d: %r" %
                            (response.status_code, response.content))
        existing = response.json()
        if len(existing) > 0:
            response = self._make_request('DELETE',
                "/address/%d/%s/" % (
                    existing[0]['vrf'],
                    existing[0]['ip'],
                ), data={'log': asset['service_tag']})
            if response.status_code != 204:
                raise Exception("failed to delete IP address from bonk %d: %r" %
                                (response.status_code, response.content))

    def ip_address_update(self, network, asset, hostname, ip):
        response = self._make_request('GET',
            "/address/%d/%s/" % (
                network.get('vrf', 0),
                ip,
            ))
        if response.status_code != 200:
            raise Exception("failed to find IP address in bonk %d: %r" %
                            (response.status_code, response.content))
        address = response.json()
        response = self._make_request('PATCH',
            "/address/%d/%s/" % (
                network.get('vrf', 0),
                ip,
            ), data={
                'log': asset['service_tag'],
                'name': hostname,
                'version': address['version'],
            })
        if response.status_code != 200:
            raise Exception("failed to update IP address in bonk %d: %r" %
                            (response.status_code, response.content))

    def cname_add(self, asset, hostname, destination):
        short, zone = hostname.split(".", 1)
        data = {
            'reference': asset['service_tag'],
            'zone': zone,
            'name': hostname,
            'type': 'CNAME',
            'value': [destination + '.'],
            'permissions': {
                'write': asset.get('managers', []) +
                    ([asset['owner']] if asset.get('owner_can_login', True) else [])
            },
        }
        response = self._make_request('GET',
            "/record/%s/CNAME/" % hostname)
        if response.status_code == 200:
            existing = response.json()
            if len(existing) > 0:
                if ('reference' in existing and
                    existing['reference'] == data['reference']):
                    if existing['value'] == data['value']:
                        return False
                else:
                    raise Exception("CNAME exists pointing to %s by %s" %
                                    (existing['value'], existing['reference']))
        response = self._make_request('POST',
            "/record/",
            data=data)
        if response.status_code != 201:
            raise Exception("failed to create CNAME in bonk %d: %r" %
                            (response.status_code, response.content))
        return True

    def cname_remove(self, asset, hostname):
        response = self._make_request('DELETE',
            "/record/%s/CNAME/" % hostname,
            data={
                'log': asset['service_tag'],
            })
        if response.status_code not in (204, 404):
            raise Exception("failed to remove CNAME from bonk %d: %r" %
                            (response.status_code, response.content))
