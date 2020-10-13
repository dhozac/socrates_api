#!/usr/bin/env python
# -*- coding: utf-8 -*-

# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
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

ANSIBLE_METADATA = {
    'metadata_version': '0.1',
    'status': ['preview'],
    'supported_by': 'community'
}

DOCUMENTATION = '''
module: fortimgr_policy
short_description: add policies based on socrates firewall rulesets to fortimanager
description:
  - module generates addresses, services and policies based on socrates rulesets
  - generated polices replace current matching policies
  - be sure to read the source before using this module
requirements:
  - "python >= 3.6"
  - module_utils.network.fortimanager
author:
  - null
notes:
  - hic sunt dracones
'''

EXAMPLES = '''
---
- name: allow loadbalancers access the gooble network on 443
  fortimgr_policy:
    device_unique_name: FGxyz
    adom: the_best_adom
    vdom: awesome_vdom
    default_zone: E1M1
    networks:
      - network: 10.10.28.0
        length: 24
        ruleset: bob_rules
        domains:
          vdom-awesome_vdom:
            data:
              description: awesome-loadbalancer-network
              vdom: awesome_vdom
              zone: E1M2
      - network: 10.11.11.0
        length: 28
        ruleset: imp_rules
        domains:
          vdom-awesome_vdom:
            data:
              description: gobble-gobble-network
              vdom: awesome_vdom
              zone: E1M2
    rulesets:
      - name: bob_rules
        rules:
          - action: accept
            protocol: tcp
            type: egress
            destination_addresses:
              - address_group: some_addresses
              - address: 10.19.0.0
                length: 24
              - fqdn: bonk.fqdn
            destination_ports:
              - 443
      - name: imp_rules
        rules:
          - action: accept
            type: ingress
            protocol: tcp
            source_addresses:
              - address: 10.0.0.0
                length: 8
            destination_ports:
              - 443
    address_groups:
      - name: some_addresses
        addresses:
          - address: 10.2.1.21
            length: 32
          - address: 10.3.2.0
            length: 24
'''


def format_path_str(path, escape_map={}, overwrite_map=False):
    '''
    This just appplies an escape character translation to given string
    and return the results. Note that due to the fantastic workings
    of either the fortimanager or the fndn fortimanager helper most
    escapes need multiple raw \'s (see default translations below)
    :param path: str to escape
    :param escape_map: dict with extra escape maps
    :param overwrite_map: bool, overwrite default map with escape_map
    :returns: escaped string
    :rtype: str
    '''
    translations = {'/': r'\\/'}
    translations.update(escape_map)
    if overwrite_map:
        translations = escape_map

    rv = path.translate(str.maketrans(translations))
    return rv


def unroll_ruleset(parent_ruleset, rulesets, seen_rulesets=None, rules=None):
    '''
    unroll a socrates ruleset, returns parent ruleset containing rules
    of all referenced 'rulesets'
    :param parent_ruleset: dict containing a socrates ruleset
    :param rulesets: list of dicts containing socrates rulesets
    :param seen_rulesets: list of ruleset names already collected
    :param rules: rules collected from referenced rulesets
    :return: dict containing a complete set of referenced ruleset rules
    :rtype: list
    '''
    # set lists on first run to avoid old rules and rulesets duplication
    if not seen_rulesets:
        seen_rulesets = []
    if not rules:
        rules = []

    for rule in parent_ruleset.get('rules', []):
        if rule not in rules:
            rules.append(rule)

    seen_rulesets.append(parent_ruleset['name'])
    for ruleset in rulesets:
        if ruleset['name'] in parent_ruleset.get('rulesets', []) and ruleset['name'] not in seen_rulesets:
            unroll_ruleset(ruleset, rulesets, seen_rulesets, rules)

    return rules


def gen_networks_rules(networks, rulesets, address_groups):
    '''
    expand all rules attached to the network ruleset and return a list of networks
    together with their respective rules
    :param networks: a list of dictionaries containing network information
    :param rulesets: a list of dictionaries containing ruleset information
    :param address_groups: a list of dictionaries containing address group information
    :return: list of network dictionaries with associated firewall rules
    :rtype: list
    '''
    rv = []

    # remove all networks without rulesets
    networks = [n for n in networks if n.get('ruleset')]
    ruleset_map = {}
    for ruleset in rulesets:
        ruleset_map[ruleset['name']] = ruleset

    for network in networks:
        if network['ruleset'] in ruleset_map.keys():
            rules = unroll_ruleset(ruleset_map[network['ruleset']], rulesets)
            network['expanded_rules'] = []
            for rule in rules:
                addresses = {'destination_addresses': [], 'source_addresses': []}
                for k in addresses.keys():
                    for dest in rule.get(k, []):
                        if dest.get('address_group'):
                            for a in get_address_group_addresses(dest['address_group'], address_groups):
                                addresses[k].append(a)
                        else:
                            addresses[k].append(dest)
                if rule.get('destination_addresses'):
                    rule['destination_addresses'] = addresses['destination_addresses']
                if rule.get('source_addresses'):
                    rule['source_addresses'] = addresses['source_addresses']
                network['expanded_rules'].append(rule)
            rv.append(network)

    return rv


def get_address_group_addresses(group_name, address_groups, addresses=None):
    '''
    find all addresses associated with given address group name
    :param group_name: name of address group as a str
    :param address_groups: list of dicts containing all address groups
    :param addresses: list of already collected adresses
    :return: list of addresses
    :rtype: list
    '''
    if not addresses:
        addresses = []

    for address_group in address_groups:
        if address_group['name'] == group_name:
            for address in address_group['addresses']:
                if address.get('address') and (address.get('length') or address.get('length') == 0):
                    addresses.append(address)
                if address.get('address_group'):
                    get_address_group_addresses(address['address_group'], address_groups, addresses)
    return addresses


def get_ingress_sources(network):
    '''
    get all ingress rules from a network
    :param network: dict containing all associated rules under the expanded_rules key
    :param address_groups: list of dicts containing all known address_groups
    :return: list of dicts containting cidr and ports
    :rtype: list
    '''
    rv = []
    ingress = [r for r in network['expanded_rules'] if r['type'] == 'ingress']
    for rule in ingress:
        for src in rule.get('source_addresses', []):
            if src.get('address') and src.get('length'):
                src_net = '{address}/{length}'.format(**src)
                rv.append({'cidr': src_net, 'ports': rule.get('destination_ports', [])})
    return rv


def match_egress_ingress(egress, networks):
    '''
    check if given egress rule have a mathing ingress rule in referenced network,
    or if dest/src is an unknown network it's assumed that it's fine
    :param egress: dict containing a socrates egress rule
    :param address_groups: list of dicts containing all known address groups
    :return: True when matching ingress is found else False
    :rtype: bool
    '''
    rv = False
    destinations = []
    for dest in egress.get('destination_addresses', []):
        if dest.get('address') and (dest.get('length') or dest.get('length') == 0):
            destinations.append('{address}/{length}'.format(**dest))

    if not destinations or not egress.get('destination_ports'):
        return rv

    network_map = {}
    for network in networks:
        _name = '{network}/{length}'.format(**network)
        network_map[_name] = network

    network_objs = [ipaddress.ip_network(k, False) for k in network_map.keys()]
    for dest in destinations:
        dest_net = ipaddress.ip_network(dest, False)
        # if destination isn't a known network it's matched
        if all([not dest_net.subnet_of(n) and not dest_net.supernet_of(n) for n in network_objs]):
            return True

        for net_obj in network_objs:
            if dest_net.subnet_of(net_obj) or dest_net.supernet_of(net_obj):
                ingress_list = get_ingress_sources(network_map[net_obj.exploded])

                for ig in ingress_list:
                    ig_net = ipaddress.ip_network(ig['cidr'], False)
                    # if ingress network is unknown, it's auto-matched
                    if all([not ig_net.subnet_of(n) and not ig_net.supernet_of(n) for n in network_objs]):
                        return True
                    if dest_net.subnet_of(ig_net):
                        for p in egress.get('destination_ports', []):
                            if p in ig['ports']:
                                return True
    return rv


def get_matched_rules(module):
    '''
    collect all networks with rulesets attached and return a dict with cidr keys
    containing only rules that are matched
    :param module: ansible module object
    :return: dict with cidr, referenced ruleset name, ingress and egress rules as lists
    :rtype: dict

    '''
    networks = gen_networks_rules(module.params['networks'], module.params['rulesets'], module.params['address_groups'])
    rv = {}
    for network in networks:
        cidr = '{network}/{length}'.format(**network)
        rv[cidr] = {'egress': [], 'ingress': [], 'ruleset': network.get('ruleset')}
        for rule in network.get('expanded_rules', []):
            if rule.get('type') == 'egress' and match_egress_ingress(rule, networks):
                rv[cidr]['egress'].append(rule)
            if rule.get('type') == 'ingress':
                rv[cidr]['ingress'].append(rule)
    return rv


def get_forti_packages(module, fmgr):
    url = '/pm/pkg/adom/{adom}'.format(**module.params)
    results = fmgr.process_request(url, {}, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to fetch packages', response=results)
    return results[1]


def get_forti_addresses(module, fmgr):
    url = '/pm/config/adom/{adom}/obj/firewall/address'.format(**module.params)
    results = fmgr.process_request(url, {}, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to fetch addresses', response=results)
    return results[1]


def get_forti_services(module, fmgr):
    url = '/pm/config/adom/{adom}/obj/firewall/service/custom'.format(**module.params)
    results = fmgr.process_request(url, {}, FMGRMethods.GET)
    if results[0] != 0:
        module.fail_json(msg='failed to fetch services', response=results)
    return results[1]


def get_forti_vdom_policies(module, fmgr):
    ret = {}
    datagram = {}
    vdom = module.params['vdom']
    device_id = module.params['device_unique_name']
    # filter out "scope-less" packages
    packages = [p for p in get_forti_packages(module, fmgr) for s in p.get('scope member', []) if s.get('vdom') == vdom and s.get('name') == device_id]

    for pkg in packages:
        url = '/pm/config/adom/{0}/pkg/{1}/firewall/policy'.format(module.params['adom'], pkg['name'])
        results = fmgr.process_request(url, datagram, FMGRMethods.GET)
        if results[0] != 0:
            module.fail_json(msg='failed to fetch policies for package {0}'.format(pkg['name']), response=results)
        ret[pkg['name']] = results[1]

    return ret


def gen_policies_from_rules(module, network_rules):
    '''
    generate fortimanager style policies from socrates rules.
    beware, this is the product of writing some "logic" one day coming back four
    days later, trying to catch up, writing more "logic". pattern repeated during several
    weeks. consider yourself warned.
    :param module: ansible module object
    :param network_rules: dictionary with networks including all rules
    :return: list with rules converted to policies
    :rtype: list
    '''
    rv = []
    delimiter = module.params['prefix_delimiter']
    address_prefix = module.params['address_name_prefix']
    global_label_prefix = module.params['policy_global_label_prefix']
    default_action = module.params['default_action']
    default_zone = module.params['default_zone']
    vdom = module.params['vdom']

    network_zone_map = {}
    for network in module.params['networks']:
        for d in network.get('domains', {}):
            if network['domains'][d].get('data'):
                if network['domains'][d]['data'].get('zone'):
                    _net = '{network}/{length}'.format(**network)
                    network_zone_map.update(
                        {
                            _net: {
                                'zone': network['domains'][d]['data']['zone'],
                                'vdom': network['domains'][d]['data'].get('vdom')
                            }
                        }
                    )

    policies = []
    network_objects = [ipaddress.ip_network(k) for k in network_zone_map.keys()]
    for cidr in network_rules.keys():
        own_net = ipaddress.ip_network(cidr)
        default_network = [{'address': str(own_net.network_address), 'length': str(own_net.prefixlen)}]
        for direction in ['egress', 'ingress']:
            for rule in network_rules[cidr].get(direction, []):
                services = set()
                if rule['protocol'] == 'icmp':
                    services.add('icmp/4')
                for port in rule.get('destination_ports', []):
                    if rule['protocol'] in module.params['service_name_prefixes']:
                        services.add('{0}/{1}'.format(rule['protocol'], port))

                for source in rule.get('source_addresses', default_network):
                    src_net = None
                    src_vdom = None
                    src_zone = default_zone
                    if source.get('address'):
                        s_len = source.get('length', 32)
                        src = '{0}/{1}'.format(source['address'], s_len)
                        src_net = ipaddress.ip_network(src, False)
                        if direction == 'egress' and src_net.supernet_of(own_net):
                            # rewrite supernet of src to own_net
                            src = copy.copy(own_net.exploded)
                            src_net = ipaddress.ip_network(src, False)
                        if direction == 'egress' and not src_net.subnet_of(own_net):
                            continue
                        for n in network_objects:
                            if src_net.subnet_of(n):
                                src_vdom = network_zone_map[n.exploded]['vdom']
                                if src_vdom == vdom:
                                    src_zone = network_zone_map[n.exploded]['zone']

                    if source.get('fqdn'):
                        src = source['fqdn']
                    for destination in rule.get('destination_addresses', default_network):
                        dest_net = None
                        dest_vdom = None
                        dest_zone = default_zone
                        if destination.get('address'):
                            d_len = destination.get('length', 32)
                            dest = '{0}/{1}'.format(destination['address'], d_len)
                            dest_net = ipaddress.ip_network(dest, False)
                            # ingress - if dest is a supernet of own_net, narrow dest down to own_net
                            if direction == 'ingress' and dest_net.supernet_of(own_net):
                                dest = copy.copy(own_net.exploded)
                                dest_net = ipaddress.ip_network(dest, False)
                            # ingress - skip if dest isn't a subnet of own_net
                            if direction == 'ingress' and not dest_net.subnet_of(own_net):
                                continue
                            for n in network_objects:
                                if dest_net.subnet_of(n):
                                    dest_vdom = network_zone_map[n.exploded]['vdom']
                                    if dest_vdom == vdom:
                                        dest_zone = network_zone_map[n.exploded]['zone']

                        if destination.get('fqdn'):
                            dest = destination['fqdn']
                        # policies with same src and dest doesn't make sense(?)
                        if dest == src:
                            continue

                        # ignore policy if there's no vdom referenced matching specified vdom
                        if vdom not in [dest_vdom, src_vdom]:
                            continue

                        dest_name = '{0}{1}{2}'.format(address_prefix, delimiter, dest)
                        src_name = '{0}{1}{2}'.format(address_prefix, delimiter, src)
                        global_label = '{0}{1}{2}'.format(global_label_prefix, delimiter, network_rules[cidr]['ruleset'])
                        policies.append(
                            {
                                'action': rule.get('action', default_action),
                                'dstaddr': [dest_name],
                                'dstintf': [dest_zone],
                                'global-label': global_label,
                                'schedule': ['always'],
                                'service': sorted([s for s in services]),
                                'srcaddr': [src_name],
                                'srcintf': [src_zone]
                            }
                        )
    rv = [i for i in policies if i not in rv]
    return rv


def gen_addresses_from_rules(module, network_rules):
    '''
    accept a dict with network keys containing mathed rules, create fortimgr styled
    address objects and return a list with forti style addresses
    :param module: ansible module object
    :param network_rules: dict containing networks along with wanted rules
    :return: list of dicts containing addresses
    :rtype: list
    '''
    address_prefix = module.params['address_name_prefix']
    delimiter = module.params['prefix_delimiter']
    directions = ['egress', 'ingress']
    seen_names = set()
    rv = []

    for cidr in network_rules.keys():
        net_obj = ipaddress.ip_network(cidr)
        net = {
            'name': delimiter.join([address_prefix, cidr]),
            'type': 'ipmask',
            'subnet': [str(net_obj.network_address), str(net_obj.netmask)]
        }
        if net['name'] not in seen_names:
            rv.append(net)
        seen_names.add(net['name'])

        rule_addresses = []
        for direction in directions:
            for rule in network_rules[cidr].get(direction, []):
                for k in ['destination_addresses', 'source_addresses']:
                    rule_addresses.extend(rule.get(k, []))

        for addr in rule_addresses:
            if addr.get('fqdn'):
                a = {}
                fqdn_type = 'fqdn'
                fqdn_key = 'fqdn'
                if '*' in addr['fqdn']:
                    fqdn_type = 'wildcard-fqdn'
                    fqdn_key = 'wildcard-fqdn'
                a = {'name': delimiter.join([address_prefix, addr['fqdn']]), 'type': fqdn_type, fqdn_key: addr['fqdn']}
            if addr.get('address'):
                if addr.get('length') is None:
                    addr['length'] = 32
                a = {'name': '{0}{1}{2}/{3}'.format(address_prefix, delimiter, addr['address'], addr['length']), 'type': 'ipmask'}
                net_obj = ipaddress.ip_network('{address}/{length}'.format(**addr))
                a.update({'subnet': [str(net_obj.network_address), str(net_obj.netmask)]})
            if not a.get('name'):
                continue
            if a['name'] not in seen_names:
                rv.append(a)
            seen_names.add(a['name'])
    return rv


def update_forti_policies(module, fmgr, policies):
    '''
    if current policies and supplied policies differ, remove all current policies
    and write new ones.
    :param module: ansible module object
    :param fmgr: fortimanager object
    :param policies: list with polices that should exists in policy package associated with vdom
    :return: change status and list of policies after change
    :rtype: dict
    '''
    rv = {'changed': False, 'policies': []}
    existing_policies = []
    delimiter = module.params['prefix_delimiter']
    global_label_prefix = module.params['policy_global_label_prefix']
    policy_packages = get_forti_vdom_policies(module, fmgr)

    if len(policy_packages.keys()) > 1:
        module.fail_json(msg='more than one policy package returned, refusing to continue')

    package = list(policy_packages.keys())[0]
    for p in policy_packages[package]:
        if p.get('global-label'):
            if p['global-label'].split(delimiter)[0] == global_label_prefix:
                existing_policies.append(p)

    base_url = '/pm/config/adom/{0}/pkg/{1}/firewall/policy'.format(module.params['adom'], package)

    # try and figure out which existing policies doesn't exist in the generated policies
    rm_policies = []
    for ep in existing_policies:
        if ep.get('global-label', '_global_label_not_set').split(delimiter)[0] != global_label_prefix:
            continue
        ep_found = False
        for np in policies:
            if all([np[k] == ep[k] for k in np.keys()]):
                ep_found = True
                break
        if not ep_found:
            rm_policies.append(ep)

    for rm_policy in rm_policies:
        if not module.check_mode:
            url = os.path.join(base_url, '{policyid}'.format(**rm_policy))
            results = fmgr.process_request(url, rm_policy, FMGRMethods.DELETE)
            if results[0] != 0:
                module.fail_json(msg='failed to delete policy {0}'.format(rm_policy['policyid']), policy=rm_policy, response=results)
            rv['changed'] = True

    # add/replace policies
    for policy in policies:
        # check if policy should be removed before adding
        for existing_policy in existing_policies:
            if compare_policies(policy, existing_policy):
                if not module.check_mode:
                    rm_url = os.path.join(base_url, '{policyid}'.format(**existing_policy))
                    rm_results = fmgr.process_request(rm_url, existing_policy, FMGRMethods.DELETE)
                    if rm_results[0] != 0:
                        module.fail_json(msg='failed to delete policy {0}'.format(existing_policy['policyid']), policy=existing_policy, response=results)
                rv['changed'] = True
                break

        if not module.check_mode:
            url = base_url
            payload = {'data': policy}
            results = fmgr.process_request(url, payload, FMGRMethods.ADD)
            if results[0] != 0:
                module.fail_json(msg='failed to add policy', policy=policy, reponse=results)
        rv['changed'] = True

    if module.check_mode:
        rv['policies'] = policies
    else:
        updated_policy_packages = get_forti_vdom_policies(module, fmgr)
        for p in updated_policy_packages[package]:
            if p.get('global-label'):
                if p['global-label'].split(delimiter)[0] == global_label_prefix:
                    rv['policies'].append(p)
    return rv


def compare_policies(policy, existing_policy, additional_sorts=[]):
    '''
    naively compare policies by comparing keys from policy with existing policy
    keys not existing in policy will not be considered.
    :param policy: dict containing the new policy
    :param existing_policy: dict
    :param additional_sorts: list of keys conaining lists that should be sorted
    :return: True when policies are equal
    :rtype: bool
    '''
    rv = False
    key_checks = []
    sort_lists = ['service']
    sort_lists.extend(additional_sorts)
    for k in policy.keys():
        if k in sort_lists:
            if isinstance(policy[k], list) and isinstance(existing_policy[k], list):
                policy[k].sort()
                existing_policy[k].sort()
        key_checks.append(policy[k] == existing_policy[k])
    rv = all(key_checks)
    return rv


def gen_updated_services(module, fmgr):
    '''
    generate a list of services not present in the fortimanager
    :param module: ansible module object
    :param fmgr: fortimanager object
    :return: list of dicts containing "forti compliant" services
    :rtype: list
    '''
    networks = get_matched_rules(module)
    delimiter = module.params['prefix_delimiter']
    sv_prefixes = module.params['service_name_prefixes']
    existing_services = [s for s in get_forti_services(module, fmgr) if s['name'].split(delimiter)[0] in sv_prefixes]
    rv = []

    services = []
    for cidr in networks.keys():
        for direction in ['egress', 'ingress']:
            for rule in networks[cidr].get(direction, []):
                if rule.get('protocol') == 'icmp':
                    for icmp_version in [4, 6]:
                        icmpv = 'ICMP'
                        if icmp_version == 6:
                            icmpv = 'ICMP6'
                        service = {'name': 'icmp/{0}'.format(icmp_version), 'protocol': icmpv}
                        services.append(service)
                for port in rule.get('destination_ports', []):
                    if rule.get('protocol') in ['tcp', 'udp']:
                        service_name = '{0}/{1}'.format(rule['protocol'], port)
                        port_key = '{0}-portrange'.format(rule['protocol'])
                        service = {'name': service_name, port_key: [str(port)], 'protocol': 'TCP/UDP/SCTP'}
                        if service not in services:
                            services.append(service)

    existing_service_names = [s['name'] for s in existing_services]
    for service in services:
        if service['name'] not in existing_service_names:
            rv.append(service)
            continue
        for e_service in existing_services:
            if service['name'] == e_service['name']:
                if not all([service[k] == e_service[k] for k in service.keys() if k != 'name']):
                    rv.append(service)
    return rv


def update_forti_addresses(module, fmgr, addresses):
    rv = {'changed': False, 'addresses': []}
    address_prefix = module.params['address_name_prefix']
    delimiter = module.params['prefix_delimiter']
    existing_addresses = [a for a in get_forti_addresses(module, fmgr) if a['name'].split(delimiter)[0] == address_prefix]
    existing_addresses_map = {}
    url = '/pm/config/adom/{adom}/obj/firewall/address'.format(**module.params)

    for existing_address in existing_addresses:
        existing_addresses_map[existing_address['name']] = existing_address

    existing_address_names = sorted([a['name'] for a in existing_addresses])

    for address in addresses:
        if address['name'] in existing_address_names:
            aname = address['name']
            # skip when address values == existing_address values
            if all([address[k] == existing_addresses_map[aname][k] for k in address.keys()]):
                continue
            fmgr_method = FMGRMethods.UPDATE
        else:
            fmgr_method = FMGRMethods.ADD
        if not module.check_mode:
            results = fmgr.process_request(url, address, fmgr_method)
            if results[0] != 0:
                module.fail_json(msg='failed to add/update address', address=address, response=results)

    updated_addresses = get_forti_addresses(module, fmgr)
    if module.check_mode:
        # fabricate diff for check mode
        check_addresses = []
        for e in updated_addresses:
            for a in addresses:
                if a['name'] == e['name']:
                    e.update(a)
                    break
            check_addresses.append(e)
        for a in addresses:
            if a['name'] not in existing_address_names:
                check_addresses.append(a)
        updated_addresses = check_addresses

    d_diff = [i for i in updated_addresses if i not in existing_addresses]
    if d_diff:
        rv['changed'] = True

    rv['addresses'] = updated_addresses
    return rv


def update_forti_services(module, fmgr, services):
    '''
    add/update services in services, return change status and a list of services available after update
    :param module: ansible module object
    :param fmgr: fortimanager helper object
    :param services: list of dicts with fortimanager style service objects
    :return: dictionary containing 'changed' (bool) and 'services' (list)
    :rtype: dict
    '''
    url = '/pm/config/adom/{adom}/obj/firewall/service/custom'.format(**module.params)
    delimiter = module.params['prefix_delimiter']
    sv_prefixes = module.params['service_name_prefixes']
    rv = {'changed': False, 'services': []}
    existing_services = get_forti_services(module, fmgr)
    existing_service_names = [s['name'] for s in existing_services if s['name'].split(delimiter)[0] in sv_prefixes]

    for service in services:
        if service['name'] in existing_service_names:
            fmgr_method = FMGRMethods.UPDATE
        else:
            fmgr_method = FMGRMethods.ADD
        if not module.check_mode:
            results = fmgr.process_request(url, service, fmgr_method)
            if results[0] != 0:
                module.fail_json(msg='failed to add service', response=results, service=service)

    updated_services = [s for s in get_forti_services(module, fmgr) if s['name'].split(delimiter)[0] in sv_prefixes]
    if module.check_mode:
        updated_services.extend(services)

    d_diff = [i for i in updated_services if i not in existing_services]
    if d_diff:
        rv['changed'] = True

    rv['services'] = updated_services
    return rv


def update_forti(module, fmgr):
    changed = False
    diff = {'before': {}, 'after': {}}
    msg = []
    global_label_prefix = module.params['policy_global_label_prefix']
    delimiter = module.params['prefix_delimiter']
    sv_prefixes = module.params['service_name_prefixes']
    network_rules = get_matched_rules(module)
    services = gen_updated_services(module, fmgr)
    addresses = gen_addresses_from_rules(module, network_rules)
    policies = gen_policies_from_rules(module, network_rules)

    if len(policies) < 1:
        module.fail_json(msg='rules to policy generation returned 0 results which would remove all policies with global tag prefix {0}{1}, clearing all rules is not supported for "safety" reasons'.format(global_label_prefix, delimiter))

    if services:
        diff['before']['services'] = [s for s in get_forti_services(module, fmgr) if s['name'].split(delimiter)[0] in sv_prefixes]
        ret = update_forti_services(module, fmgr, services)
        diff['after']['services'] = ret['services']
        if ret['changed']:
            changed = ret['changed']
            msg.append('services: updated')
        else:
            msg.append('services: no change')
    else:
        msg.append('services: no change')

    if addresses:
        diff['before']['addresses'] = get_forti_addresses(module, fmgr)
        ret = update_forti_addresses(module, fmgr, addresses)
        diff['after']['addresses'] = ret['addresses']
        if ret['changed']:
            changed = ret['changed']
            msg.append('addresses: updated')
        else:
            msg.append('addresses: no change')
    else:
        msg.append('addresses: no change')

    if policies:
        policy_packages = get_forti_vdom_policies(module, fmgr)
        if len(policy_packages.keys()) > 1:
            module.fail_json(msg='more than one policy package returned, refusing to continue', policy_packages=policy_packages)

        package = list(policy_packages.keys())[0]
        current_policies = []
        for p in policy_packages[package]:
            if p.get('global-label'):
                if p['global-label'].split(delimiter)[0] == global_label_prefix:
                    current_policies.append(p)

        diff['before']['policies'] = current_policies
        ret = update_forti_policies(module, fmgr, policies)
        diff['after']['policies'] = ret['policies']
        if ret['changed']:
            changed = ret['changed']
            msg.append('policies: updated')
        else:
            msg.append('policies: no change')

    if not msg:
        msg.append('no change')

    msg_str = ', '.join(msg)
    # append check mode for clarity
    if module.check_mode:
        msg_str = '{0} - check mode'.format(msg_str)
    return changed, diff, msg_str


def main():
    module = AnsibleModule(
        argument_spec=dict(
            device_unique_name=dict(required=True, type='str'),
            vdom=dict(type='str', required=True),
            adom=dict(type='str', required=True),
            default_zone=dict(type='str', required=True),
            address_name_prefix=dict(type='str', default='sot'),
            service_name_prefixes=dict(type='list', default=['tcp', 'udp', 'icmp']),
            prefix_delimiter=dict(type='str', default='/'),
            policy_global_label_prefix=dict(type='str', default='socrates'),
            networks=dict(type='list', required=True),
            rulesets=dict(type='list', required=True),
            address_groups=dict(type='list', required=True),
            default_action=dict(type='str', default='accept')
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
    changed, diff, msg = update_forti(module, fmgr)
    module.exit_json(changed=changed, diff=diff, msg=msg)


if __name__ == '__main__':
    main()
