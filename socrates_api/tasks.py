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

import base64
import jsonpath_rw_ext
import json
import logging
import os
import re
import requests
import socket
import subprocess
import time
import traceback
try:
    from urllib.parse import urlparse
except ImportError:
    from urlparse import urlparse
import copy
import datetime
from functools import reduce
import pytz
import deepdiff
from celery import shared_task, chord, group
from django.contrib.auth.models import User
from django.conf import settings
from django.core.mail import send_mail
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils import timezone
from django.utils.module_loading import import_string
from email.mime.text import MIMEText
from django_rethink import r, get_connection, RethinkObjectNotFound
from socrates_api.serializers import *
from socrates_api.ipam import IPAMIPNotFoundException
from tempfile import NamedTemporaryFile
from kombu.utils.json import JSONEncoder
from netaddr import IPNetwork, IPAddress

logger = logging.getLogger("socrates_api.tasks")

lldp_remote_system = re.compile(r'System Name TLV\s+(\S+)\s+')
dell_pdisk_capacity = re.compile(r'^[0-9.,]+[GTP]B\(([0-9]+)bytes\)')
hp_enclosure_serial = re.compile(r'^\s+Enclosure Serial: ([A-Za-z0-9]+)\s*$', re.MULTILINE)
hp_enclosure_bay = re.compile(r'^\s+Server Bay: ([0-9]+)\s*$', re.MULTILINE)
dell_enclosure_serial = re.compile(r'Chassis Information.*?Serial Number: ([A-Za-z0-9]+)')
dell_enclosure_bay = re.compile(r'Base Board Information.*?Location In Chassis: Slot ([0-9]+)')

def ipv4_network_contains(cidr, ip):
    return IPAddress(ip) in IPNetwork(cidr)

# This adds support for the ^= operator used in the PCI code below
jsonpath_rw_ext.parser.ExtendedJsonPathLexer.t_FILTER_OP += r'|\^='
jsonpath_rw_ext._filter.OPERATOR_MAP['^='] = lambda x, y: x.startswith(y)

@shared_task
def extract_asset_from_raw(service_tag, final_step=False):
    conn = get_connection()
    raw_asset = next(r.table("assets_raw").get_all(service_tag, index="service_tag").run(conn))
    data = {}
    data['efi'] = raw_asset['intake'].get('efi', False)
    data['cpu'] = [x.value for x in jsonpath_rw_ext.parse('$..children[?class="processor"].version').find(raw_asset)]
    try:
        memory = jsonpath_rw_ext.parse('$..children[?id="memory"]').find(raw_asset)[0].value
    except IndexError:
        memories = [x.value for x in jsonpath_rw_ext.parse('$..children[?class="memory"]').find(raw_asset) if x.value['id'].startswith("memory")]
        memory = {'children': []}
        for m in memories:
            memory['children'].extend(m.get('children', []))
        memory['size'] = sum(map(lambda x: x.value, jsonpath_rw_ext.parse("$..size").find(memory)))
    data['ram'] = {'slots': {}, 'total': memory['size']}
    for memory_slot in memory['children']:
        data['ram']['slots'][memory_slot['slot']] = {}
        if 'product' in memory_slot:
            data['ram']['slots'][memory_slot['slot']]['product'] = memory_slot['product']
        if 'description' in memory_slot:
            data['ram']['slots'][memory_slot['slot']]['description'] = memory_slot['description']
        if 'size' in memory_slot:
            data['ram']['slots'][memory_slot['slot']]['size'] = memory_slot['size']

    system = raw_asset['intake']['lshw']
    data['vendor'] = system['vendor']
    data['model'] = system['product']

    if system['vendor'] != 'Supermicro' and system['configuration']['chassis'] == 'blade':
        data['asset_subtype'] = 'blade'
        dmidata = NamedTemporaryFile()
        dmidata.write(base64.b64decode(raw_asset['intake']['dmidecode'].encode("ascii")))
        dmidata.flush()
        if data['vendor'] == 'HP':
            p = subprocess.Popen(["dmidecode", "--from-dump", dmidata.name, "-t", "204", "-q"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if p.returncode == 0:
                stdout = stdout.decode("utf-8")
                parent_m = hp_enclosure_serial.search(stdout)
                bay_m = hp_enclosure_bay.search(stdout)
                if parent_m:
                    data['parent'] = parent_m.group(1)
                if bay_m:
                    data['parent_position'] = [int(bay_m.group(1))]
            else:
                logger.warn("%s: dmidecode returned %d" % (service_tag, p.returncode))
        elif data['vendor'] == 'Dell Inc.':
            p = subprocess.Popen(["dmidecode", "--from-dump", dmidata.name, "-t", "2", "-t", "3", "-q"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if p.returncode == 0:
                stdout = stdout.decode("utf-8")
                parent_m = dell_enclosure_serial.search(stdout)
                bay_m = dell_enclosure_bay.search(stdout)
                if parent_m:
                    data['parent'] = parent_m.group(1)
                if bay_m:
                    data['parent_position'] = [int(bay_m.group(1).lstrip("0"))]
            else:
                logger.warn("%s: dmidecode returned %d" % (service_tag, p.returncode))
        dmidata.close()

    elif system['vendor'] == 'Supermicro' and 'ipmicfg' in raw_asset['intake'] and 'nodeid' in raw_asset['intake']['ipmicfg']:
        data['asset_subtype'] = 'blade'
        if 'chassis' in raw_asset['intake']['ipmicfg']:
            data['parent'] = raw_asset['intake']['ipmicfg']['chassis']
        if raw_asset['intake']['ipmicfg']['nodeid'].isdigit():
            data['parent_position'] = [int(raw_asset['intake']['ipmicfg']['nodeid'])]
        else:
            data['parent_position'] = [raw_asset['intake']['ipmicfg']['nodeid']]

    data['oob'] = {}
    if 'oob-config' in raw_asset and raw_asset['oob-config'].get('success', False):
        data['oob'].update({
            'username': raw_asset['oob-config']['username'],
            'password': raw_asset['oob-config']['password'],
        })

    if 'oob' in raw_asset['intake'] and 'version' in raw_asset['intake']['oob']:
        data['oob'].update({
            'version': raw_asset['intake']['oob']['version'],
            'mac': raw_asset['intake']['oob']['mac'],
        })

    data['nics'] = []
    for nic_lshw in map(lambda x: x.value, jsonpath_rw_ext.parse('$..children[?class="network"]').find(raw_asset)):
        if 'logicalname' not in nic_lshw:
            # iSCSI NICs show up as network devices
            continue
        nic = {
            'name': nic_lshw['logicalname'],
            'mac': nic_lshw['serial'],
        }
        system_m = lldp_remote_system.search(raw_asset['intake']['lldp'].get(nic['name'], ""))
        if system_m is not None:
            try:
                switch_asset = next(AssetSerializer.filter({'switch': {'domain': system_m.group(1)}}))
            except r.errors.ReqlCursorEmpty:
                logger.warning("switch domain %s is unknown", system_m.group(1))
            else:
                if 'port_regexp' in switch_asset['switch']:
                    port_m = re.search(switch_asset['switch']['port_regexp'], raw_asset['intake']['lldp'].get(nic['name'], ""))
                    if port_m:
                        nic['remote'] = {
                            'domain': system_m.group(1),
                            'port': port_m.group('interface'),
                        }
        data['nics'].append(nic)

    enclosures = []
    data['storage'] = []
    if data['vendor'].lower().startswith("dell"):
        for i in raw_asset['intake']['storage']:
            controller = {'id': i['ID'], 'name': i['Name']}
            controller['pdisks'] = []
            for pdisk in i['pdisks']:
                m = dell_pdisk_capacity.match(pdisk['Capacity'])
                capacity = int(m.group(1))
                controller['pdisks'].append({
                    'id': pdisk['ID'],
                    'name': pdisk['Name'],
                    'vendor': pdisk['VendorID'],
                    'serial': pdisk['SerialNo.'],
                    'capacity': capacity,
                    'bus': pdisk['BusProtocol'],
                    'media': pdisk['Media'],
                })
            controller['vdisks'] = []
            for vdisk in i['vdisks']:
                pdisks = [{'id': pdisk['ID'], 'name': pdisk['Name']} for pdisk in vdisk['pdisks']]
                controller['vdisks'].append({
                    'id': vdisk['ID'],
                    'name': vdisk['Name'],
                    'by_id': vdisk['DeviceName'],
                    'raid': vdisk['Layout'],
                    'pdisks': pdisks,
                })
            data['storage'].append(controller)
            for enclosure in i.get('enclosures', []):
                if enclosure['Name'] == "Backplane":
                    continue
                enclosures.append({
                    'service_tag': enclosure['ServiceTag'],
                    'model': enclosure['Name'],
                })

    elif data['vendor'].lower().startswith("hp"):
        for i in raw_asset['intake']['storage']:
            controller = {'id': i['Slot'], 'name': i['Name']}
            controller['pdisks'] = []
            for pdisk in i['pdisks']:
                bus = pdisk['InterfaceType']
                media = 'HDD'
                if bus.startswith("Solid State"):
                    bus = bus[12:]
                    media = 'SSD'
                size, unit = pdisk['Size'].split(" ", 1)
                capacity = float(size) * {'GB': 1000000000, 'TB': 1000000000000}[unit]
                controller['pdisks'].append({
                    'id': pdisk['ID'],
                    'serial': pdisk['SerialNumber'],
                    'capacity': capacity,
                    'bus': bus,
                    'media': media,
                })
            controller['vdisks'] = []
            for vdisk in i['vdisks']:
                pdisks = [{'id': pdisk['ID']} for pdisk in vdisk['pdisks']]
                layout = {'1+0': 'RAID-10', '1': 'RAID-1', '5': 'RAID-5', '6': 'RAID-6'}[vdisk['FaultTolerance']]
                controller['vdisks'].append({
                    'id': vdisk['ID'],
                    'by_id': vdisk['DiskName'],
                    'raid': layout,
                    'pdisks': pdisks,
                })
            data['storage'].append(controller)
            for enclosure in i.get('enclosures', []):
                if enclosure['Location'] == "Internal":
                    continue
                enclosures.append({
                    'service_tag': enclosure['SerialNumber'],
                    'vendor': enclosure['VendorID'],
                    'model': enclosure['Name'],
                    'bays': enclosure['DriveBays'],
                })

    elif 'storage' in raw_asset['intake']:
        data['storage'] = raw_asset['intake']['storage']

    if 'by_id_map' in raw_asset['intake']:
        vdisks = set([vdisk['by_id'] for controller in data['storage'] for vdisk in controller['vdisks']])
        for storage in map(lambda x: x.value, jsonpath_rw_ext.parse('$..children[?class="storage"]').find(raw_asset['intake']['lshw'])):
            devices = []
            if 'children' not in storage:
                continue
            for device in storage['children']:
                if 'logicalname' not in device or 'size' not in device or ('capabilities' in device and 'removable' in device['capabilities']):
                    continue
                if not isinstance(device['logicalname'], list):
                    device['logicalname'] = [device['logicalname']]
                by_id = ["disk/by-id/" + by_id for by_id, node in raw_asset['intake']['by_id_map'].items() if node in device['logicalname'] and (by_id.startswith("scsi-") or by_id.startswith("ata-"))]
                if len(by_id) == 0:
                    continue
                by_id = by_id[0]
                if by_id in vdisks:
                    continue
                device['by_id'] = by_id
                devices.append(device)
            if len(devices) > 0:
                if 'storage' not in data:
                    data['storage'] = []
                data['storage'].append({
                    'id': storage['businfo'],
                    'type': 'direct',
                    'name': "%s %s" % (storage['vendor'], storage['product']),
                    'pdisks': [{
                        'id': device['physid'],
                        'serial': device.get('serial', None),
                        'capacity': device['size'],
                        'by_id': device['by_id'],
                    } for device in devices]
                })

    try:
        instance = AssetSerializer.get(service_tag=service_tag)
    except RethinkObjectNotFound:
        instance = None

    if 'raid-config' in raw_asset and raw_asset['raid-config'].get('success', False) and raw_asset['raid-config']['timestamp'] > (time.time() - 3600):
        for vdisk, by_id in raw_asset['raid-config']['vdisks_by_id'].items():
            if vdisk in instance['provision']['storage'] and 'by_id' not in instance['provision']['storage'][vdisk]:
                if 'provision' not in data:
                    data['provision'] = {}
                if 'storage' not in data['provision']:
                    data['provision']['storage'] = {}
                if vdisk not in data['provision']['storage']:
                    data['provision']['storage'][vdisk] = {}
                data['provision']['storage'][vdisk]['by_id'] = by_id

    dmidata = NamedTemporaryFile()
    dmidata.write(base64.b64decode(raw_asset['intake']['dmidecode'].encode("ascii")))
    dmidata.flush()
    p = subprocess.Popen(["dmidecode", "--from-dump", dmidata.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dmidecode_out, dmidecode_err = p.communicate()
    dmidecode_rc = p.returncode
    dmidata.close()

    slots = {}
    if dmidecode_rc == 0:
        designation = None
        address = None
        for line in dmidecode_out.decode("utf-8").splitlines():
            if line.startswith("Handle 0x"):
                if designation is not None and address is not None:
                    slots[address] = designation
                designation = None
                address = None
            elif ":" in line:
                field, value = map(lambda x: x.strip(), line.split(":", 1))
                if field in ("Designation", "Reference Designation"):
                    designation = value
                elif field == "Bus Address":
                    address = value

    data['cards'] = []
    for pci in map(lambda x: x.value, jsonpath_rw_ext.parse('$..children[?businfo^="pci@"]').find(raw_asset)):
        if pci['businfo'][4:] not in slots:
            continue
        card = {
            'slot': slots[pci['businfo'][4:]],
            'vendor': pci['vendor'],
            'product': pci['product'],
        }
        if 'subdevice' in pci:
            card['subvendor'] = pci['subvendor']
            card['subdevice'] = pci['subdevice']
        data['cards'].append(card)

    # warranty lookup
    if 'vendor' in data:
        if instance is not None and 'supportvendor' in instance:
            data['supportvendor'] = instance['supportvendor']
        elif hasattr(settings, 'SUPPORTVENDORS'):
            data['supportvendor'] = settings.SUPPORTVENDORS[data['vendor']]
    if data.get('supportvendor') == 'dell':
        data['warranty'] = _extract_dell_warranty_from_raw(service_tag)
    # add more vendors here if they supply a warranty API

    data['log'] = 'Extracting raw data'
    if instance is not None:
        data['version'] = instance['version']
        if instance.get('provisioning', False) and instance['state'] == 'in-use' and final_step:
            data['provisioning'] = False
        serializer = AssetSerializer(instance, data=data, partial=True)
    else:
        data['version'] = 1
        data['service_tag'] = service_tag
        data['state'] = 'new'
        data['asset_type'] = 'server'
        serializer = AssetSerializer(instance, data=data)

    serializer.is_valid(raise_exception=True)
    serializer.save()

    for enclosure in enclosures:
        try:
            enclosure_asset = AssetSerializer.get(service_tag=enclosure['service_tag'])
            if enclosure_asset.get('connected_to', []) != [service_tag]:
                enclosure_asset = AssetSerializer(enclosure_asset, partial=True, data={
                    'connected_to': [service_tag],
                    'version': enclosure_asset['version'],
                    'log': "Automatically updated by intake on %s" % service_tag,
                })
                enclosure_asset.is_valid(raise_exception=True)
                enclosure_asset.save()
        except RethinkObjectNotFound:
            enclosure_asset = AssetSerializer(None, data={
                'state': 'in-use',
                'asset_type': 'storage',
                'asset_subtype': 'das',
                'service_tag': enclosure['service_tag'],
                'vendor': enclosure.get('vendor', data['vendor']),
                'model': enclosure['model'],
                'connected_to': [service_tag],
                'version': 1,
                'log': "Automatically created by intake on %s" % service_tag,
            })
            enclosure_asset.is_valid(raise_exception=True)
            enclosure_asset.save()

    return True

class DoUntilRetriesExceeded(Exception):
    pass

def do_until(c, ic=None, wait=5, retries=12):
    attempt = 0
    while not c() and attempt < retries:
        if ic and attempt == 0:
            ic()
        time.sleep(wait)
        attempt = attempt + 1
    if attempt == retries:
        raise DoUntilRetriesExceeded()

@shared_task
def extract_warranty_from_raw(asset):
    update = {'log' : 'Updating warranty from raw'}
    if 'supportvendor' in asset.keys() and asset['supportvendor'] == 'dell':
        try:
            update['warranty'] = _extract_dell_warranty_from_raw(asset['service_tag'])
        except Exception as e:
            logger.warn('service tag %s failed.' % asset['service_tag'])
    asset_update(asset, update)
    return asset


def dell_timestamp_to_datetime(timestamp_str):
    format_str = '%Y-%m-%dT%H:%M:%SZ'
    if '.' in timestamp_str:
        format_str = '%Y-%m-%dT%H:%M:%S.%fZ'
    return pytz.utc.localize(datetime.datetime.strptime(timestamp_str, format_str))


def _extract_dell_warranty_from_raw(service_tag):
    conn = get_connection()
    raw_asset = next(r.table("assets_raw").get_all(service_tag, index="service_tag").run(conn))
    warranty = {}
    if 'warranty' in raw_asset.keys():
        warranty = raw_asset['warranty']
    data = {}
    if warranty and not warranty['invalid']:
        raw_entitlements = warranty.get('entitlements', [])
        entitlements = {}
        next_end_date = None
        for wtype in (5, 11):
            if wtype == 5:
                stype = 'Machine'
            elif wtype == 11:
                stype = 'Disks'
            type_end_date = None
            for e in raw_entitlements:
                if e['serviceLevelGroup'] == wtype:
                    current_end_date = dell_timestamp_to_datetime(e['endDate'])
                    if current_end_date > datetime.datetime.now(tz=pytz.utc):
                        if not type_end_date or current_end_date > type_end_date:
                            type_end_date = current_end_date
                            entitlements[stype] = {'description': e['serviceLevelDescription'], 'end_date': current_end_date}
                            if not next_end_date or current_end_date < next_end_date:
                                next_end_date = current_end_date
        data['entitlements'] = entitlements
        data['shipping_date'] = dell_timestamp_to_datetime(warranty['shipDate'])
        data['next_end_date'] = next_end_date
        data['valid'] = True
    else:
        data = {'valid': False}
    return data


@shared_task
def batch_update_warranties_from_vendors():
    _batch_update_warranties_from_dell()
    return True


def _batch_update_warranties_from_dell():
    service_tags = list(x['service_tag'] for x in r.table('assets').filter(r.row['state'] != 'deleted').filter({'supportvendor': 'dell'}).run(get_connection()))
    return _call_dell_warranty_api(service_tags)


def _call_dell_warranty_api(service_tags):
    result = _get_dell_warranties_from_api(service_tags)
    for service_tag, warranty in result.items():
        status = r.table("assets_raw").get_all(service_tag, index="service_tag").update({"warranty": warranty}).run(get_connection())
        if max(status.values()) == 0:
            status = r.table('assets_raw').insert({'service_tag': service_tag, 'warranty': warranty}).run(get_connection())
        extract_warranty_from_raw(asset_get(service_tag))
    return result


@shared_task
def retry_invalid_warranties_from_vendors():
    _retry_invalid_warranties_from_dell()
    return True

def _retry_invalid_warranties_from_dell():
    service_tags = []
    no_warranty_assets = get_no_warranty_assets()
    for a in no_warranty_assets:
        if a.get('supportvendor', '') == 'dell':
            service_tags.append(a['service_tag'])
    missing_warranty_assets = get_missing_warranty_assets()
    for a in missing_warranty_assets:
        if a.get('supportvendor', '') == 'dell':
            service_tags.append(a['service_tag'])
    _call_dell_warranty_api(service_tags)


def _get_dell_oauth2_bearer():
    rv = False
    url = settings.DELL_OAUTH2_URL
    headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    data = {
        'client_id': settings.DELL_OAUTH2_CLIENTID,
        'client_secret': settings.DELL_OAUTH2_CLIENTSECRET,
        'grant_type': 'client_credentials'
    }
    r = requests.post(url, headers=headers, data=data)
    if not r.ok:
        raise Exception('Dell API oauth2 failed , status code: {0}, text: {1}'.format(r.status_code, r.text))

    rv = r.json()
    return rv


def _get_dell_warranties_from_api(service_tags):
    rv = {}
    auth = _get_dell_oauth2_bearer()
    headers = {'Accept': 'application/json', 'Authorization': '{token_type} {access_token}'.format(**auth)}
    url = settings.DELL_API_URL
    batch_size = getattr(settings, 'DELL_API_BATCHSIZE', 100)
    service_tag_batches = [service_tags[i:i + batch_size] for i in range(0, len(service_tags), batch_size)]
    for batch in service_tag_batches:
        batch = set(batch)
        payload = {'servicetags': ','.join(batch)}
        for attempt in range(5):
            r = requests.get(url, headers=headers, params=payload)
            if r.ok:
                break
            if attempt < 4:
                logger.warning('Failed to communicate with Dell warranty API: status code: {0}, text: {1}, attempt {2} of 4'.format(r.status_code, r.text, attempt))
                time.sleep(5)
                continue
            else:
                raise Exception('Failed to get warranty information from Dell warranty API status code: {0}, text: {1}'.format(r.status_code, r.text))

        for dell_asset in r.json():
            asset_tag = dell_asset['serviceTag']
            rv[asset_tag] = dell_asset

    return rv


@shared_task
def update_warranty_from_vendor(asset):
    if asset.get('supportvendor', '') == 'dell':
        return _call_dell_warranty_api([asset['service_tag']])
    return False

@shared_task
def asset_get(service_tag):
    asset = r.table('assets').get_all(service_tag, index='service_tag').nth(0).run(get_connection())
    return asset

@shared_task
def asset_get_by_id(id):
    asset = r.table('assets').get(id).run(get_connection())
    return asset

@shared_task
def get_expiring_warranty_assets(days):
    date = pytz.utc.localize(datetime.datetime.utcnow()) + datetime.timedelta(days=days)
    assets = r.table('assets').filter(r.row['state'] != 'deleted').filter(r.not_(r.row['warranty']['valid'])).filter(r.row['warranty'].has_fields('next_end_date')).filter(lambda asset: (asset['warranty']['next_end_date'] < date) & (asset['warranty']['shipping_date'] >= pytz.utc.localize(datetime.datetime.utcnow()) - datetime.timedelta(days=settings.WARRANTY_REPORT_MAX_AGE*365-days))).run(get_connection())
    # r.table('assets').filter(lambda asset: asset['warranty']['next_end_date'] != None and asset['warranty']['next_end_date'] < date).run(get_connection())
    return assets

@shared_task
def get_no_warranty_assets():
    assets = list(r.table('assets').filter(r.row['state'] != 'deleted').filter(~r.row['warranty'].has_fields('next_end_date')).filter(lambda asset: asset['warranty']['shipping_date'] >= pytz.utc.localize(datetime.datetime.utcnow()) - datetime.timedelta(days=settings.WARRANTY_REPORT_MAX_AGE*365)).run(get_connection()))
    assets = assets + list(r.table('assets').filter(r.row['state'] != 'deleted').filter(r.not_(r.row['warranty']['valid'])).run(get_connection()))
    return assets

@shared_task
def get_in_warranty_assets():
    assets = r.table('assets').filter(r.row['state'] != 'deleted').filter(r.row['warranty'].ne(False)).run(get_connection())
    return assets

@shared_task
def get_missing_warranty_assets():
    assets = r.table('assets').filter(r.row['state'] != 'deleted').filter(r.row['warranty'].not_().default(True)).run(get_connection())
    return assets

@shared_task
def get_eol_assets(max_age, days):
    assets = r.table('assets').filter(r.row['state'] != 'deleted').filter(lambda asset: asset['warranty']['shipping_date'] < pytz.utc.localize(datetime.datetime.utcnow()) - datetime.timedelta(days=max_age*365-days)).run(get_connection())
    return assets

@shared_task
def send_expiring_warranty_report(recipients, days):
    assets = list(get_expiring_warranty_assets(days))
    if len(assets) > 0:
        template_name = 'expiring-warranty.mail.j2'
        try:
            hostname = settings.ALLOWED_HOSTS[-1]
        except IndexError:
            hostname = socket.gethostname()
        rendered_template = render_to_string(template_name, context={'days': days, 'assets': assets, 'hostname': hostname})
        csv = 'service_tag,model,hostname,shipping_date,next_end_date,entitlements\n'
        for a in sorted(assets):
            e = ''
            if 'warranty' in a and 'entitlements' in a['warranty']:
                entitlements = a.get('warranty', {}).get('entitlements', {})
                for k, v in entitlements.items():
                    e += ',"%s: %s %s"'%(k, v.get('description', ''), v.get('end_date', ''))
            csv += '"%s","%s","%s","%s","%s"%s\n'%(a['service_tag'], a.get('model', "UNKNOWN"), a.get('provision', {}).get('hostname', ''), a.get('warranty', {}).get('shipping_date', ''), a.get('warranty', {}).get('next_end_date', ''), e)
        attachment = MIMEText(csv, 'csv')
        attachment.add_header("Content-Disposition", "attachment", filename="expiring_warranty_assets.csv")
        email = EmailMessage('Expiring hardware warranties', rendered_template, settings.SOCRATES_MAIL_FROM, recipients)
        email.attach(attachment)
        email.send()
        logger.warn('Expiring warranty report: %s assets with expiring warranty in the next %s days' % (len(assets), days))
    else:
        logger.info('Expiring warranty report: No assets with expiring warranty in the next %s days' % days)
    return len(assets)

@shared_task
def send_eol_report(recipients, max_age, days):
    assets = list(get_eol_assets(max_age, days))
    if len(assets) > 0:
        template_name = 'end-of-life.mail.j2'
        try:
            hostname = settings.ALLOWED_HOSTS[-1]
        except IndexError:
            hostname = socket.gethostname()
        rendered_template = render_to_string(template_name, context={'max_age': max_age, 'days': days, 'assets': assets, 'hostname': hostname})
        csv = 'service_tag,model,hostname,shipping_date\n'
        for a in sorted(assets):
            csv += '"%s","%s","%s","%s"\n'%(a['service_tag'], a.get('model', "UNKNOWN"), a.get('provision', {}).get('hostname', ''), a.get('warranty', {}).get('shipping_date', ''))
        attachment = MIMEText(csv, 'csv')
        attachment.add_header("Content-Disposition", "attachment", filename="eol_assets.csv")
        email = EmailMessage('End of life assets', rendered_template, settings.SOCRATES_MAIL_FROM, recipients)
        email.attach(attachment)
        email.send()
        logger.warn('EOL report: %s EOL assets older than %s years in the next %s days.' % (len(assets), max_age, days))
    else:
        logger.info('EOL report: No EOL assets older than %s years in the next %s days.' % (max_age, days))
    return len(assets)

@shared_task
def send_no_warranty_report(recipients):
    assets = list(get_no_warranty_assets())
    if len(assets) > 0:
        template_name = 'no-warranty.mail.j2'
        try:
            hostname = settings.ALLOWED_HOSTS[-1]
        except IndexError:
            hostname = socket.gethostname()
        rendered_template = render_to_string(template_name, context={'assets': assets, 'hostname': hostname})
        csv = 'service_tag,model,hostname,shipping_date\n'
        for a in sorted(assets):
            csv += '"%s","%s","%s","%s"\n'%(a['service_tag'], a.get('model', "UNKNOWN"), a.get('provision', {}).get('hostname', ''), a.get('warranty', {}).get('shipping_date', ''))
        attachment = MIMEText(csv, 'csv')
        attachment.add_header("Content-Disposition", "attachment", filename="invalid_warranty_assets.csv")
        email = EmailMessage('Assets without valid warranty', rendered_template, settings.SOCRATES_MAIL_FROM, recipients)
        email.attach(attachment)
        email.send()
        logger.warn("No warranty report: %s assets without warranty." % len(assets))
    else:
        logger.info("No warranty report: No assets without warranty.")
    return len(assets)

@shared_task
def asset_update(asset, update, **kwargs):
    if not update:
        return asset
    if 'version' not in update:
        update['version'] = asset['version']
    serializer = AssetSerializer(asset, data=update, partial=True, **kwargs)
    serializer.is_valid(raise_exception=True)
    return serializer.save()

@shared_task
def asset_replace(asset, new_asset, **kwargs):
    serializer = AssetSerializer(asset, data=new_asset, **kwargs)
    serializer.is_valid(raise_exception=True)
    return serializer.save()

class IPMIException(Exception):
    pass

def ipmi_command(service_tag, username, password, command):
    try:
        return subprocess.check_output(["ipmitool",
            "-I", "lanplus", "-U", username, "-P", password,
            "-H", service_tag + '.' + settings.SOCRATES_OOB_DOMAIN,
            ] + command, stderr=subprocess.STDOUT, timeout=10).decode("ascii")
    except subprocess.CalledProcessError as e:
        raise IPMIException("We have IPMI errors! %s: %d %s" % (service_tag, e.returncode, e.output))

@shared_task(bind=True)
def ipmi_shutdown(self, asset):
    if asset['asset_type'] == 'server':
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], ['chassis', 'power', 'off'])
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    elif asset['asset_type'] == 'vm':
        parent_asset = AssetSerializer.get(service_tag=asset['parent'])
        if 'url' in parent_asset and parent_asset['url'].startswith("ansible://"):
            url = urlparse(parent_asset['url'])
            run_playbook(asset, url.path.lstrip("/") + "shutdown.yml", extra_vars={'parent_asset': parent_asset, 'url': url._asdict()})
    return asset

@shared_task(bind=True)
def ipmi_poweron(self, asset):
    if asset['asset_type'] == 'server':
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], ['chassis', 'power', 'on'])
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    elif asset['asset_type'] == 'vm':
        parent_asset = AssetSerializer.get(service_tag=asset['parent'])
        if 'url' in parent_asset and parent_asset['url'].startswith("ansible://"):
            url = urlparse(parent_asset['url'])
            run_playbook(asset, url.path.lstrip("/") + "poweron.yml", extra_vars={'parent_asset': parent_asset, 'url': url._asdict()})
    return asset

@shared_task(bind=True)
def ipmi_reboot(self, asset):
    if asset['asset_type'] == 'server':
        # 'boot' means:
        # if server is on, reboot.
        # if server is off, power on.
        try:
            if 'on' in ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], ['chassis', 'power', 'status']):
                ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], ['chassis', 'power', 'reset'])
            else:
                ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], ['chassis', 'power', 'on'])
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    elif asset['asset_type'] == 'vm':
        parent_asset = AssetSerializer.get(service_tag=asset['parent'])
        if 'url' in parent_asset and parent_asset['url'].startswith("ansible://"):
            url = urlparse(parent_asset['url'])
            run_playbook(asset, url.path.lstrip("/") + "reboot.yml", extra_vars={'parent_asset': parent_asset, 'url': url._asdict()})
    return asset

@shared_task(bind=True)
def ipmi_boot_pxe(self, asset):
    pxe_boot_command = ['chassis', 'bootdev', 'pxe']
    if asset['asset_type'] == 'server':
        if asset.get('efi', False):
            pxe_boot_command.append('options=efiboot')
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], pxe_boot_command)
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    return asset

@shared_task(bind=True)
def ipmi_ping(self, asset):
    if asset['asset_type'] == 'server':
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], ['chassis', 'power', 'status'])
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    return asset

@shared_task(bind=True)
def ipmi_power_state(self, asset):
    if asset['asset_type'] == 'server':
        if asset.get('oob'):
            try:
                return ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], ['chassis', 'power', 'status']).replace('Chassis Power is ', '').strip()
            except IPMIException as e:
                self.retry(exc=e, countdown=3, max_retries=40)
        else:
            return 'unknown (asset missing oob)'
    elif asset['asset_type'] == 'vm':
        parent_asset = AssetSerializer.get(service_tag=asset['parent'])
        if 'url' in parent_asset and parent_asset['url'].startswith("ansible://"):
            url = urlparse(parent_asset['url'])
            return run_playbook_with_output(asset, url.path.lstrip("/") + "power-state.yml", extra_vars={'parent_asset': parent_asset, 'url': url._asdict()})['result']

def reconfigure_network_port_ansible(switch_asset, url, asset):
    switch = url.netloc.split("@")[-1]
    ansible_asset = asset_get(asset['service_tag'])

    if asset.get('provisioning', False) or asset.get('maintenance', False) or asset.get('decommissioning', False):
        if 'provision' not in ansible_asset:
            ansible_asset['provision'] = {}
        if 'vlan' not in ansible_asset['provision']:
            ansible_asset['provision']['vlan'] = {}
        ansible_asset['provision']['vlan']['network'] = NetworkSerializer.get_by_domain_install(domain=switch_asset['switch']['domain'])
        ansible_asset['provision'].pop('vlans', None)
    elif 'provision' in ansible_asset:
        if 'vlan' in ansible_asset['provision']:
            ansible_asset['provision']['vlan']['network'] = NetworkSerializer.get_by_asset_vlan(domain=switch_asset['switch']['domain'], vlan=ansible_asset['provision']['vlan'])
        for vlan in ansible_asset['provision'].get('vlans', []):
            vlan['network'] = NetworkSerializer.get_by_asset_vlan(domain=switch_asset['switch']['domain'], vlan=vlan)

    additional_vlans = []

    conn = get_connection()
    # Automatically add networks for hypervisors
    try:
        cluster_asset = r.table('assets'). \
            filter({'state': 'in-use', 'asset_type': 'vmcluster'}). \
            filter(lambda x: x['hypervisors'].contains(asset['service_tag'])). \
            nth(0).run(conn)
    except:
        pass
    else:
        additional_vlans = list(r.table('networks').filter(
            lambda network: network['domains'].has_fields(
                cluster_asset['service_tag']
            )
        ).merge(
            lambda network: {'asset_domain': network['domains'][switch_asset['switch']['domain']]}
        ).run(conn))

    if 'network' in asset and 'device' in asset['network']:
        remote_domain = switch_asset['switch']['domain']
        additional_vlans = list(r.table('networks').filter(
            lambda network: network['domains'].has_fields(
                remote_domain
            ) &
            network['domains'].has_fields(
                asset['network']['device']
            )
        ).merge(
            lambda network: {'asset_domain': network['domains'][remote_domain]}
        ).run(conn))

    elif 'switch' in asset and 'domain' in asset['switch']:
        remote_domain = switch_asset['switch']['domain']
        additional_vlans = list(r.table('networks').filter(
            lambda network: network['domains'].has_fields(
                remote_domain
            ) &
            network['domains'].has_fields(
                asset['switch']['domain']
            )
        ).merge(
            lambda network: {'asset_domain': network['domains'][remote_domain]}
        ).run(conn))

    run_playbook(ansible_asset, url.path.lstrip("/") + "reconfigure.yml",
                 switch=switch, extra_vars={
                     'switch_asset': switch_asset,
                     'url': url._asdict(),
                     'additional_vlans': additional_vlans,
                 })

def reconfigure_network_port_vm_ansible(parent_asset, url, asset):
    ansible_asset = asset_get(asset['service_tag'])

    if asset.get('provisioning', False):
        if 'provision' not in ansible_asset:
            ansible_asset['provision'] = {}
        if 'vlan' not in ansible_asset['provision']:
            ansible_asset['provision']['vlan'] = {}
        ansible_asset['provision']['vlan']['network'] = NetworkSerializer.get_by_domain_install(domain=parent_asset['service_tag'])
        ansible_asset['provision'].pop('vlans', None)
    elif 'provision' in ansible_asset:
        if 'vlan' in ansible_asset['provision']:
            ansible_asset['provision']['vlan']['network'] = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=ansible_asset['provision']['vlan'])
        for vlan in ansible_asset['provision'].get('vlans', []):
            vlan['network'] = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=vlan)

    update = run_playbook_with_output(
        ansible_asset,
        url.path.lstrip("/") + "reconfigure.yml",
        extra_vars={
            'parent_asset': parent_asset,
            'url': url._asdict(),
        }
    )
    return asset_update(ansible_asset, update)

@shared_task
def reconfigure_network_port(asset):
    if asset['asset_type'] in ('server', 'network', 'storage'):
        domains = set(map(lambda x: x.value, jsonpath_rw_ext.parse('$.nics[*].remote.domain').find(asset)))
        for domain in domains:
            switch_asset = next(AssetSerializer.filter(switch={'domain': domain}))
            url = urlparse(switch_asset['url'])
            if url.scheme == 'ansible':
                reconfigure_network_port_ansible(switch_asset, url, asset)
            else:
                raise Exception("Unknown switch URL scheme for %s" % switch_asset['service_tag'])
    elif asset['asset_type'] == 'vm':
        parent_asset = AssetSerializer.get(service_tag=asset['parent'])
        if 'url' in parent_asset and parent_asset['url'].startswith("ansible://"):
            url = urlparse(parent_asset['url'])
            asset = reconfigure_network_port_vm_ansible(parent_asset, url, asset)
    return asset

ansible_password_hider = re.compile(r'password=([^ ]+)')
@shared_task
def run_playbook(asset, playbook, **kwargs):
    extra_vars = {'asset': asset}
    if hasattr(settings, 'ANSIBLE_EXTRA_VARS'):
        extra_vars.update(settings.ANSIBLE_EXTRA_VARS)
    if 'extra_vars' in kwargs:
        extra_vars.update(kwargs['extra_vars'])

    hosts = [asset.get('provision', {}).get('hostname', asset['service_tag'] + '.' + settings.SOCRATES_OOB_DOMAIN)]
    #clause to run with switch as host if passed to function
    if 'switch' in kwargs:
        hosts = [kwargs.pop('switch')]

    template = NamedTemporaryFile(delete=False)

    #clause to include template if passed to function
    if 'template' in kwargs:
        template.write(kwargs.pop('template'))
        extra_vars['ev_template'] = template.name
        template.close()
    else:
        template.close()

    extra_vars_temp = NamedTemporaryFile(mode='w+', delete=False, suffix='.json')
    json.dump(extra_vars, extra_vars_temp, cls=JSONEncoder)
    extra_vars_temp.close()

    if settings.ANSIBLE_PLAYBOOK_DIR is None:
        return asset

    if not hasattr(settings, 'ANSIBLE_INVENTORY'):
        inventory = ",".join(hosts) + ","
    else:
        inventory = settings.ANSIBLE_INVENTORY

    p = subprocess.Popen([
        "ansible-playbook",
        "-i", inventory,
        "-e", "@" + extra_vars_temp.name,
        "-l", ":".join(hosts),
        os.path.join(settings.ANSIBLE_PLAYBOOK_DIR, playbook)
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    prefix = "%s: %s: " % (asset['service_tag'], playbook)
    for line in stdout.splitlines():
        if line:
            line = line.decode("utf-8")
            line = ansible_password_hider.sub("password=HIDDEN", line)
            logger.info(prefix + line)
    for line in stderr.splitlines():
        if line:
            line = line.decode("utf-8")
            line = ansible_password_hider.sub("password=HIDDEN", line)
            logger.error(prefix + line)

    if p.returncode != 0:
        raise Exception("Playbook run of %s failed on %s with %d" % (playbook, asset['service_tag'], p.returncode))

    os.remove(extra_vars_temp.name)
    os.remove(template.name)

    return asset

@shared_task
def run_playbook_with_output(*args, **kwargs):
    output = NamedTemporaryFile(delete=False)
    output.close()
    if 'extra_vars' not in kwargs:
        kwargs['extra_vars'] = {}
    kwargs['extra_vars']['socrates_output'] = output.name
    run_playbook(*args, **kwargs)
    f = open(output.name)
    data = json.load(f)
    f.close()
    os.unlink(output.name)
    return data

def get_ipam(asset, forward_user=True, username=None):
    if forward_user and username is None:
        history = HistorySerializer.filter({'object': {'id': asset['id']}})
        for entry in sorted(history, key=lambda x: x['object']['version'], reverse=True):
            if 'username' in entry and entry['username']:
                username = entry['username']
                break
    return import_string(settings.SOCRATES_IPAM)(settings, username)

@shared_task
def add_to_dns(asset, old_asset=None):
    ipam = get_ipam(asset)
    update = {'log': 'Provisioned to DNS', 'provision': copy.deepcopy(asset['provision'])}
    changed = False
    old_vlans = {}
    now_vlans = dict(map(lambda x: (x['suffix'], x), filter(lambda x: 'suffix' in x, update['provision'].get('vlans', []))))
    if old_asset is not None and 'provision' in old_asset and 'cidr' in old_asset['provision'].get('vlan', ''):
        # Handle moves to a new network
        if asset['provision']['vlan']['cidr'] != old_asset['provision']['vlan']['cidr']:
            changed = True
            old_network = NetworkSerializer.get_by_asset_vlan(old_asset, old_asset['provision']['vlan'])
            if 'ip' in old_asset['provision']['vlan']:
                ipam.ip_address_remove(old_network, asset, old_asset['provision']['hostname'], old_asset['provision']['vlan']['ip'])
            new_network = NetworkSerializer.get_by_asset_vlan(asset, asset['provision']['vlan'])
            kwargs = {}
            if 'ip' in asset['provision']['vlan'] and ipv4_network_contains(asset['provision']['vlan']['cidr'], asset['provision']['vlan']['ip']):
                kwargs['ip'] = asset['provision']['vlan']['ip']
            if 'ports' in asset['provision']['vlan']:
                kwargs['mac'] = [nic['mac'] for nic in asset['nics'] if nic['name'] in asset['provision']['vlan']['ports']]
            else:
                kwargs['mac'] = [nic['mac'] for nic in asset['nics']]
            update['provision']['vlan']['ip'] = ipam.ip_address_allocate(new_network, asset, asset['provision']['hostname'], **kwargs)

        # Handle changing hostname
        elif asset['provision']['hostname'] != old_asset['provision']['hostname']:
            network = NetworkSerializer.get_by_asset_vlan(asset, asset['provision']['vlan'])
            ipam.ip_address_update(network, asset, asset['provision']['hostname'], asset['provision']['vlan']['ip'])
            for cidr, vlan in now_vlans.items():
                network = NetworkSerializer.get_by_asset_vlan(asset, vlan)
                shortname, domain = asset['provision']['hostname'].split(".", 1)
                hostname = "%s%s.%s" % (shortname, vlan['suffix'], domain)
                ipam.ip_address_update(network, asset, hostname, vlan['ip'])

        # Remove old additional VLANs
        old_vlans = dict(map(lambda x: (x['suffix'], x), filter(lambda x: 'suffix' in x, old_asset['provision'].get('vlans', []))))
        for suffix in set(old_vlans.keys()) - set(now_vlans.keys()):
            vlan = old_vlans[suffix]
            network = NetworkSerializer.get_by_asset_vlan(old_asset, vlan)
            shortname, domain = old_asset['provision']['hostname'].split(".", 1)
            hostname = "%s%s.%s" % (shortname, vlan['suffix'], domain)
            ipam.ip_address_remove(network, asset, hostname, vlan['ip'])

    else:
        # Add new host
        changed = True
        network = NetworkSerializer.get_by_asset_vlan(asset, asset['provision']['vlan'])
        kwargs = {}
        if 'ip' in asset['provision']['vlan']:
            kwargs['ip'] = asset['provision']['vlan']['ip']
        if 'ports' in asset['provision']['vlan']:
            kwargs['mac'] = [nic['mac'] for nic in asset['nics'] if nic['name'] in asset['provision']['vlan']['ports']]
        else:
            kwargs['mac'] = [nic['mac'] for nic in asset['nics']]
        update['provision']['vlan']['ip'] = ipam.ip_address_allocate(network, asset, asset['provision']['hostname'], **kwargs)

    # Add new additional VLANs
    for suffix in set(now_vlans.keys()) - set(old_vlans.keys()):
        changed = True
        vlan = now_vlans[suffix]
        network = NetworkSerializer.get_by_asset_vlan(asset, vlan)
        shortname, domain = asset['provision']['hostname'].split(".", 1)
        hostname = "%s%s.%s" % (shortname, vlan['suffix'], domain)
        kwargs = {}
        if 'ip' in vlan:
            kwargs['ip'] = vlan['ip']
        if 'ports' in vlan and vlan.get('native', False):
            kwargs['mac'] = [nic['mac'] for nic in asset['nics'] if nic['name'] in vlan['ports']]
        vlan['ip'] = ipam.ip_address_allocate(network, asset, hostname, **kwargs)

    if changed:
        asset = asset_update(asset, update)

    now_aliases = set(asset['provision'].get('aliases', []))
    old_aliases = set()
    if old_asset is not None and 'provision' in old_asset:
        old_aliases = set(old_asset['provision'].get('aliases', []))
    for alias in now_aliases - old_aliases:
        ipam.cname_add(asset, alias, asset['provision']['hostname'])
    for alias in old_aliases - now_aliases:
        ipam.cname_remove(asset, alias)

    return asset

def remove_ip_from_asset(asset):
    new_asset = copy.deepcopy(asset)
    if 'provision' in asset and 'vlan' in asset['provision'] and 'ip' in asset['provision']['vlan']:
        new_asset['provision']['vlan'] = dict([(key, val) for key, val in asset['provision']['vlan'].items() if key != "ip"])
        new_asset['provision']['vlans'] = [dict([(key, val) for key, val in vlan.items() if key != "ip"]) for vlan in asset['provision'].get('vlans', [])]
    new_asset['log'] = 'Removed from DNS'
    return asset_replace(asset, new_asset)

@shared_task
def remove_from_dns(asset):
    ipam = get_ipam(asset)
    for vlan in [asset['provision'].get('vlan', {})] + asset['provision'].get('vlans', []):
        if 'cidr' in vlan:
            network = NetworkSerializer.get_by_asset_vlan(asset, vlan)
        else:
            network = None
        shortname, domain = asset['provision']['hostname'].split(".", 1)
        hostname = "%s%s.%s" % (shortname, vlan.get('suffix', ""), domain)
        ipam.ip_address_remove(network, asset, hostname, vlan.get('ip', None))
    for alias in asset['provision'].get('aliases', []):
        ipam.cname_remove(asset, alias)
    return remove_ip_from_asset(asset)

def remove_vm_service_tags(asset, present_service_tags):
    conn = get_connection()
    all_vms = set([vm_asset['service_tag'] for vm_asset in
        r.table('assets').get_all(asset['service_tag'], index='parent').filter(lambda asset: asset['state'] != "deleted").pluck("service_tag").run(conn)
    ])
    for removed_vm in all_vms - present_service_tags:
        asset = AssetSerializer.get(service_tag=removed_vm)
        update = {
            'state': 'deleted',
            'provisioning': False,
            'log': 'Removed VM',
        }
        asset_update(asset, update)

@shared_task
def provision_vm(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    if 'url' in parent_asset and parent_asset['url'].startswith("ansible://"):
        url = urlparse(parent_asset['url'])
        ansible_asset = asset_get(asset['service_tag'])
        if asset.get('provisioning', False):
            ansible_asset['provision']['vlan']['network'] = NetworkSerializer.get_by_domain_install(domain=parent_asset['service_tag'])
        else:
            ansible_asset['provision']['vlan']['network'] = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=asset['provision']['vlan'])
        for vlan in ansible_asset['provision'].get('vlans', []):
            vlan['network'] = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=vlan)
        os = OperatingSystemSerializer.get(name=asset['provision']['os'])
        update = run_playbook_with_output(ansible_asset, url.path.lstrip("/") + "provision.yml", extra_vars={'parent_asset': parent_asset, 'url': url._asdict(), 'os': os.get('ids')})
        return asset_update(asset, update)
    return asset

@shared_task
def remove_vm(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    if 'url' in parent_asset and parent_asset['url'].startswith("ansible://"):
        url = urlparse(parent_asset['url'])
        update = run_playbook_with_output(asset, url.path.lstrip("/") + "decommission.yml", extra_vars={'parent_asset': parent_asset, 'url': url._asdict()})
        return asset_update(asset, update)

def collect_vms_ansible(asset):
    url = urlparse(asset['url'])
    vms = run_playbook_with_output(asset, url.path.lstrip("/") + "collect.yml", extra_vars={'url': url._asdict()})
    service_tags = set()
    for vm in vms:
        service_tags.add(vm['service_tag'])
        try:
            vm_asset = AssetSerializer.get(service_tag=service_tag)
            vm['log'] = 'Discovered VM'
            if vm_asset['state'] != 'ready':
                vm['state'] = 'in-use'
            asset_update(vm_asset, vm)
        except RethinkObjectNotFound:
            data = {
                'state': 'in-use',
                'asset_type': 'vm',
                'asset_subtype': asset['asset_subtype'],
                'version': 1,
                'service_tag': vm['service_tag'],
                'parent': asset['service_tag'],
                'log': 'Discovered VM',
            }
            data.update(vm)
            vm_asset = AssetSerializer(None, data=data)
            vm_asset.is_valid(raise_exception=True)
            vm_asset.save()

    remove_vm_service_tags(asset, service_tags)
    return len(vms)

@shared_task
def collect_vms(asset):
    if 'url' in asset and asset['url'].startswith("ansible://"):
        return collect_vms_ansible(asset)

@shared_task
def collect_all_vms():
    task = group([collect_vms.s(asset) for asset in AssetSerializer.filter(asset_type='vmcluster', state='in-use')]).apply_async()

@shared_task
def collect_vm_networks(asset):
    return 0

@shared_task
def collect_switch_networks(asset):
    networks = 0
    url = urlparse(asset['url'])
    if url.scheme == 'ansible':
        siblings = AssetSerializer.filter(lambda switch:
            switch.has_fields('switch') &
            (switch['url'] == asset['url'])
        )
        sibling_domains = [switch['switch']['domain'] for switch in siblings]
        friends = [nic['remote']['domain'] for nic in asset.get('nics', []) if 'remote' in nic]
        related_switches = sibling_domains + friends
        firewalls = AssetSerializer.filter(lambda firewall:
            firewall.has_fields('network') &
            firewall['network'].has_fields('device') &
            (firewall['nics'].map(lambda nic: nic['remote']['domain']).
                set_intersection(related_switches).count() > 0)
        )
        firewall_domains = [x['network']['device'] for x in firewalls]
        switch = url.netloc.split("@")[-1]
        for domain in run_playbook_with_output(asset, url.path.lstrip("/") + "collect.yml", switch=switch, extra_vars={'url': url._asdict(), 'collect': 'switch'}):
            try:
                network = NetworkSerializer.get(
                    reduce(r.or_,
                        map(lambda d:
                                r.row['domains'].has_fields(d) &
                                (r.row['domains'][d]['vlan_id'] == domain['vlan_id']),
                            firewall_domains
                        ),
                        False
                    )
                )
            except RethinkObjectNotFound:
                logger.warning("network for VLAN id %d on domain %s not found", domain['vlan_id'], asset['switch']['domain'])
                continue
            networks += 1
            changes = {}
            if asset['switch']['domain'] in network['domains']:
                if domain['name'] != network['domains'][asset['switch']['domain']]['name']:
                    changes['domains'] = {asset['switch']['domain']: domain}
            else:
                changes['domains'] = {asset['switch']['domain']: domain}
            if changes:
                serializer = NetworkSerializer(network, data=changes, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
    return networks

def collect_firewall_networks_ansible(asset, url):
    networks = 0
    hypervisors = [x['service_tag'] for x in AssetSerializer.filter({'asset_type': 'vmcluster', 'state': 'in-use'})]
    for network in run_playbook_with_output(asset, url.path.lstrip("/") + "collect.yml", switch=url.netloc.split("@")[-1], extra_vars={'url': url._asdict(), 'collect': 'firewall'}):
        networks += 1
        try:
            current = NetworkSerializer.get(vrf=network['vrf'], network=network['network'], length=network['length'])
        except RethinkObjectNotFound:
            serializer = NetworkSerializer(None, data=network)
            serializer.is_valid(raise_exception=True)
            serializer.save()
        else:
            diff = deepdiff.DeepDiff(current, network, view='tree')
            if any([x in diff for x in ['values_changed', 'dictionary_item_added', 'iterable_item_added']]):
                serializer = NetworkSerializer(current, data=network, partial=True)
                serializer.is_valid(raise_exception=True)
                serializer.save()
    return networks

@shared_task
def collect_firewall_networks(asset):
    if 'url' not in asset:
        return 0
    url = urlparse(asset['url'])
    if url.scheme == 'ansible':
        return collect_firewall_networks_ansible(asset, url)
    return 0

@shared_task
def collect_networks():
    networks = 0
    for asset in AssetSerializer.filter(r.row.has_fields({'network': {'device': True}, 'url': True})):
        networks += collect_firewall_networks(asset)
    for asset in AssetSerializer.filter(r.row.has_fields({'switch': True, 'url': True})):
        networks += collect_switch_networks(asset)
    for asset in AssetSerializer.filter(asset_type='vmcluster', state='in-use'):
        networks += collect_vm_networks(asset)
    return networks

@shared_task
def begin_maintenance(asset):
    if asset.get('provision') and asset['provision'].get('hostname'):
        return run_playbook(asset, 'maintenance-begin.yml')
    return asset

@shared_task
def end_maintenance(asset):
    if asset.get('provision') and asset['provision'].get('hostname'):
        return run_playbook(asset, 'maintenance-end.yml')
    return asset

@shared_task
def remove_hypervisor_from_cluster(asset):
    try:
        cluster_asset = next(r.table('assets').filter(
                {'asset_type': 'vmcluster'}).filter(lambda x:
                    x['hypervisors'].contains(asset['service_tag'])
                ).run(get_connection()))
        update_hvlist = [x for x in cluster_asset['hypervisors'] if x != asset['service_tag']]
        update = {'log': 'Removed hypervisor',
                  'hypervisors': update_hvlist}
        asset_update(cluster_asset, update)
    except r.errors.ReqlCursorEmpty:
        pass
    return asset

@shared_task
def event_emit(asset, event):
    event = EventSerializer(None, data={
        'event': event,
        'asset_id': asset['id'],
        'service_tag': asset['service_tag'],
        'version': asset['version'],
        'timestamp': timezone.now(),
    })
    event.is_valid(raise_exception=True)
    event.save()
    return asset

@shared_task
def asset_drop_provision(asset, physically):
    new_asset = copy.deepcopy(asset)
    del new_asset['provision']
    new_asset['log'] = 'Cleaned out provision'
    if physically:
        del new_asset['parent']
        del new_asset['parent_position']
    return asset_replace(asset, new_asset)

@shared_task
def cleanup_taskqueue():
    r.table('celery_taskqueue').filter(r.row['timestamp'].lt(timezone.now() - datetime.timedelta(seconds=settings.CELERY_RESULT_EXPIRES))).delete().run(get_connection())

def add_network_ansible(asset, network, url):
    switch = url.netloc.split("@")[-1]
    domain = run_playbook_with_output(asset, url.path.lstrip("/") + "add-network.yml", switch=switch, extra_vars={'network': network, 'url': url._asdict()})
    serializer = NetworkSerializer(network, data={'domains': {domain['domain']: domain}}, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return asset

def remove_network_ansible(asset, network, url):
    switch = url.netloc.split("@")[-1]
    run_playbook(asset, url.path.lstrip("/") + "remove-network.yml", switch=switch, extra_vars={'network': network, 'url': url._asdict()})
    return asset

@shared_task
def add_network(asset, network):
    ipam = get_ipam(asset, False)
    network = NetworkSerializer.get(id=network['id'])
    network['ipam'] = ipam.ip_prefix_get(network)
    if asset['asset_type'] == 'vmcluster':
        url = urlparse(asset['url'])
        if url.scheme == 'ansible':
            return add_network_ansible(asset, network, url)
    elif 'url' in asset:
        url = urlparse(asset['url'])
        if url.scheme == 'ansible':
            return add_network_ansible(asset, network, url)

@shared_task
def remove_network(asset, network):
    if asset['asset_type'] == 'vmcluster':
        url = urlparse(asset['url'])
        if url.scheme == 'ansible':
            return remove_network_ansible(asset, network, url)
    elif 'url' in asset:
        url = urlparse(asset['url'])
        if url.scheme == 'ansible':
            return remove_network_ansible(asset, network, url)

def firewall_apply_ansible(asset, url, networks, address_groups, rulesets):
    return run_playbook(asset, url.path.lstrip("/") + "apply.yml",
                        switch=url.netloc.split("@")[-1],
                        extra_vars={'url': url._asdict(), 'networks': networks, 'rulesets': rulesets, 'address_groups': address_groups})

@shared_task
def firewall_apply(asset):
    if 'url' not in asset:
        return False
    url = urlparse(asset['url'])
    address_groups = [a for a in FirewallAddressGroupSerializer.filter()]
    networks = [n for n in NetworkSerializer.filter()]
    rulesets = [r for r in FirewallRuleSetSerializer.filter()]
    if url.scheme == 'ansible':
        return firewall_apply_ansible(asset, url, networks, address_groups, rulesets)
    return False

@shared_task
def firewall_apply_all():
    tasks = []
    for asset in AssetSerializer.filter({'asset_subtype': 'firewall'}):
        if asset.get('url'):
            tasks.append(firewall_apply.si(asset))
    chain(tasks).apply_async()

def _firewall_group_manage_ansible(asset, name, url, group):
    return run_playbook(asset, url.path.lstrip("/") + name + ".yml",
        switch=url.netloc.split("@")[-1],
        extra_vars={'url': url._asdict(), 'group': group})

def _firewall_group_manage(group, name):
    for asset in AssetSerializer.filter(r.row.has_fields({'network': {'device': True}, 'url': True})):
        if 'url' not in asset:
            continue
        url = urlparse(asset['url'])
        if url.scheme == 'ansible':
            _firewall_group_manage_ansible(asset, name, url, group)

@shared_task
def firewall_add_group(group):
    return _firewall_group_manage(group, "add-group")

@shared_task
def firewall_update_group(group):
    return _firewall_group_manage(group, "set-group")

@shared_task
def firewall_remove_group(group):
    return _firewall_group_manage(group, "remove-group")

def _run_load_balancer_playbook(load_balancer, playbook):
    asset = asset_get(load_balancer['cluster'])
    urls = {}
    for service_tag in asset['composed_of']:
        subasset = asset_get(service_tag)
        urls[subasset['url']] = subasset
    if 'irules' in load_balancer:
        irules = list(LoadBalancerIRuleSerializer.filter(lambda irule:
            r.expr(load_balancer['irules']).contains(irule['name'])))
    else:
        irules = []
    for subasset in urls.values():
        url = urlparse(subasset['url'])
        switch = url.netloc.split("@")[-1]
        run_playbook(subasset, url.path.lstrip("/") + playbook, switch=switch, extra_vars={'lbcluster': asset, 'load_balancer': load_balancer, 'irules': irules, 'url': url._asdict()})

@shared_task
def add_load_balancer(load_balancer):
    return _run_load_balancer_playbook(load_balancer, 'add-lb.yml')

@shared_task
def update_load_balancer(load_balancer):
    return _run_load_balancer_playbook(load_balancer, 'set-lb.yml')

@shared_task
def remove_load_balancer(load_balancer):
    return _run_load_balancer_playbook(load_balancer, 'remove-lb.yml')

@shared_task
def remove_from_load_balancers(asset):
    load_balancers = LoadBalancerSerializer.filter(
        lambda lb: lb['members'].contains(
            lambda m: m['name'] == asset['provision']['hostname']
        )
    )
    for load_balancer in load_balancers:
        serializer = LoadBalancerSerializer(load_balancer, data={
            'members': [m for m in load_balancer['members']
                              if m['name'] != asset['provision']['hostname']],
        }, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
    return asset

@shared_task
def add_cluster_networks(cluster_asset):
    tasks = []
    for network in NetworkSerializer.filter(lambda n: n['domains'].has_fields(cluster_asset['service_tag'])):
        tasks.append(add_network.si(cluster_asset, network))
    chain(tasks).apply_async()
    return cluster_asset
