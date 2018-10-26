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
import urlparse
import copy
import datetime
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
from pyghmi.ipmi import command
from pyghmi import exceptions as pyghmi_exception
from kombu.utils.json import JSONEncoder
from netaddr import IPNetwork, IPAddress

try:
    import pyVmomi
    import pyVim.connect
    import ssl
    HAS_VMWARE = True
except ImportError:
    HAS_VMWARE = False

try:
    import ovirtsdk
    import ovirtsdk.api
    import ovirtsdk.xml
    HAS_OVIRT = True
except ImportError:
    HAS_OVIRT = False

try:
    import libvirt
    from lxml import etree
    from cStringIO import StringIO
    HAS_LIBVIRT = True
except ImportError:
    HAS_LIBVIRT = False

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
    raw_asset = r.table("assets_raw").get_all(service_tag, index="service_tag").run(conn).next()
    data = {}
    data['cpu'] = map(lambda x: x.value, jsonpath_rw_ext.parse('$..children[?class="processor"].version').find(raw_asset))
    try:
        memory = jsonpath_rw_ext.parse('$..children[?id="memory"]').find(raw_asset)[0].value
    except IndexError:
        memories = filter(lambda x: x['id'].startswith("memory"), map(lambda x: x.value, jsonpath_rw_ext.parse('$..children[?class="memory"]').find(raw_asset)))
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
        dmidata.write(base64.b64decode(raw_asset['intake']['dmidecode']))
        dmidata.flush()
        if data['vendor'] == 'HP':
            p = subprocess.Popen(["dmidecode", "--from-dump", dmidata.name, "-t", "204", "-q"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if p.returncode == 0:
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
        data['parent'] = raw_asset['intake']['ipmicfg']['fru']['Chassis Serial number (CS)']
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
                switch_asset = AssetSerializer.filter({'switch': {'domain': system_m.group(1)}}).next()
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
                by_id = ["disk/by-id/" + by_id for by_id, node in raw_asset['intake']['by_id_map'].iteritems() if node in device['logicalname'] and (by_id.startswith("scsi-") or by_id.startswith("ata-"))]
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
        for vdisk, by_id in raw_asset['raid-config']['vdisks_by_id'].iteritems():
            if vdisk in instance['provision']['storage'] and 'by_id' not in instance['provision']['storage'][vdisk]:
                if 'provision' not in data:
                    data['provision'] = {}
                if 'storage' not in data['provision']:
                    data['provision']['storage'] = {}
                if vdisk not in data['provision']['storage']:
                    data['provision']['storage'][vdisk] = {}
                data['provision']['storage'][vdisk]['by_id'] = by_id

    dmidata = NamedTemporaryFile()
    dmidata.write(base64.b64decode(raw_asset['intake']['dmidecode']))
    dmidata.flush()
    p = subprocess.Popen(["dmidecode", "--from-dump", dmidata.name], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    dmidecode_out, dmidecode_err = p.communicate()
    dmidecode_rc = p.returncode
    dmidata.close()

    slots = {}
    if dmidecode_rc == 0:
        designation = None
        address = None
        for line in dmidecode_out.splitlines():
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

def _extract_dell_warranty_from_raw(service_tag):
    conn = get_connection()
    raw_asset = r.table("assets_raw").get_all(service_tag, index="service_tag").run(conn).next()
    warranty = {}
    if 'warranty' in raw_asset.keys():
        warranty = raw_asset['warranty']
    data = {}
    if warranty and warranty != "Invalid":
        raw_entitlements = warranty['AssetEntitlementData']
        entitlements = {}
        next_end_date = None
        for wtype in (5, 11):
            if wtype == 5:
                stype = 'Machine'
            elif wtype == 11:
                stype = 'Disks'
            type_end_date = None
            for e in raw_entitlements:
                if e['ServiceLevelGroup'] == wtype:
                    current_end_date = pytz.utc.localize(datetime.datetime.strptime(e['EndDate'], "%Y-%m-%dT%H:%M:%S"))
                    if current_end_date > pytz.utc.localize(datetime.datetime.utcnow()):
                        if not type_end_date or current_end_date > type_end_date:
                            type_end_date = current_end_date
                            entitlements[stype] = {'description': e['ServiceLevelDescription'], 'end_date': current_end_date}
                            if not next_end_date or current_end_date < next_end_date:
                                next_end_date = current_end_date
        if warranty['AssetHeaderData']['OrderNumber']:
            data['order_number'] = warranty['AssetHeaderData']['OrderNumber']
        data['entitlements'] = entitlements
        data['shipping_date'] = pytz.utc.localize(datetime.datetime.strptime(warranty['AssetHeaderData']['ShipDate'], "%Y-%m-%dT%H:%M:%S"))
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
    batch = []
    result = {}
    for service_tag in service_tags:
        batch.append(service_tag)
        if len(batch) >= settings.DELL_API_BATCHSIZE:
            result.update(_send_dell_warranty_api_batch(batch))
            batch = []
            time.sleep(5)
    if len(batch) > 0:
        result.update(_send_dell_warranty_api_batch(batch))
    for service_tag, warranty in result.iteritems():
        status = r.table("assets_raw").get_all(service_tag, index="service_tag").update({"warranty": warranty}).run(get_connection())
        if max(status.values()) == 0:
            status = r.table('assets_raw').insert({'service_tag': service_tag, 'warranty': warranty}).run(get_connection())
        #if status['unchanged'] != 1:
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


def _send_dell_warranty_api_batch(batch):
    data = {"ID": ','.join(batch)}
    headers = {"apikey": settings.DELL_API_KEY, "accept" : "application/json", "Content-type" : "application/x-www-form-urlencoded"}
    for attempt in range(5):
        req = requests.post(settings.DELL_API_URL, data=data, headers=headers)
        if req.status_code == requests.codes.ok:
            result = {}
            raw = req.json()
            for item in raw["AssetWarrantyResponse"]:
                asset_tag = item["AssetHeaderData"]["ServiceTag"]
                result[asset_tag] = item
            for item in raw["InvalidBILAssets"]["BadAssets"]:
                result[item] = "Invalid"
            for item in raw["InvalidFormatAssets"]["BadAssets"]:
                result[item] = "Invalid"
            return result
        else:
            if attempt < 4:
                logger.info('Dell Warranty API request failed, status code: %s, attempt: %s, retrying in 5 seconds'%(str(req.status_code), attempt))
                time.sleep(5)
            else:
                logger.warn('Dell Warranty API request failed, status code: %s, attempt: %s, giving up!'%(str(req.status_code), attempt))
                raise Exception('Trouble connecting to Dell API: Status Code: ' + str(req.status_code) + ' - Message: ' + req.text)

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

def ipmi_command(service_tag, username, password, callback):
    try:
        session = command.Command(bmc=service_tag + '.' + settings.SOCRATES_OOB_DOMAIN, userid=username, password=password)
        # this looks ugly appending a dot like this but makes the variable
        # in settings look nicer.
        return callback(session)
    except pyghmi_exception.IpmiException as e:
        raise IPMIException("We have IPMI errors! %s: %s" % (service_tag, e.message))

@shared_task(bind=True)
def ipmi_shutdown(self, asset):
    if asset['asset_type'] == 'server':
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], lambda session: session.set_power('off', wait=False))
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    elif asset['asset_type'] == 'vm':
        if asset['asset_subtype'] == 'vmware':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)
            vm = find_vm_vmware(si, datacenter, asset)
            wait_for_task_completion_vmware(vm.PowerOffVM_Task())
            pyVim.connect.Disconnect(si)
        elif asset['asset_subtype'] == 'ovirt':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)
            vm = api.vms.get(id=vm_id_ovirt(asset))
            if vm.status.state != "down":
                vm.stop()
            while api.vms.get(id=vm_id_ovirt(asset)).status.state != "down":
                time.sleep(5)
            api.disconnect()
        elif asset['asset_subtype'] == 'libvirt':
            ipmi_shutdown_libvirt(asset)
    return asset

@shared_task(bind=True)
def ipmi_poweron(self, asset):
    if asset['asset_type'] == 'server':
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], lambda session: session.set_power('on', wait=False))
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    elif asset['asset_type'] == 'vm':
        if asset['asset_subtype'] == 'vmware':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)
            vm = find_vm_vmware(si, datacenter, asset)
            if vm.runtime.powerState == 'poweredOff':
                wait_for_task_completion_vmware(vm.PowerOnVM_Task())
            pyVim.connect.Disconnect(si)
        elif asset['asset_subtype'] == 'ovirt':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)
            vm = api.vms.get(id=vm_id_ovirt(asset))
            if vm.status.state != "up":
                vm.start()
            while api.vms.get(id=vm_id_ovirt(asset)).status.state != "up":
                time.sleep(5)
            api.disconnect()
        elif asset['asset_subtype'] == 'libvirt':
            ipmi_poweron_libvirt(asset)
    return asset

@shared_task(bind=True)
def ipmi_reboot(self, asset):
    if asset['asset_type'] == 'server':
        # 'boot' means:
        # if server is on, reboot.
        # if server is off, power on.
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], lambda session: session.set_power('boot', wait=False))
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    elif asset['asset_type'] == 'vm':
        if asset['asset_subtype'] == 'vmware':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)
            vm = find_vm_vmware(si, datacenter, asset)
            if vm.runtime.powerState == 'poweredOff':
                wait_for_task_completion_vmware(vm.PowerOnVM_Task())
            else:
                wait_for_task_completion_vmware(vm.ResetVM_Task())
            pyVim.connect.Disconnect(si)
        elif asset['asset_subtype'] == 'ovirt':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)
            vm = api.vms.get(id=vm_id_ovirt(asset))
            if vm.status.state == "up":
                vm.stop()
            vm.start()
            while api.vms.get(id=vm_id_ovirt(asset)).status.state != "up":
                time.sleep(5)
            api.disconnect()
        elif asset['asset_subtype'] == 'libvirt':
            ipmi_reboot_libvirt(asset)
    return asset

@shared_task(bind=True)
def ipmi_boot_pxe(self, asset):
    if asset['asset_type'] == 'server':
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], lambda session: session.set_bootdev('network', persist=False))
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    return asset

@shared_task(bind=True)
def ipmi_ping(self, asset):
    if asset['asset_type'] == 'server':
        try:
            ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], lambda session: session.get_power())
        except IPMIException as e:
            self.retry(exc=e, countdown=3, max_retries=40)
    return asset

@shared_task(bind=True)
def ipmi_power_state(self, asset):
    if asset['asset_type'] == 'server':
        if asset.get('oob'):
            try:
                return ipmi_command(asset['service_tag'], asset['oob']['username'], asset['oob']['password'], lambda session: session.get_power()['powerstate'])
            except IPMIException as e:
                self.retry(exc=e, countdown=3, max_retries=40)
        else:
            return 'unknown (asset missing oob)'
    elif asset['asset_type'] == 'vm':
        if asset['asset_subtype'] == 'vmware':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)
            vm = find_vm_vmware(si, datacenter, asset)
            if vm.runtime.powerState == 'poweredOn':
                ret = 'on'
            else:
                ret = 'off'
            pyVim.connect.Disconnect(si)
            return ret
        elif asset['asset_subtype'] == 'ovirt':
            parent_asset = AssetSerializer.get(service_tag=asset['parent'])
            api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)
            vm = api.vms.get(id=vm_id_ovirt(asset))
            if vm.status.state == "up":
                ret = 'on'
            else:
                ret = 'off'
            api.disconnect()
            return ret
        elif asset['asset_subtype'] == 'libvirt':
            return ipmi_power_state_libvirt(asset)

def reconfigure_network_port_vmware(asset):
    if asset['provisioning']:
        network_serializer = NetworkSerializer.get_by_domain_install(domain=asset['parent'])
    else:
        network_serializer = NetworkSerializer.get_by_asset_vlan(domain=asset['parent'], vlan=asset['provision']['vlan'])
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)
    network, backing = find_network_by_vlan_vmware(cluster, network_serializer)
    vm = find_vm_vmware(si, datacenter, asset)
    devices = [
        pyVmomi.vim.vm.device.VirtualDeviceSpec(
            operation=pyVmomi.vim.vm.device.VirtualDeviceSpec.Operation.edit,
            device=[device for device in vm.config.hardware.device if isinstance(device, pyVmomi.vim.vm.device.VirtualEthernetCard)][0],
        ),
    ]
    devices[0].device.backing = backing
    task = vm.ReconfigVM_Task(pyVmomi.vim.vm.ConfigSpec(deviceChange=devices))
    wait_for_task_completion_vmware(task)
    if task.info.state != pyVmomi.vim.TaskInfo.State.success:
        raise Exception("Failed to reconfigure networking on VM %s" % asset['provision']['hostname'])
    update = extract_asset_vmware(parent_asset, asset, cluster, vm)
    update['log'] = 'Reconfigured network port'
    pyVim.connect.Disconnect(si)
    return asset_update(asset, update)

def reconfigure_network_port_ovirt(asset):
    if asset['provisioning']:
        network_serializer = NetworkSerializer.get_by_domain_install(domain=asset['parent'])
    else:
        network_serializer = NetworkSerializer.get_by_asset_vlan(domain=asset['parent'], vlan=asset['provision']['vlan'])
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)
    vm = api.vms.get(id=vm_id_ovirt(asset))
    nic = vm.nics.list()[0]
    new_network = ovirtsdk.xml.params.Network(id=api.networks.get(name=network_serializer['asset_name']).id)
    if new_network.id != nic.network.id:
        nic.network = new_network
        nic.update()
    update = extract_asset_ovirt(parent_asset, asset, api, vm)
    update['log'] = 'Reconfigured network port'
    api.disconnect()
    return asset_update(asset, update)

def reconfigure_network_port_ansible(switch_asset, url, asset):
    switch = url.netloc.split("@")[-1]
    ansible_asset = asset_get(asset['service_tag'])

    if asset.get('provisioning', False) or asset.get('maintenance', False):
        if 'provision' not in ansible_asset:
            ansible_asset['provision'] = {}
        elif 'vlan' not in ansible_asset['provision']:
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

    if asset['asset_type'] == 'network' and 'network' in asset and 'device' in asset['network']:
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

    elif asset['asset_type'] == 'network' and 'switch' in asset and 'domain' in asset['switch']:
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
                     'url': url,
                     'additional_vlans': additional_vlans,
                 })

@shared_task
def reconfigure_network_port(asset):
    if asset['asset_type'] in ('server', 'network', 'storage'):
        domains = set(map(lambda x: x.value, jsonpath_rw_ext.parse('$.nics[*].remote.domain').find(asset)))
        for domain in domains:
            switch_asset = AssetSerializer.filter(switch={'domain': domain}).next()
            url = urlparse.urlparse(switch_asset['url'])
            if url.scheme == 'ansible':
                reconfigure_network_port_ansible(switch_asset, url, asset)
            else:
                raise Exception("Unknown switch URL scheme for %s" % switch_asset['service_tag'])
    elif asset['asset_type'] == 'vm':
        if asset['asset_subtype'] == 'vmware':
            asset = reconfigure_network_port_vmware(asset)
        elif asset['asset_subtype'] == 'ovirt':
            asset = reconfigure_network_port_ovirt(asset)
        elif asset['asset_subtype'] == 'libvirt':
            asset = reconfigure_network_port_libvirt(asset)
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

    extra_vars_temp = NamedTemporaryFile(delete=False, suffix='.json')
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
            line = ansible_password_hider.sub("password=HIDDEN", line)
            logger.info(prefix + line)
    for line in stderr.splitlines():
        if line:
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
            for cidr, vlan in now_vlans.iteritems():
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
        new_asset['provision']['vlan'] = dict([(key, val) for key, val in asset['provision']['vlan'].iteritems() if key != "ip"])
        new_asset['provision']['vlans'] = [dict([(key, val) for key, val in vlan.iteritems() if key != "ip"]) for vlan in asset['provision'].get('vlans', [])]
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

def connect_hypervisor_vmware(parent_asset):
    url = urlparse.urlparse(parent_asset['url'])
    sslcontext = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    if hasattr(settings, 'SOCRATES_VMWARE_CERT_VERIFY') and settings.SOCRATES_VMWARE_CERT_VERIFY:
        sslcontext.verify_mode = ssl.CERT_REQUIRED
    else:
        sslcontext.verify_mode = ssl.CERT_NONE
    si = pyVim.connect.SmartConnect(host=url.netloc, user=settings.SOCRATES_VMWARE_USERNAME, pwd=settings.SOCRATES_VMWARE_PASSWORD, sslContext=sslcontext)
    vcenter = si.RetrieveContent()
    _, datacenter_name, cluster_name = url.path.split("/")
    datacenter = filter(lambda x: x.name == datacenter_name, vcenter.rootFolder.childEntity)[0]
    cluster = filter(lambda x: x.name == cluster_name, datacenter.hostFolder.childEntity)[0]
    return si, vcenter, datacenter, cluster

def wait_for_task_completion_vmware(tasks):
    if not isinstance(tasks, list):
        tasks = [tasks]
    while any([task.info.state in (pyVmomi.vim.TaskInfo.State.queued, pyVmomi.vim.TaskInfo.State.running) for task in tasks]):
        time.sleep(5)
    return tasks

def find_network_name_by_backing_vmware(cluster, backing):
    for possible_network in cluster.network:
        if (isinstance(backing, pyVmomi.vim.vm.device.VirtualEthernetCard.DistributedVirtualPortBackingInfo) and
            isinstance(possible_network, pyVmomi.vim.dvs.DistributedVirtualPortgroup)):
            if (possible_network.config.distributedVirtualSwitch.uuid == backing.port.switchUuid and
                possible_network.key == backing.port.portgroupKey):
                return possible_network.name
        elif (isinstance(backing, pyVmomi.vim.vm.device.VirtualEthernetCard.NetworkBackingInfo) and
              isinstance(possible_network, pyVmomi.vim.Network)):
            if possible_network.name == backing.network.name:
                return possible_network.name
    return None

def find_network_by_vlan_vmware(cluster, network_serializer):
    pg_lookup = {}
    for pg in cluster.host[0].config.network.portgroup:
        pg_lookup[pg.spec.name] = pg.spec.vlanId

    for possible_network in cluster.network:
        if isinstance(possible_network, pyVmomi.vim.dvs.DistributedVirtualPortgroup):
            if possible_network.config.defaultPortConfig.vlan.vlanId == network_serializer['asset_domain']['vlan_id']:
                return possible_network, pyVmomi.vim.VirtualEthernetCardDistributedVirtualPortBackingInfo(
                    port=pyVmomi.vim.DistributedVirtualSwitchPortConnection(
                        portgroupKey=possible_network.key,
                        switchUuid=possible_network.config.distributedVirtualSwitch.uuid,
                    )
                )
        elif isinstance(possible_network, pyVmomi.vim.Network):
            if possible_network.name not in pg_lookup.keys():
                continue
            if pg_lookup[possible_network.name] == network_serializer['asset_domain']['vlan_id']:
                return possible_network, pyVmomi.vim.VirtualEthernetCardNetworkBackingInfo(
                    deviceName=possible_network.name,
                    network=possible_network,
                )
    else:
        raise Exception("Network %s couldn't be found in the designated cluster" % (network_serializer['asset_domain']['name']))

def find_vm_vmware(si, datacenter, asset):
    service_tag = asset['service_tag']
    uuid = asset['service_tag'][7:].replace(" ", "").replace("-", "")
    uuid = uuid[:8] + "-" + uuid[8:12] + "-" + uuid[12:16] + "-" + uuid[16:20] + "-" + uuid[20:]
    vm = si.content.searchIndex.FindByUuid(datacenter, uuid, True, False)
    if vm is None:
        raise Exception("VM for %s not found" % asset['service_tag'])
    return vm

def vm_service_tag_vmware(vm):
    uuid = vm.config.uuid.replace("-", "")
    uuid = " ".join([uuid[i:i+2] for i in range(0, len(uuid), 2)])
    uuid = uuid[:23] + '-' + uuid[24:]
    return 'VMware-' + uuid

def extract_asset_vmware(parent_asset, asset, cluster, vm, disk_map={}):
    update = {
        'parent': parent_asset['service_tag'],
        'service_tag': vm_service_tag_vmware(vm),
        'cpu': ['vCPU'] * vm.config.hardware.numCPU,
        'ram': {'slots': {}, 'total': vm.config.hardware.memoryMB << 20},
        'provision': {
            'hostname': vm.name,
        },
    }

    update['nics'] = []
    for id, nic in enumerate([x for x in vm.config.hardware.device if isinstance(x, pyVmomi.vim.VirtualEthernetCard)]):
        vlan_name = find_network_name_by_backing_vmware(cluster, nic.backing)
        update['nics'].append({
            'name': "eth%d" % id,
            'mac': nic.macAddress,
            'remote': {
                'domain': parent_asset['service_tag'],
                'name': vlan_name,
            },
        })

    update['storage'] = []
    for disk in vm.config.hardware.device:
        if not isinstance(disk, pyVmomi.vim.vm.device.VirtualDisk):
            continue
        for data_class, volumes in parent_asset['storage'][0]['datastores'].iteritems():
            if disk.backing.datastore.name in volumes:
                break
        else:
            data_class = None
        if disk.unitNumber in disk_map:
            if 'storage' not in update['provision']:
                update['provision']['storage'] = {}
            update['provision']['storage'][disk_map[disk.unitNumber]] = {
                'storage_id': disk.backing.uuid,
            }
        update['storage'].append({
            'capacity': disk.capacityInKB << 10,
            'filename': disk.backing.fileName,
            'class': data_class,
            'id': disk.backing.uuid,
        })

    return update

def collect_vms_vmware(asset):
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(asset)
    vm_view = vcenter.viewManager.CreateContainerView(vcenter.rootFolder, [pyVmomi.vim.VirtualMachine], True)
    service_tags = set()
    for vm in vm_view.view:
        if cluster != vm.runtime.host.parent:
            continue
        service_tag = vm_service_tag_vmware(vm)
        service_tags.add(service_tag)
        try:
            vm_asset = AssetSerializer.get(service_tag=service_tag)
            update = extract_asset_vmware(asset, vm_asset, cluster, vm)
            update['log'] = 'Discovered VM'
            if vm_asset['state'] != 'ready':
                update['state'] = 'in-use'
            asset_update(vm_asset, update)
        except RethinkObjectNotFound:
            data = {
                'state': 'in-use',
                'asset_type': 'vm',
                'asset_subtype': 'vmware',
                'version': 1,
                'service_tag': service_tag,
                'parent': asset['service_tag'],
                'log': 'Discovered VM',
            }
            data.update(extract_asset_vmware(asset, data, cluster, vm))
            vm_asset = AssetSerializer(None, data=data)
            vm_asset.is_valid(raise_exception=True)
            vm_asset.save()

    remove_vm_service_tags(asset, service_tags)
    pyVim.connect.Disconnect(si)

def new_virtual_disk_vmware(asset, parent_asset, datacenter, cluster, disk_id, disk_name, disk, controller_key=5000):
    datastores = sorted(filter(lambda x: x.name in parent_asset['storage'][0]['datastores'][disk['class']], cluster.datastore), key=lambda x: x.info.freeSpace - (x.summary.uncommitted if isinstance(x.summary.uncommitted, (int, long)) else 0))
    datastore = datastores[-1]
    if disk_id >= 7:
        disk_id += 1
    return pyVmomi.vim.VirtualDisk(
        key=6000 + disk_id,
        controllerKey=controller_key,
        unitNumber=disk_id,
        capacityInKB=disk['size'] >> 10,
        backing=pyVmomi.vim.VirtualDiskFlatVer2BackingInfo(
            fileName='[%s] %s/%s-%s.vmdk' % (
                datastore.name, asset['provision']['hostname'], asset['provision']['hostname'], disk_name),
            datastore=datastore,
            diskMode='persistent',
            thinProvisioned=True
            )
        )

def reprovision_vm_vmware(asset, parent_asset):
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)
    vm = find_vm_vmware(si, datacenter, asset)

    device_changes = []
    tasks = []
    seen_disks = set()
    seen_networks = {}
    controller_key = None
    for device in vm.config.hardware.device:
        if isinstance(device, pyVmomi.vim.vm.device.VirtualDisk):
            controller_key = device.controllerKey
            for data_class, volumes in parent_asset['storage'][0]['datastores'].iteritems():
                if device.backing.datastore.name in volumes:
                    break
            else:
                data_class = None
            capacity = device.capacityInKB << 10 if device.capacityInBytes is None else device.capacityInBytes
            for name, info in asset['provision']['storage'].iteritems():
                if 'storage_id' in info and info['storage_id'] == device.backing.uuid:
                    seen_disks.add(name)
                    if abs(capacity - asset['provision']['storage'][name]['size']) > 1024:
                        device.capacityInKB = asset['provision']['storage'][name]['size'] >> 10
                        device_changes.append(pyVmomi.vim.vm.device.VirtualDeviceSpec(
                            operation=pyVmomi.vim.vm.device.VirtualDeviceSpec.Operation.edit,
                            device=device,
                        ))

        elif isinstance(device, pyVmomi.vim.VirtualEthernetCard):
            seen_networks[find_network_name_by_backing_vmware(cluster, device.backing)] = device

    disk_map = {}
    disk_id = len(seen_disks)
    for new_disk in sorted(set(asset['provision']['storage'].keys()) - seen_disks):
        disk_id += 1
        device_changes.append(pyVmomi.vim.vm.device.VirtualDeviceSpec(
            operation=pyVmomi.vim.vm.device.VirtualDeviceSpec.Operation.add,
            fileOperation=pyVmomi.vim.vm.device.VirtualDeviceSpec.FileOperation.create,
            device=new_virtual_disk_vmware(asset, parent_asset, datacenter, cluster, disk_id, new_disk, asset['provision']['storage'][new_disk], controller_key=controller_key),
        ))
        disk_map[device_changes[-1].device.unitNumber] = new_disk

    # Special case for the simple one of one interface
    if len(seen_networks) == 1 and len(asset['provision'].get('vlans', [])) == 0:
        network_serializer = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=asset['provision']['vlan'])
        if seen_networks.keys()[0] != network_serializer['asset_name']:
            device = seen_networks.values()[0]
            network, device.backing = find_network_by_vlan_vmware(cluster, network_serializer)
            device_changes.append(pyVmomi.vim.vm.device.VirtualDeviceSpec(
                operation=pyVmomi.vim.vm.device.VirtualDeviceSpec.Operation.edit,
                device=device,
            ))
    else:
        nic_id = 4000 + len(seen_networks)
        network_serializers = {}
        for vlan in [asset['provision']['vlan']] + asset['provision'].get('vlans', []):
            network_serializer = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=vlan)
            network_serializers[network_serializer['asset_name']] = network_serializer
        for network_name in set(seen_networks.keys()) - set(network_serializers.keys()):
            network, backing = find_network_by_vlan_vmware(cluster, network_serializers[network_name])
            device_changes.append(pyVmomi.vim.vm.device.VirtualDeviceSpec(
                operation=pyVmomi.vim.vm.device.VirtualDeviceSpec.Operation.add,
                device=pyVmomi.vim.VirtualVmxnet3(
                    key=4000 + nic_id,
                    backing=backing,
                    addressType='generated',
                ),
            ))
            nic_id += 1

    config_spec = pyVmomi.vim.vm.ConfigSpec(
        deviceChange=device_changes,
        name=asset['provision']['hostname'],
        numCPUs=asset['provision']['cpus'],
        memoryMB=asset['provision']['ram'] >> 20,
    )
    tasks.append(vm.ReconfigVM_Task(config_spec))

    wait_for_task_completion_vmware(tasks)
    for task in tasks:
        if task.info.state != pyVmomi.vim.TaskInfo.State.success:
            raise Exception("Reprovision VM task failed for %s" % asset['service_tag'])

    update = {'log': 'Reprovisioned VM'}
    update.update(extract_asset_vmware(parent_asset, asset, cluster, vm, disk_map))

    pyVim.connect.Disconnect(si)
    return asset_update(asset, update)

def provision_vm_vmware(asset, parent_asset):
    if asset['state'] == 'in-use':
        return reprovision_vm_vmware(asset, parent_asset)

    update = {'asset_subtype': 'vmware'}
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)

    os = OperatingSystemSerializer.get(name=asset['provision']['os'])
    vmspec = pyVmomi.vim.VirtualMachineConfigSpec()
    vmspec.name = asset['provision']['hostname']
    vmspec.guestId = 'rhel7_64Guest'
    if 'ids' in os and 'vmware' in os['ids']:
        vmspec.guestId = os['ids']['vmware']
    if 'ids' in os and 'vmware_hw' in os['ids']:
        vmspec.version = os['ids']['vmware_hw']
    vmspec.memoryMB = asset['provision']['ram'] >> 20
    vmspec.numCPUs = asset['provision']['cpus']
    vmspec.bootOptions = pyVmomi.vim.VirtualMachineBootOptions(bootRetryEnabled=True, bootRetryDelay=10000)

    # Add NIC
    network_serializer = NetworkSerializer.get_by_domain_install(domain=parent_asset['service_tag'])
    network, backing = find_network_by_vlan_vmware(cluster, network_serializer)

    vmspec.deviceChange.append(
        pyVmomi.vim.VirtualDeviceConfigSpec(
            operation=pyVmomi.vim.VirtualDeviceConfigSpecOperation.add,
            device=pyVmomi.vim.VirtualVmxnet3(
                key=4000,
                backing=backing,
                addressType='generated'
                )
            )
        )

    nic_id = 4001
    for vlan in asset['provision'].get('vlans', []):
        network_serializer = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=vlan)
        network, backing = find_network_by_vlan_vmware(cluster, network_serializer)
        vmspec.deviceChange.append(
            pyVmomi.vim.VirtualDeviceConfigSpec(
                operation=pyVmomi.vim.VirtualDeviceConfigSpecOperation.add,
                device=pyVmomi.vim.VirtualVmxnet3(
                    key=nic_id,
                    backing=backing,
                    addressType='generated'
                )
            )
        )
        nic_id += 1

    # Add a scsi adapter
    vmspec.deviceChange.append(
        pyVmomi.vim.VirtualDeviceConfigSpec(
            operation=pyVmomi.vim.VirtualDeviceConfigSpecOperation.add,
            device=pyVmomi.vim.ParaVirtualSCSIController(
                key=5000,
                sharedBus=pyVmomi.vim.VirtualSCSISharing.noSharing,
                busNumber=0
                )
            )
        )

    # Create and add a disk
    disk_map = {}
    for disk_id, disk in enumerate(sorted(asset['provision']['storage'].iteritems(), key=lambda v: "\x00%s" % v[1].get('by_id', v[0]) if v[0] == 'os' else v[1].get('by_id', v[0]))):
        disk_name, disk = disk
        vmspec.deviceChange.append(
            pyVmomi.vim.VirtualDeviceConfigSpec(
                operation=pyVmomi.vim.VirtualDeviceConfigSpecOperation.add,
                fileOperation=pyVmomi.vim.VirtualDeviceConfigSpecFileOperation.create,
                device=new_virtual_disk_vmware(asset, parent_asset, datacenter, cluster, disk_id, disk_name, disk),
            )
        )
        disk_map[vmspec.deviceChange[-1].device.unitNumber] = disk_name
        if disk_name == 'os':
            vmspec.files = pyVmomi.vim.vm.FileInfo(vmPathName='[%s] %s' % (vmspec.deviceChange[-1].device.backing.datastore.name, asset['provision']['hostname']))
    vmspec.extraConfig.append(pyVmomi.vim.OptionValue(key='bios.bootDeviceClasses', value='allow:hd,net'))

    createvmtask = datacenter.vmFolder.CreateVM_Task(config=vmspec, pool=cluster.resourcePool)
    wait_for_task_completion_vmware(createvmtask)
    if createvmtask.info.state != pyVmomi.vim.TaskInfo.State.success:
        raise Exception("Create VM task failed for %s" % asset['provision']['hostname'])

    update.update(extract_asset_vmware(parent_asset, asset, cluster, createvmtask.info.result, disk_map))

    update['log'] = 'Provisioned to VMware'

    pyVim.connect.Disconnect(si)
    return asset_update(asset, update)

def add_network_vmware(asset, network):
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(asset)
    name = network['domains'][asset['service_tag']]['name']
    vlan_id = network['domains'][asset['service_tag']]['vlan_id']
    dvs_list = [x['dvswitch'] for x in asset['nics'] if 'dvswitch' in x.keys()]
    vs_list = [x['vswitch'] for x in asset['nics'] if 'vswitch' in x.keys()]
    dvs_view = si.content.viewManager.CreateContainerView(si.content.rootFolder, [pyVmomi.vim.DistributedVirtualSwitch], True).view

    for dv_switch in dvs_view:
        dv_pg = None
        if dv_switch.name in dvs_list:
            for n in dv_switch.portgroup:
                if n.config.defaultPortConfig.vlan.vlanId == vlan_id:
                    dv_pg = n
                    break
        if dv_switch.name in dvs_list and dv_pg is None:
            dv_pg_spec = pyVmomi.vim.dvs.DistributedVirtualPortgroup.ConfigSpec()
            dv_pg_spec.name = name
            dv_pg_spec.numPorts = 8
            dv_pg_spec.type = pyVmomi.vim.dvs.DistributedVirtualPortgroup.PortgroupType.earlyBinding
            dv_pg_spec.defaultPortConfig = pyVmomi.vim.dvs.VmwareDistributedVirtualSwitch.VmwarePortConfigPolicy()
            dv_pg_spec.defaultPortConfig.vlan = pyVmomi.vim.dvs.VmwareDistributedVirtualSwitch.VlanIdSpec()
            dv_pg_spec.defaultPortConfig.vlan.vlanId = vlan_id
            dv_pg_spec.defaultPortConfig.vlan.inherited = False

            task = dv_switch.AddDVPortgroup_Task([dv_pg_spec])
            wait_for_task_completion_vmware(task)
            if task.info.state != pyVmomi.vim.TaskInfo.State.success:
                raise Exception("Adding port group task failed for %s" % network['id'])

    for host in cluster.host:
        pg = None
        for portgroup in host.config.network.portgroup:
            if portgroup.spec.vswitchName in vs_list and portgroup.spec.vlanId == vlan_id:
                pg = portgroup
                break
        if not pg:
            for vswitch in vs_list:
                pg_spec = pyVmomi.vim.host.PortGroup.Specification()
                pg_spec.name = name
                pg_spec.vlanId = vlan_id
                pg_spec.vswitchName = vswitch
                pg_spec.policy = pyVmomi.vim.host.NetworkPolicy()
                host.configManager.networkSystem.AddPortGroup(portgrp=pg_spec)

    pyVim.connect.Disconnect(si)
    return asset

def remove_network_vmware(asset, network):
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(asset)
    vlan_id = network['domains'][asset['service_tag']]['vlan_id']
    dvs_list = [x['dvswitch'] for x in asset['nics'] if 'dvswitch' in x.keys()]
    vs_list = [x['vswitch'] for x in asset['nics'] if 'vswitch' in x.keys()]

    for n in cluster.network:
        if isinstance(n, pyVmomi.vim.dvs.DistributedVirtualPortgroup):
            if n.config.defaultPortConfig.vlan.vlanId == vlan_id and n.config.distributedVirtualSwitch.name in dvs_list:
                n.Destroy_Task()
        elif isinstance(n, pyVmomi.vim.Network):
            for portgroup in n.host[0].config.network.portgroup:
                if portgroup.spec.name == n.name and portgroup.spec.vlanId == vlan_id and portgroup.spec.vswitchName in vs_list:
                    for host in n.host:
                        host.configManager.networkSystem.RemovePortGroup(n.name)
    pyVim.connect.Disconnect(si)
    return asset

def connect_hypervisor_ovirt(parent_asset):
    url, path = parent_asset['url'].split("#", 1)
    api = ovirtsdk.api.API(
        str(url),
        username=settings.SOCRATES_OVIRT_USERNAME,
        password=settings.SOCRATES_OVIRT_PASSWORD,
        insecure=settings.SOCRATES_OVIRT_INSECURE,
    )
    datacenter_name, cluster_name = path.split("/", 1)
    datacenter = api.datacenters.get(name=str(datacenter_name))
    cluster = api.clusters.get(name=str(cluster_name))
    return api, datacenter, cluster

def vm_service_tag_ovirt(vm):
    return "ovirt-" + vm.id

def vm_id_ovirt(asset):
    return str(asset['service_tag'][6:])

def extract_asset_ovirt(parent_asset, asset, api, vm):
    update = {
        'parent': parent_asset['service_tag'],
        'service_tag': vm_service_tag_ovirt(vm),
        'cpu': ['vCPU'] * vm.cpu.topology.cores,
        'ram': {'slots': {}, 'total': vm.memory},
        'provision': {
            'hostname': vm.name,
        },
    }

    update['nics'] = []
    for id, nic in enumerate([x for x in vm.nics.list()]):
        vlan_name = api.networks.get(id=nic.network.id).name
        update['nics'].append({
            'name': "eth%d" % id,
            'mac': nic.mac.address,
            'remote': {
                'domain': parent_asset['service_tag'],
                'name': vlan_name,
            },
        })

    update['storage'] = []
    for disk in vm.disks.list():
        for data_class, volumes in parent_asset['storage'][0]['datastores'].iteritems():
            if api.storagedomains.get(id=disk.storage_domains.storage_domain[0].id).name in volumes:
                break
        else:
            data_class = None
        update['storage'].append({
            'capacity': disk.size,
            'filename': disk.name,
            'class': data_class,
        })

    return update

ovirt_filename_re = re.compile(r'[A-Za-z0-9-_.]*_(.+)')
def reprovision_vm_ovirt(asset, parent_asset):
    api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)
    vm = api.vms.get(id=vm_id_ovirt(asset))

    vm.name = asset['provision']['hostname']
    vm.cpu.topology.cores = asset['provision']['cpus']
    vm.memory = asset['provision']['ram']
    vm = vm.update()

    seen_disks = set()
    wait_for_disks = []
    for disk in vm.disks.list():
        m = ovirt_filename_re.match(disk.name)
        if m:
            name = m.group(1)
        else:
            raise Exception("Unknown disk name format: %s" % disk.name)
        seen_disks.add(name)
        if name in asset['provision']['storage']:
            if abs(disk.size - asset['provision']['storage'][name]['size']) > 1024:
                disk.provisioned_size = asset['provision']['storage'][name]['size']
                disk.update()
                wait_for_disks.append(disk.id)

    for disk_name in sorted(set(asset['provision']['storage'].keys()) - seen_disks):
        disk = asset['provision']['storage'][disk_name]
        storage_domains = sorted(map(lambda sd: api.storagedomains.get(name=str(sd)), parent_asset['storage'][0]['datastores'][disk['class']]), key=lambda sd: sd.available)
        wait_for_disks.append(vm.disks.add(ovirtsdk.xml.params.Disk(
            storage_domains=ovirtsdk.xml.params.StorageDomains(storage_domain=[storage_domains[-1]]),
            name='%s_%s' % (asset['provision']['hostname'], disk_name),
            size=disk['size'],
            interface='virtio',
            format='raw',
            sparse=True,
            bootable=disk_name == 'os'
        )).id)

    for disk_name in sorted(seen_disks - set(asset['provision']['storage'].keys())):
        disk = vm.disks.get(name='%s_%s' % (asset['provision']['hostname'], disk_name))
        disk.delete()

    while not all([api.disks.get(id=disk).status.state == 'ok' for disk in wait_for_disks]):
        time.sleep(5)

    update = {'log': 'Reprovisioned VM'}
    update.update(extract_asset_ovirt(parent_asset, asset, api, vm))

    api.disconnect()
    return asset_update(asset, update)

def provision_vm_ovirt(asset, parent_asset):
    if asset['state'] == 'in-use':
        return reprovision_vm_ovirt(asset, parent_asset)

    update = {'asset_subtype': 'ovirt'}
    api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)

    vm = api.vms.add(ovirtsdk.xml.params.VM(
        name=asset['provision']['hostname'],
        cpu=ovirtsdk.xml.params.CPU(topology=ovirtsdk.xml.params.CpuTopology(cores=asset['provision']['cpus'])),
        memory=asset['provision']['ram'],
        cluster=cluster,
        template=api.templates.get('Blank'),
        type_="server",
        os=ovirtsdk.xml.params.OperatingSystem(boot=[ovirtsdk.xml.params.Boot(dev="hd"), ovirtsdk.xml.params.Boot(dev="network")]),
        high_availability=ovirtsdk.xml.params.HighAvailability(enabled=True),
    ))

    network_serializer = NetworkSerializer.get_by_domain_install(domain=parent_asset['service_tag'])
    vm.nics.add(ovirtsdk.xml.params.NIC(name='nic1', network=ovirtsdk.xml.params.Network(name=network_serializer['asset_name']), interface='virtio'))

    nic_id = 2
    for vlan in asset['provision'].get('vlans', []):
        network_serializer = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=vlan)
        vm.nics.add(ovirtsdk.xml.params.NIC(name='nic%d' % nic_id, network=ovirtsdk.xml.params.Network(name=network_serializer['asset_name']), interface='virtio'))
        nic_id += 1

    for disk_name, disk in asset['provision']['storage'].iteritems():
        storage_domains = sorted(map(lambda sd: api.storagedomains.get(name=str(sd)), parent_asset['storage'][0]['datastores'][disk['class']]), key=lambda sd: sd.available)
        vm.disks.add(ovirtsdk.xml.params.Disk(
            storage_domains=ovirtsdk.xml.params.StorageDomains(storage_domain=[storage_domains[-1]]),
            name='%s_%s' % (asset['provision']['hostname'], disk_name),
            size=disk['size'],
            interface='virtio',
            format='raw',
            sparse=True,
            bootable=disk_name == 'os'
        ))

    while api.vms.get(id=vm.id).status.state != 'down':
        time.sleep(5)
    while not all([disk.status.state == 'ok' for disk in api.vms.get(id=vm.id).disks.list()]):
        time.sleep(5)

    update.update(extract_asset_ovirt(parent_asset, asset, api, api.vms.get(id=vm.id)))
    update['log'] = 'Provisioned to oVirt'
    asset = asset_update(asset, update)

    api.disconnect()

    return asset

def collect_vms_ovirt(asset):
    api, datacenter, cluster = connect_hypervisor_ovirt(asset)
    service_tags = set()
    for vm in api.vms.list():
        service_tag = vm_service_tag_ovirt(vm)
        service_tags.add(service_tag)
        try:
            vm_asset = AssetSerializer.get(service_tag=service_tag)
            update = extract_asset_ovirt(asset, vm_asset, api, vm)
            update['log'] = 'Discovered VM'
            update['state'] = 'in-use'
            asset_update(vm_asset, update)
        except RethinkObjectNotFound:
            data = {
                'state': 'in-use',
                'asset_type': 'vm',
                'asset_subtype': 'ovirt',
                'version': 1,
                'service_tag': service_tag,
                'parent': asset['service_tag'],
                'log': 'Discovered VM',
            }
            data.update(extract_asset_ovirt(asset, data, api, vm))
            vm_asset = AssetSerializer(None, data=data)
            vm_asset.is_valid(raise_exception=True)
            vm_asset.save()

    remove_vm_service_tags(asset, service_tags)
    api.disconnect()

def add_network_ovirt(asset, network):
    api, datacenter, cluster = connect_hypervisor_ovirt(asset)
    net = api.networks.add(ovirtsdk.xml.params.Network(
        name=network['domains'][asset['service_tag']]['name'],
        data_center=datacenter,
        description="%s/%d" % (network['network'], network['length']),
        vlan=ovirtsdk.xml.params.VLAN(id="%d" % network['domains'][asset['service_tag']]['vlan_id']),
    ))
    cluster.networks.add(net)
    api.disconnect()
    return asset

def remove_network_ovirt(asset, network):
    api, datacenter, cluster = connect_hypervisor_ovirt(asset)
    name = network['domains'][asset['service_tag']]['name']
    network = api.networks.get(name=name)
    network.delete()
    api.disconnect()
    return asset

@shared_task
def provision_vm(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    if parent_asset['asset_subtype'] == 'vmware':
        return provision_vm_vmware(asset, parent_asset)
    elif parent_asset['asset_subtype'] == 'ovirt':
        return provision_vm_ovirt(asset, parent_asset)
    elif parent_asset['asset_subtype'] == 'libvirt':
        return provision_vm_libvirt(asset, parent_asset)
    return asset

def remove_vm_vmware(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(parent_asset)
    vm = find_vm_vmware(si, datacenter, asset)
    destroytask = vm.Destroy_Task()
    wait_for_task_completion_vmware(destroytask)
    pyVim.connect.Disconnect(si)
    return asset

def remove_vm_ovirt(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api, datacenter, cluster = connect_hypervisor_ovirt(parent_asset)
    vm = api.vms.get(id=vm_id_ovirt(asset))
    task = vm.delete(async=False)
    api.disconnect()
    return asset

@shared_task
def remove_vm(asset):
    if asset['asset_subtype'] == 'vmware':
        return remove_vm_vmware(asset)
    elif asset['asset_subtype'] == 'ovirt':
        return remove_vm_ovirt(asset)
    elif asset['asset_subtype'] == 'libvirt':
        return remove_vm_libvirt(asset)

@shared_task
def collect_vms(asset):
    if asset['asset_subtype'] == 'vmware':
        return collect_vms_vmware(asset)
    elif asset['asset_subtype'] == 'ovirt':
        return collect_vms_ovirt(asset)
    elif asset['asset_subtype'] == 'libvirt':
        return collect_vms_libvirt(asset)

@shared_task
def collect_all_vms():
    task = group([collect_vms.s(asset) for asset in AssetSerializer.filter(asset_type='vmcluster', state='in-use')]).apply_async()

def collect_vm_networks_vmware(asset):
    si, vcenter, datacenter, cluster = connect_hypervisor_vmware(asset)
    hypervisor_asset = asset_get(asset['hypervisors'][0])
    hypervisor_domain = jsonpath_rw_ext.parse('$.nics[*].remote.domain').find(hypervisor_asset)[0].value
    networks = 0
    for network in cluster.network:
        if isinstance(network, pyVmomi.vim.dvs.DistributedVirtualPortgroup):
            vlan_id = network.config.defaultPortConfig.vlan.vlanId
        elif isinstance(network, pyVmomi.vim.Network):
            for portgroup in network.host[0].config.network.portgroup:
                if portgroup.spec.name == network.name:
                    vlan_id = portgroup.spec.vlanId
                    break
            else:
                continue
        else:
            continue
        if not isinstance(vlan_id, (int, long)):
            continue
        try:
            network_serializer = NetworkSerializer.get_by_domain_id(domain=hypervisor_domain, vlan_id=vlan_id)
        except RethinkObjectNotFound:
            continue
        changes = {}
        if asset['service_tag'] in network_serializer['domains']:
            if network_serializer['domains'][asset['service_tag']]['name'] != network.name:
                changes['domains'] = {asset['service_tag']: {
                    'name': network.name,
                    'vlan_id': vlan_id,
                }}
        else:
            changes['domains'] = {asset['service_tag']: {
                'name': network.name,
                'vlan_id': vlan_id
            }}
        networks += 1
        if changes:
            network_serializer = NetworkSerializer(network_serializer, data=changes, partial=True)
            network_serializer.is_valid(raise_exception=True)
            network_serializer.save()
    pyVim.connect.Disconnect(si)
    return networks

@shared_task
def collect_vm_networks(asset):
    if asset['asset_subtype'] == 'vmware':
        return collect_vm_networks_vmware(asset)
    elif asset['asset_subtype'] == 'libvirt':
        return collect_vm_networks_libvirt(asset)
    else:
        return 0

@shared_task
def collect_switch_networks(asset):
    networks = 0
    url = urlparse.urlparse(asset['url'])
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
        firewall_domains = map(lambda x: x['network']['device'], firewalls)
        switch = url.netloc.split("@")[-1]
        for domain in run_playbook_with_output(asset, url.path.lstrip("/") + "collect.yml", switch=switch, extra_vars={'url': url, 'collect': 'switch'}):
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
    hypervisors = map(lambda x: x['service_tag'], AssetSerializer.filter({'asset_type': 'vmcluster', 'state': 'in-use'}))
    for network in run_playbook_with_output(asset, url.path.lstrip("/") + "collect.yml", switch=url.netloc.split("@")[-1], extra_vars={'url': url, 'collect': 'firewall'}):
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
    url = urlparse.urlparse(asset['url'])
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
        schedule_and_propagate_downtime(asset)
    return asset

@shared_task
def end_maintenance(asset):
    #FIXME: remove scheduled downtime, OP5 API is lacking this feature. Awaiting https://jira.op5.com/browse/MON-6502
    return asset

def schedule_and_propagate_downtime(asset):
    url = settings.MONITOR_API_URL + settings.MONITOR_SCHEDULE_DOWNTIME_ENDPOINT
    user = settings.SOCRATES_OP5_USERNAME
    pwd = settings.SOCRATES_OP5_PASSWORD
    timestamp = int(time.time())

    data = {"host_name": asset['provision']['hostname'],
            "duration": settings.MONITOR_DOWNTIME_DEFAULT_DURATION,
            "fixed": True,
            "start_time": timestamp,
            "end_time": timestamp+settings.MONITOR_DOWNTIME_DEFAULT_DURATION,
            "trigger_id": 0,
            "comment": "downtime scheduled from Socrates"}

    r = requests.post(url, headers=settings.MONITOR_API_HEADERS, auth=(user, pwd), data=json.dumps(data))
    return asset

@shared_task
def remove_hypervisor_from_cluster(asset):
    try:
        cluster_asset = r.table('assets').filter(
                {'asset_type': 'vmcluster'}).filter(lambda x:
                    x['hypervisors'].contains(asset['service_tag'])
                ).run(get_connection()).next()
        update_hvlist = filter(lambda x: x != asset['service_tag'], cluster_asset['hypervisors'])
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

if HAS_LIBVIRT:
    libvirt_power_states = {
        libvirt.VIR_DOMAIN_NOSTATE: None,
        libvirt.VIR_DOMAIN_RUNNING: 'on',
        libvirt.VIR_DOMAIN_BLOCKED: 'on',
        libvirt.VIR_DOMAIN_PAUSED: 'off',
        libvirt.VIR_DOMAIN_SHUTDOWN: 'on',
        libvirt.VIR_DOMAIN_SHUTOFF: 'off',
        libvirt.VIR_DOMAIN_CRASHED: 'off',
        libvirt.VIR_DOMAIN_PMSUSPENDED: 'off',
    }

def wait_for_state_libvirt(vm, state):
    attempts = 20
    for _ in range(attempts):
        time.sleep(5)
        if (state == 'off' and not vm.isActive()) or (state == 'on' and vm.isActive()):
            break
    else:
        raise Exception("Failed to achieve state %s: %r" % (state, vm.isActive()))

def ipmi_shutdown_libvirt(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api = connect_hypervisor_libvirt(parent_asset)
    vm = find_vm_libvirt(api, asset)
    if vm.isActive():
        vm.destroy()
        wait_for_state_libvirt(vm, 'off')
    api.close()

def ipmi_poweron_libvirt(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api = connect_hypervisor_libvirt(parent_asset)
    vm = find_vm_libvirt(api, asset)
    if not vm.isActive():
        vm.create()
        wait_for_state_libvirt(vm, 'on')
    api.close()

def ipmi_reboot_libvirt(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api = connect_hypervisor_libvirt(parent_asset)
    vm = find_vm_libvirt(api, asset)
    if vm.isActive():
        vm.destroy()
    wait_for_state_libvirt(vm, 'off')
    vm.create()
    wait_for_state_libvirt(vm, 'on')
    api.close()

def ipmi_power_state_libvirt(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api = connect_hypervisor_libvirt(parent_asset)
    vm = find_vm_libvirt(api, asset)
    state = libvirt_power_states[vm.state()[0]]
    api.close()
    return state

def connect_hypervisor_libvirt(parent_asset):
    api = libvirt.open(parent_asset['url'])
    return api

def vm_service_tag_libvirt(vm):
    return "libvirt-" + vm.UUIDString()

def vm_id_libvirt(asset):
    return str(asset['service_tag'][8:])

def find_vm_libvirt(api, asset):
    return api.lookupByUUIDString(vm_id_libvirt(asset))

libvirt_units = {
    None: 0,
    'B': 0,
    'KiB': 10,
    'MiB': 20,
    'GiB': 30,
    'TiB': 40,
}
def extract_asset_libvirt(parent_asset, asset, api, vm, tree=None):
    if tree is None:
        root = etree.fromstring(vm.XMLDesc())
        tree = etree.ElementTree(root)

    cpus = int(tree.xpath("/domain/vcpu")[0].text)
    memory = tree.xpath("/domain/memory")[0]
    memory = int(memory.text) << libvirt_units[memory.get("unit", 'KiB')]
    update = {
        'parent': parent_asset['service_tag'],
        'service_tag': vm_service_tag_libvirt(vm),
        'cpu': ['vCPU'] * cpus,
        'ram': {'slots': {}, 'total': memory},
        'provision': {
            'hostname': vm.name(),
        },
    }

    networks = {}
    for network in api.listAllNetworks():
        network_root = etree.fromstring(network.XMLDesc())
        name = network_root.xpath("/network/name")[0].text
        forward = network_root.xpath("/network/forward")[0]
        if forward.get("mode") == "bridge":
            for interface in forward.xpath("interface"):
                networks[interface.get("dev")] = name
            for bridge in network_root.xpath("bridge"):
                networks[bridge.get("name")] = name

    update['nics'] = []
    for id, interface in enumerate(tree.xpath('/domain/devices/interface')):
        interface_type = interface.get('type', 'network')
        if interface_type == 'direct':
            source = interface.xpath('source')[0]
            if source.get('mode') == 'bridge':
                name = networks[source.get('dev')]
            else:
                raise Exception("Unknown direct mode: %s" % source.get('mode'))
        elif interface_type == 'network':
            name = interface.xpath('source')[0].get('network')
        elif interface_type == 'bridge':
            source = interface.xpath('source')[0]
            name = source.get('network')
            if not name:
                name = networks[source.get('bridge')]
        else:
            raise Exception("Unknown interface type: %s" % interface_type)
        update['nics'].append({
            'name': "eth%d" % id,
            'mac': interface.xpath("mac")[0].attrib['address'],
            'remote': {
                'domain': parent_asset['service_tag'],
                'name': name,
            },
        })

    pools = {}
    for data_class, pool_names in parent_asset['storage'][0]['datastores'].iteritems():
        for pool_name in pool_names:
            pools[pool_name] = data_class

    update['storage'] = []
    for disk in tree.xpath("/domain/devices/disk"):
        if disk.get('device', "disk") != "disk":
            continue
        source = disk.xpath("source")[0]
        type_to_field = {
            'file': 'file',
            'block': 'dev',
        }
        disk_type = disk.get('type', 'file')
        if disk_type == 'volume':
            vol = api.storagePoolLookupByName(source.get('pool')).storageVolLookupByName(source.get('volume'))
            path = vol.path()
        elif disk_type in type_to_field:
            path = source.get(type_to_field[disk_type])
            vol = api.storageVolLookupByPath(path)
        else:
            raise Exception("Unknown disk type: %s" % etree.tostring(disk))
        capacity = vol.info()[1]
        data_class = pools[vol.storagePoolLookupByVolume().name()]
        update['storage'].append({
            'capacity': capacity,
            'filename': path,
            'class': data_class,
        })

    return update

def collect_vms_libvirt(asset):
    api = connect_hypervisor_libvirt(asset)
    service_tags = set()
    for vm in api.listAllDomains():
        service_tag = vm_service_tag_libvirt(vm)
        service_tags.add(service_tag)
        try:
            vm_asset = AssetSerializer.get(service_tag=service_tag)
            update = extract_asset_libvirt(asset, vm_asset, api, vm)
            update['log'] = 'Discovered VM'
            if vm_asset['state'] != 'ready':
                update['state'] = 'in-use'
            asset_update(vm_asset, update)
        except RethinkObjectNotFound:
            data = {
                'state': 'in-use',
                'asset_type': 'vm',
                'asset_subtype': 'libvirt',
                'version': 1,
                'service_tag': service_tag,
                'parent': asset['service_tag'],
                'log': 'Discovered VM',
            }
            data.update(extract_asset_libvirt(asset, data, api, vm))
            vm_asset = AssetSerializer(None, data=data)
            vm_asset.is_valid(raise_exception=True)
            vm_asset.save()

    remove_vm_service_tags(asset, service_tags)
    api.close()

def new_virtual_disk_libvirt(asset, parent_asset, api, disk_id, disk_name, disk):
    pools = sorted(map(lambda x: api.storagePoolLookupByName(x), parent_asset['storage'][0]['datastores'][disk['class']]), key=lambda x: x.info()[3])
    pool = pools[-1]
    pool_type = etree.parse(StringIO(pool.XMLDesc())).getroot().get("type")
    xml = render_to_string('libvirt-create-volume.xml', context={
        'pool': pool,
        'pool_type': pool_type,
        'asset': asset,
        'parent_asset': parent_asset,
        'disk_id': disk_id,
        'disk_name': disk_name,
        'disk': disk,
    })
    return pool.createXML(xml)

libvirt_filename_re = re.compile(r'.*_(.+?)(\.raw)?$')
def reprovision_vm_libvirt(asset, parent_asset):
    api = connect_hypervisor_libvirt(parent_asset)
    vm = find_vm_libvirt(api, asset)

    root = etree.fromstring(vm.XMLDesc())
    tree = etree.ElementTree(root)
    data = extract_asset_libvirt(parent_asset, asset, api, vm, tree=tree)

    if len(data['cpu']) != asset['provision']['cpus']:
        vm.setVcpusFlags(asset['provision']['cpus'], libvirt.VIR_DOMAIN_AFFECT_CONFIG | libvirt.VIR_DOMAIN_VCPU_MAXIMUM)
        vm.setVcpusFlags(asset['provision']['cpus'], libvirt.VIR_DOMAIN_AFFECT_CONFIG)

    if data['ram']['total'] != asset['provision']['ram']:
        vm.setMemoryFlags(asset['provision']['ram'] >> 10, libvirt.VIR_DOMAIN_AFFECT_CONFIG | libvirt.VIR_DOMAIN_MEM_MAXIMUM)
        vm.setMemoryFlags(asset['provision']['ram'] >> 10, libvirt.VIR_DOMAIN_AFFECT_CONFIG)


    seen_vlans = dict(map(lambda x: (x['remote']['name'], x['mac']), data['nics']))
    vlans = {}
    for vlan in [asset['provision']['vlan']] + asset['provision'].get('vlans', []):
        network_serializer = NetworkSerializer.get_by_asset_vlan(asset=asset, vlan=vlan)
        vlans[network_serializer['asset_name']] = network_serializer

    for vlan_name in set(seen_vlans.keys()) - set(vlans.keys()):
        for mac in root.xpath("/domain/devices/interface/mac"):
            if mac.attrib['address'] != seen_vlans[vlan_name]:
                continue
            xml = etree.tostring(mac.getparent())
            break
        else:
            raise Exception("Unable to find interface for %s" % vlan_name)
        vm.detachDeviceFlags(xml, libvirt.VIR_DOMAIN_AFFECT_CONFIG)

    for vlan_name in set(vlans.keys()) - set(seen_vlans.keys()):
        xml = render_to_string('libvirt-attach-interface.xml', context={
            'asset': asset,
            'network': vlans[vlan_name],
        })
        vm.attachDeviceFlags(xml, libvirt.VIR_DOMAIN_AFFECT_CONFIG)


    seen_disks = dict(map(lambda x: (libvirt_filename_re.match(x['filename']).group(1), x), data['storage']))
    disks = set(asset['provision']['storage'].keys())
    for disk_name in set(seen_disks.keys()) - disks:
        for disk in root.xpath("/domain/devices/disk"):
            type_to_field = {
                'file': 'file',
                'block': 'dev',
                'volume': 'volume',
            }
            disk_type = disk.get('type', 'file')
            source = disk.xpath("source")[0]
            if disk_type in type_to_field and source.get(type_to_field[disk_type]) == seen_disks[disk_name]['filename']:
                xml = etree.tostring(disk)
                break
        else:
            raise Exception("Unable to find disk for %s" % disk_name)
        vm.detachDeviceFlags(xml, libvirt.VIR_DOMAIN_AFFECT_CONFIG)
        vol = api.storageVolLookupByPath(seen_disks[disk_name]['filename'])
        vol.delete()

    disk_id = len(seen_disks.keys())
    for disk in disks - set(seen_disks.keys()):
        vol = new_virtual_disk_libvirt(asset, parent_asset, api, disk_id, disk, asset['provision']['storage'][disk])
        disk_id += 1
        xml = render_to_string('libvirt-attach-volume.xml', context={
            'asset': asset,
            'vol': vol,
            'disk': asset['provision']['storage'][disk],
            'disk_name': disk,
            'disk_id': disk_id,
        })
        vm.attachDeviceFlags(xml, libvirt.VIR_DOMAIN_AFFECT_CONFIG)

    for disk_name in disks.intersection(seen_disks.keys()):
        if abs(asset['provision']['storage'][disk_name]['size'] - seen_disks[disk_name]['capacity']) > 1024:
            logger.info("Resizing %s from %d to %s", disk_name, seen_disks[disk_name]['capacity'], asset['provision']['storage'][disk_name]['size'])
            vol = api.storageVolLookupByPath(seen_disks[disk_name]['filename'])
            vol.resize(asset['provision']['storage'][disk_name]['size'])


    update = extract_asset_libvirt(parent_asset, asset, api, vm)
    update['log'] = 'Reprovisioned VM'

    api.close()
    return asset_update(asset, update)

def provision_vm_libvirt(asset, parent_asset):
    if asset['state'] == 'in-use':
        return reprovision_vm_libvirt(asset, parent_asset)

    update = {'asset_subtype': 'libvirt'}
    api = connect_hypervisor_libvirt(parent_asset)

    os = OperatingSystemSerializer.get(name=asset['provision']['os'])
    os_variant = "rhel7"
    if 'ids' in os and 'libvirt' in os['ids']:
        os_variant = os['ids']['libvirt']
    command = [
        "virt-install",
        "--connect", parent_asset['url'],
        "-n", asset['provision']['hostname'],
        "--hvm",
        "--memory", "%d" % (asset['provision']['ram'] >> 20),
        "--vcpus", "%d" % asset['provision']['cpus'],
        "--cpu", "host",
        "--os-variant", os_variant,
        "--boot", "hd,network,menu=on,useserial=on",
        "--graphics", "spice",
        "--autostart", "--noreboot", "--noautoconsole", "--print-xml"
    ]

    for disk_id, disk in enumerate(sorted(asset['provision']['storage'].iteritems(), key=lambda v: "\x00%s" % v[1].get('by_id', v[0]) if v[0] == 'os' else v[1].get('by_id', v[0]))):
        disk_name, disk = disk
        vol = new_virtual_disk_libvirt(asset, parent_asset, api, disk_id, disk_name, disk)
        command.extend([
            "--disk", "vol=%s/%s,serial=%s" % (vol.storagePoolLookupByVolume().name(), vol.name(), disk.get('by_id', disk_name))
        ])

    network_serializer = NetworkSerializer.get_by_domain_install(domain=parent_asset['service_tag'])
    command.extend([
        "--network", "network=%s" % network_serializer['asset_name']
    ])
    for vlan in asset['provision'].get('vlans', []):
        network_serializer = NetworkSerializer.get_by_asset_vlan(domain=parent_asset['service_tag'], vlan=vlan)
        command.extend([
            "--network", "network=%s" % network_serializer['asset_name']
        ])

    p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()
    if p.returncode != 0:
        raise Exception("virt-install failed with %d: %s%s" % (p.returncode, stdout, stderr))

    root = etree.fromstring(stdout)
    os = root.xpath("/domain/os")[0]
    smbios = etree.SubElement(os, "smbios")
    smbios.set("mode", "sysinfo")
    sysinfo = etree.SubElement(root, "sysinfo")
    sysinfo.set("type", "smbios")
    system = etree.SubElement(sysinfo, "system")
    entry = etree.SubElement(system, "entry")
    entry.set("name", "serial")
    entry.text = "libvirt-" + root.xpath("/domain/uuid")[0].text

    tree = etree.ElementTree(root)
    vm = api.defineXML(etree.tostring(tree))
    vm.setAutostart(1)

    update.update(extract_asset_libvirt(parent_asset, asset, api, vm, tree))
    update['log'] = 'Provisioned to libvirt'

    api.close()
    return asset_update(asset, update)

def reconfigure_network_port_libvirt(asset):
    if asset['provisioning']:
        network_serializer = NetworkSerializer.get_by_domain_install(domain=asset['parent'])
    else:
        network_serializer = NetworkSerializer.get_by_asset_vlan(domain=asset['parent'], vlan=asset['provision']['vlan'])
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api = connect_hypervisor_libvirt(parent_asset)
    vm = find_vm_libvirt(api, asset)
    root = etree.fromstring(vm.XMLDesc())
    interface = root.xpath("/domain/devices/interface")[0]
    source = interface.xpath("source")[0]

    network = api.networkLookupByName(network_serializer['asset_name'])
    net_root = etree.fromstring(network.XMLDesc())
    forward = net_root.xpath("forward")[0]
    if forward.get("mode") == "direct":
        source.set("dev", net_root.xpath("/forward/interface")[0].get("dev"))
    elif forward.get("mode") == "bridge":
        source.set("network", network.name())
        interface.set("type", "network")
    vm.updateDeviceFlags(etree.tostring(interface), libvirt.VIR_DOMAIN_AFFECT_CONFIG)
    if vm.isActive():
        vm.updateDeviceFlags(etree.tostring(interface), libvirt.VIR_DOMAIN_AFFECT_LIVE)
    update = extract_asset_libvirt(parent_asset, asset, api, vm)
    update['log'] = 'Reconfigured network port'
    api.close()
    return asset_update(asset, update)

def remove_vm_libvirt(asset):
    parent_asset = AssetSerializer.get(service_tag=asset['parent'])
    api = connect_hypervisor_libvirt(parent_asset)
    vm = find_vm_libvirt(api, asset)
    root = etree.fromstring(vm.XMLDesc())
    vm.undefine()
    for disk in root.xpath("/domain/devices/disk"):
        if disk.get('device', "disk") != "disk":
            continue
        source = disk.xpath("source")[0]
        type_to_field = {
            'file': 'file',
            'block': 'dev',
        }
        disk_type = disk.get('type', 'file')
        try:
            if disk_type == 'volume':
                vol = api.storagePoolLookupByName(source.get('pool')).storageVolLookupByName(source.get('volume'))
            elif disk_type in type_to_field:
                path = source.get(type_to_field[disk_type])
                vol = api.storageVolLookupByPath(path)
            else:
                raise Exception("Don't know how to delete type %s" % disk.get("type"))
            vol.delete()
        except libvirt.libvirtError:
            logger.warn("Failed to delete storage volume %s", etree.tostring(disk))
    api.close()
    return asset

def collect_vm_networks_libvirt(asset):
    api = connect_hypervisor_libvirt(asset)
    hypervisor_asset = asset_get(asset['hypervisors'][0])
    hypervisor_domain = jsonpath_rw_ext.parse('$.nics[*].remote.domain').find(hypervisor_asset)[0].value
    networks = 0

    for network in api.listAllNetworks():
        root = etree.fromstring(network.XMLDesc())
        forward = root.xpath("/network/forward")[0]
        name = root.xpath("name")[0].text
        if forward.get("mode") == "bridge":
            interface = forward.xpath("interface")
            bridge = root.xpath("/network/bridge")
            if len(interface) > 0:
                vlan_id = int(interface[0].get("dev").split(".", 1)[1])
            elif len(bridge) > 0:
                iface = api.interfaceLookupByName(bridge[0].get("name"))
                iface_root = etree.fromstring(iface.XMLDesc())
                vlan_id = int(iface_root.xpath("/interface/bridge/interface/vlan")[0].get("tag"))
            else:
                raise Exception("Unknown bridge network: %s" % name)
        else:
            continue
        try:
            network_serializer = NetworkSerializer.get_by_domain_id(domain=hypervisor_domain, vlan_id=vlan_id)
        except RethinkObjectNotFound:
            continue
        changes = {}
        if asset['service_tag'] in network_serializer['domains']:
            if network_serializer['domains'][asset['service_tag']]['name'] != name:
                changes['domains'] = {asset['service_tag']: {
                    'name': name,
                    'vlan_id': vlan_id
                }}
        else:
            changes['domains'] = {asset['service_tag']: {
                'name': name,
                'vlan_id': vlan_id
            }}
        networks += 1
        if changes:
            network_serializer = NetworkSerializer(network_serializer, data=changes, partial=True)
            network_serializer.is_valid(raise_exception=True)
            network_serializer.save()

    api.close()
    return networks

def add_network_libvirt(asset, network):
    api = connect_hypervisor_libvirt(asset)
    name = network['domains'][asset['service_tag']]['name']
    vlan_id = network['domains'][asset['service_tag']]['vlan_id']

    primary_interface = None
    if 'nics' not in asset or len(asset['nics']) == 0:
        management_ip = socket.gethostbyaddr(api.getHostname())[2][0]
        for if_name in api.listInterfaces():
            interface = api.interfaceLookupByName(if_name)
            if not interface.isActive():
                continue
            root = etree.fromstring(interface.XMLDesc())
            tree = etree.ElementTree(root)
            ip = tree.xpath('/interface/protocol[@family="ipv4"]/ip')
            if len(ip) == 0:
                continue
            ip = ip[0]
            if management_ip == ip.attrib['address']:
                primary_interface = if_name
    else:
        primary_interface = asset['nics'][0]['name']

    if_br_xml = render_to_string('libvirt-create-bridge-interface.xml', context={
        'asset': asset,
        'interface': primary_interface,
        'network': network,
        'name': name,
    })
    net_xml = render_to_string('libvirt-create-network.xml', context={
        'asset': asset,
        'interface': primary_interface,
        'network': network,
        'name': name,
    })
    try:
        if_br = api.interfaceLookupByName("br%d" % vlan_id)
    except libvirt.libvirtError:
        if_br = api.interfaceDefineXML(if_br_xml)
    if not if_br.isActive():
        if_br.create()
    try:
        net = api.networkLookupByName(name)
    except libvirt.libvirtError:
        net = api.networkDefineXML(net_xml)
    net.setAutostart(True)
    if not net.isActive():
        net.create()
    api.close()
    return asset

def remove_network_libvirt(asset, network):
    api = connect_hypervisor_libvirt(asset)
    name = network['domains'][asset['service_tag']]['name']
    try:
        net = api.networkLookupByName(name)
    except libvirt.libvirtError:
        pass
    else:
        net.destroy()
        net.undefine()
    try:
        iface = api.interfaceLookupByName("br%d" % network['domains'][asset['service_tag']]['vlan_id'])
    except libvirt.libvirtError:
        pass
    else:
        iface.destroy()
        iface.undefine()
    api.close()
    return asset

def add_network_ansible(asset, network, url):
    switch = url.netloc.split("@")[-1]
    domain = run_playbook_with_output(asset, url.path.lstrip("/") + "add-network.yml", switch=switch, extra_vars={'network': network, 'url': url})
    serializer = NetworkSerializer(network, data={'domains': {domain['domain']: domain}}, partial=True)
    serializer.is_valid(raise_exception=True)
    serializer.save()
    return asset

def remove_network_ansible(asset, network, url):
    switch = url.netloc.split("@")[-1]
    run_playbook(asset, url.path.lstrip("/") + "remove-network.yml", switch=switch, extra_vars={'network': network, 'url': url})
    return asset

@shared_task
def add_network(asset, network):
    ipam = get_ipam(asset, False)
    network = NetworkSerializer.get(id=network['id'])
    network['ipam'] = ipam.ip_prefix_get(network)
    if asset['asset_type'] == 'vmcluster':
        if asset['asset_subtype'] == 'vmware':
            return add_network_vmware(asset, network)
        elif asset['asset_subtype'] == 'ovirt':
            return add_network_ovirt(asset, network)
        elif asset['asset_subtype'] == 'libvirt':
            return add_network_libvirt(asset, network)
    elif 'url' in asset:
        url = urlparse.urlparse(asset['url'])
        if url.scheme == 'ansible':
            return add_network_ansible(asset, network, url)

@shared_task
def remove_network(asset, network):
    if asset['asset_type'] == 'vmcluster':
        if asset['asset_subtype'] == 'vmware':
            return remove_network_vmware(asset, network)
        elif asset['asset_subtype'] == 'ovirt':
            return remove_network_ovirt(asset, network)
        elif asset['asset_subtype'] == 'libvirt':
            return remove_network_libvirt(asset, network)
    elif 'url' in asset:
        url = urlparse.urlparse(asset['url'])
        if url.scheme == 'ansible':
            return remove_network_ansible(asset, network, url)

def firewall_apply_ansible(asset, url, network, rules, networks):
    return run_playbook(asset, url.path.lstrip("/") + "apply.yml",
        switch=url.netloc.split("@")[-1],
        extra_vars={'url': url, 'network': network, 'rules': rules, 'networks': networks})

@shared_task
def firewall_apply(asset, network):
    if 'url' not in asset:
        return False
    ruleset = FirewallRuleSetSerializer(FirewallRuleSetSerializer.get(name=network['ruleset']))
    rules = ruleset.resolve()
    networks = {}
    for rule in rules:
        for k in ['destination_addresses', 'source_addresses']:
            for ur_address in rule.get(k, []):
                ur_address['resolved'] = FirewallAddressSerializer(ur_address).resolve()
                for address in ur_address['resolved']:
                    try:
                        a_network = NetworkSerializer.get_by_ip(address['address'])
                        if a_network['id'] not in networks:
                            networks[a_network['id']] = a_network
                        address['network_id'] = a_network['id']
                    except RethinkObjectNotFound:
                        pass
    for other_network in networks.values():
        if 'ruleset' not in other_network:
            continue
        n_ruleset = FirewallRuleSetSerializer(FirewallRuleSetSerializer.get(name=other_network['ruleset']))
        other_network['resolved_rules'] = n_ruleset.resolve()
        for rule in other_network['resolved_rules']:
            for k in ['destination_addresses', 'source_addresses']:
                for ur_address in rule.get(k, []):
                    ur_address['resolved'] = FirewallAddressSerializer(ur_address).resolve()
    url = urlparse.urlparse(asset['url'])
    if url.scheme == 'ansible':
        return firewall_apply_ansible(asset, url, network, rules, networks)
    return False

def _firewall_group_manage_ansible(asset, name, url, group):
    return run_playbook(asset, url.path.lstrip("/") + name + ".yml",
        switch=url.netloc.split("@")[-1],
        extra_vars={'url': url, 'group': group})

def _firewall_group_manage(group, name):
    for asset in AssetSerializer.filter(r.row.has_fields({'network': {'device': True}, 'url': True})):
        if 'url' not in asset:
            continue
        url = urlparse.urlparse(asset['url'])
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
        url = urlparse.urlparse(subasset['url'])
        switch = url.netloc.split("@")[-1]
        run_playbook(subasset, url.path.lstrip("/") + playbook, switch=switch, extra_vars={'load_balancer': load_balancer, 'irules': irules, 'url': url})

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
            'members': filter(lambda m: m['name'] != asset['provision']['hostname'],
                load_balancer['members']),
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
