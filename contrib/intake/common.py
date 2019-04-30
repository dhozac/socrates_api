#!/usr/bin/python -tt

import os
import sys
import subprocess
import json
import re
import time
import shlex
import glob

def fail_json(msg):
    json.dump({'failed': True, 'msg': msg}, sys.stdout)
    sys.exit(1)

def call_with_output(command, error_msg, input=None, success=[0], env=None):
    p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
    stdout, stderr = p.communicate(input)
    if p.returncode not in success:
        fail_json(error_msg % {"returncode": p.returncode, "out": stdout, "err": stderr})
    return p.returncode, stdout, stderr

def find_by_id_symlink(device):
    rc, stdout, stderr = call_with_output(["udevadm", "info", "--name=%s" % device, "--query=symlink", "--export"], "Failed to get by-id path for %s" % device)
    for symlink in stdout.split():
        if symlink.startswith("disk/by-id/scsi-"):
            return symlink
    return device

def find_by_path_symlink(device):
    rc, stdout, stderr = call_with_output(["udevadm", "info", "--name=%s" % device, "--query=symlink", "--export"], "Failed to get by-id path for %s" % device)
    for symlink in stdout.split():
        if symlink.startswith("disk/by-path/"):
            return symlink.replace("disk/by-path/", "")
    return device

def dehumanize(size):
    suffix = {
        'MB': 1024 ** 2,
        'GB': 1024 ** 3,
        'TB': 1024 ** 4,
    }
    value, unit = size.split()
    return int(float(value) * suffix[unit])

def parse_om(suffix, filters=""):
    filters = [x.lower() for x in filters]
    cmd = ["omreport"] + suffix.split()
    try:
        data = subprocess.Popen(cmd, stdout=subprocess.PIPE).communicate()[0]
    except OSError, e:
        print >> sys.stderr, "problem running %s, %s" % (" ".join(cmd), e)
        sys.exit(1)
    data = data.replace(' ', '').splitlines()
    result = []
    for item in data:
        if ":" not in item:
            continue
        key, val = item.split(":", 1)
        if filters:
            if key.lower() not in filters:
                continue
        if len(result) == 0 or key in result[-1]:
            result.append({})
        result[-1][key] = val
    return result

def dell_disks():
    ctrlfilter = ['ID', 'Name', 'FirmwareVersion', 'CacheMemorySize']
    vdiskfilter = ['ID', 'Name', 'Layout', 'Size', 'DeviceName']
    pdiskfilter = ['ID', 'Name', 'Capacity', 'VendorID', 'PartNumber', 'SerialNo.', 'BusProtocol', 'Media', 'State', 'HotSpare']
    enclfilter = ['ID', 'Name', 'ServiceTag', 'FirmwareVersion']

    attempts = 0
    while attempts < 5:
        controllers = parse_om("storage controller", ctrlfilter)
        if len(controllers) > 0:
            break
        # systemd means that srvadmin isn't done starting up when we start running most of the time. ENTERPRISE SLEEP!
        time.sleep(30)
        attempts += 1

    for controller in controllers:
        controller['vdisks'] = parse_om("storage vdisk controller={0}".format(controller['ID']), vdiskfilter)
        for vdisk in controller['vdisks']:
            vdisk['DeviceName'] = find_by_id_symlink(vdisk['DeviceName'])
            vdisk['pdisks'] = parse_om("storage pdisk controller={0} vdisk={1}".format(controller['ID'], vdisk['ID']), ['ID', 'Name'])
        controller['pdisks'] = parse_om("storage pdisk controller={0}".format(controller['ID']), pdiskfilter)
        controller['enclosures'] = parse_om("storage enclosure controller={0}".format(controller['ID']), enclfilter)

    return controllers

def hp_disks():
    env = os.environ.copy()
    env['INFOMGR_BYPASS_NONSA'] = "1"

    def parse_hpssacli(output, block_starter, object_creator, attr_filter, new_line_ends_block=True):
        ret = []
        o = None
        for line in output.splitlines():
            if line.strip() == "":
                if new_line_ends_block:
                    o = None
                continue
            m = block_starter.match(line)
            if m:
                o = object_creator(m)
                ret.append(o)
            elif o is not None:
                for attr in attr_filter:
                    if callable(attr):
                        if attr(o, line):
                            break
                else:
                    key, val = map(lambda x: x.strip(), line.split(":", 1))
                    key = key.replace(" ", "")
                    if key in attr_filter:
                        o[key] = val
        return ret

    rc, out, err = call_with_output(["hpssacli", "controller", "all", "show", "detail"], "Failed to list HP controllers %(returncode)d:\n%(err)s\n", env=env, success=[0, 1])
    controller_re = re.compile(r'^(.*) in Slot ([0-9]+)')
    controllers = parse_hpssacli(out, controller_re, lambda m: {'Name': m.group(1), 'Slot': m.group(2)}, ['SerialNumber', 'FirmwareVersion', 'TotalCacheSize'])

    arrays = {}
    physicaldrive_re = re.compile(r'\s+physicaldrive (.*)')
    array_re = re.compile(r'\s+(array ([A-Z])|unassigned)')
    for controller in controllers:
        rc, out, err = call_with_output(["hpssacli", "controller", "slot=%s" % controller['Slot'], "physicaldrive", "all", "show", "detail"], "Failed to list HP physical drives %(returncode)d:\n%(err)s\n", env=env, success=[0, 1])
        if rc == 1 and 'Error: The specified controller does not have any physical drives on it.' not in out:
            fail_json('Failed to list HP physical drives %d:\n%s\n' % (rc, err))
        controller['pdisks'] = parse_hpssacli(out, physicaldrive_re, lambda m: {'ID': m.group(1)}, ['InterfaceType', 'Size', 'FirmwareRevision', 'SerialNumber', 'Model', 'DriveType'])
        last_array = None
        arrays[controller['Slot']] = {}
        for line in out.splitlines():
            a_m = array_re.match(line)
            p_m = physicaldrive_re.match(line)
            if a_m:
                last_array = a_m.group(2)
                arrays[controller['Slot']][last_array] = []
            elif p_m:
                arrays[controller['Slot']][last_array].append({'ID': p_m.group(1)})

    physicaldrive_member_re = re.compile(r'\s+physicaldrive (.*) \(')
    def get_physicaldrive(vdisk, line):
        m = physicaldrive_member_re.match(line)
        if m:
            vdisk['pdisks'] = vdisk.get('pdisks', []) + [{'ID': m.group(1)}]
            return True
        return False

    for controller in controllers:
        rc, out, err = call_with_output(["hpssacli", "controller", "slot=%s" % controller['Slot'], "logicaldrive", "all", "show", "detail"], "Failed to list HP logical drives %(returncode)d:\n%(err)s\n", env=env, success=[0, 1])
        controller['vdisks'] = parse_hpssacli(out, array_re, lambda m: {'label': m.group(2)}, ['UniqueIdentifier', 'FaultTolerance', 'DiskName', 'LogicalDrive', get_physicaldrive], False)
        for vdisk in controller['vdisks']:
            vdisk['ID'] = vdisk['LogicalDrive']
            vdisk['DiskName'] = find_by_id_symlink(vdisk['DiskName'])
            if 'pdisks' not in vdisk:
                vdisk['pdisks'] = arrays[controller['Slot']].get(vdisk['label'], [])

    enclosure_re = re.compile(r'\s+([\w\s]+) at Port (\w+), Box (\w+)')
    for controller in controllers:
        rc, out, err = call_with_output(["hpssacli", "controller", "slot=%s" % controller['Slot'], "enclosure", "all", "show", "detail"], "Failed to list HP enclosures %(returncode)d:\n%(err)s\n", env=env, success=[0, 1])
        controller['enclosures'] = parse_hpssacli(out, enclosure_re, lambda m: {'ID': "%s:%s" % (m.group(2), m.group(3)), 'Name': m.group(1)}, ['VendorID', 'SerialNumber', 'FirmwareVersion', 'DriveBays', 'Location'])

    return controllers

def generic_disks():
    controllers = {}

    rc, out, err = call_with_output(["/opt/MegaRAID/storcli/storcli64", "show", "J"], "Failed to run storcli64 show %(returncode)d:\n%(err)s\n")
    data = json.loads(out)
    for storcli_controller in data['Controllers'][0]['Response Data'].get('System Overview', []):
        controller = {
            'id': str(storcli_controller['Ctl']),
            'type': 'storcli',
            'product': '',
            'vdisks': [],
            'pdisks': [],
        }
        rc, out, err = call_with_output(["/opt/MegaRAID/storcli/storcli64", "/c%s" % controller['id'], "show", "all", "J"], "Failed to run storcli64 /c%s show %%(returncode)d:\n%%(err)s\n" % controller['id'])
        controller_data = json.loads(out)
        controller['product'] = controller_data['Controllers'][0]['Response Data']['Basics']['Model']
        for vdisk in controller_data['Controllers'][0]['Response Data'].get('VD LIST', []):
            device = os.path.basename(
                glob.glob(("/sys/bus/pci/devices/0000:%(Bus Number)02x:%(Device Number)02x.%(Function Number)x/host*/target*/*:%%s/block/*" % controller_data['Controllers'][0]['Response Data']['Bus']) % vdisk['DG/VD'].split("/")[1])[0]
            )
            controller['vdisks'].append({
                'id': vdisk['DG/VD'],
                'raid': vdisk['TYPE'].replace("RAID", "RAID-"),
                'name': vdisk['Name'],
                'by_id': find_by_id_symlink(device),
                'by_path': find_by_path_symlink(device),
                'pdisks': [],
            })
        for pdisk in controller_data['Controllers'][0]['Response Data'].get('PD LIST', []):
            controller['pdisks'].append({
                'id': pdisk['EID:Slt'],
                'vendor': pdisk['Model'],
                'capacity': dehumanize(pdisk['Size']),
                'bus': pdisk['Intf'],
                'media': pdisk['Med'],
            })
            for vdisk in controller['vdisks']:
                if vdisk['id'].startswith("%s/" % pdisk['DG']):
                    vdisk['pdisks'].append({'id': pdisk['EID:Slt']})
        controllers[controller['id']] = controller

    rc, out, err = call_with_output(["lsblk", "-P", "-b", "--output", "NAME,SERIAL,ROTA,SIZE,TYPE,VENDOR,MODEL"], "Failed to list block devices %(returncode)d:\n%(err)s\n")
    devices = {}
    for line in out.splitlines():
        info = dict([x.split("=", 1) for x in shlex.split(line)])
        devices[info['NAME']] = info

    real_vdisks = [vdisk['by_path'] for controller in controllers.values() for vdisk in controller['vdisks']]
    disks = filter(lambda x: not x.rstrip("0123456789").endswith("-part") and x not in real_vdisks, os.listdir("/dev/disk/by-path"))
    for disk in disks:
        controller, disk_type, disk_id = disk.rsplit("-", 2)
        if controller not in controllers:
            controllers[controller] = {'id': controller, 'type': 'direct', 'vdisks': [], 'pdisks': []}
        device = os.path.basename(os.readlink(os.path.join("/dev/disk/by-path/" + disk)))
        controllers[controller]['pdisks'].append({
            'id': '-'.join([disk_type, disk_id]),
            'by_path': disk,
            'vendor': devices[device]['VENDOR'],
            'model': devices[device]['MODEL'],
            'serial': devices[device]['SERIAL'],
            'capacity': int(devices[device]['SIZE']),
            'media': 'SSD' if devices[device]['ROTA'] == '0' else 'HDD',
        })
        rc, out, err = call_with_output(["mdadm", "-E", "/dev/disk/by-path/%s-part2" % disk], "Failed to examine disk %s with return %%(returncode)d:\n%%(err)s\n" % disk, success=[0, 1])
        if rc != 0:
            continue
        examined = dict([line.split(":", 1) for line in out.splitlines() if ':' in line])
        if 'Name' not in examined:
            continue
        examined['Name'] = re.sub(r'^([^ \t]*:)?([^ \t:]*) .*', r'\2', examined['Name'])
        for vdisk in controllers[controller]['vdisks']:
            if vdisk['name'] == examined['Name']:
                vdisk['pdisks'].append({'id': '-'.join([disk_type, disk_id]), 'uuid': examined['Device UUID']})
                break
        else:
            controllers[controller]['vdisks'].append({
                'id': examined['Array UUID'],
                'by_id': 'md-uuid-' + examined['Array UUID'],
                'name': examined['Name'],
                'raid': examined['Raid Level'].replace("raid", "RAID-"),
                'pdisks': [{'id': '-'.join([disk_type, disk_id]), 'uuid': examined['Device UUID']}],
            })

    return controllers.values()
