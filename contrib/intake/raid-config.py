#!/usr/bin/python -tt

import os
import sys
import subprocess
import json
import re
import string
import random
from common import *

def dell_same_config(old_vdisk, new_vdisk):
    return (
        old_vdisk['Layout'] == new_vdisk['raid'] and
        set(map(lambda x: x['ID'], old_vdisk['pdisks'])) == set(map(lambda x: x['id'], new_vdisk['pdisks']))
    )

HP_RAID_LEVELS = {
    'RAID-0': '0',
    'RAID-1': '1',
    'RAID-5': '5',
    'RAID-6': '6',
    'RAID-10': '1+0',
}
def hp_same_config(old_vdisk, new_vdisks):
    for disk_name, new_vdisk in new_vdisks.iteritems():
        if (
            old_vdisk['FaultTolerance'] == HP_RAID_LEVELS.get(new_vdisk['raid'], None) and
            set(map(lambda x: x['ID'], old_vdisk['pdisks'])) == set(map(lambda x: x['id'], new_vdisk['pdisks']))
        ):
            return disk_name
        else:
            return None

def generic_same_config(old_vdisk, new_vdisk):
    return (
        old_vdisk['raid'] == new_vdisk['raid'] and
        set(map(lambda x: x['id'], old_vdisk['pdisks'])) == set(map(lambda x: x['id'], new_vdisk['pdisks']))
    )

def main(system_manufacturer, model, asset_tag, configuration_file):
    configuration = json.load(open(configuration_file, 'r'))
    if 'storage' not in configuration:
        fail_json('No storge configuration present')
    if system_manufacturer == 'Dell':
        current_disks = dell_disks()
        result = {'success': True, 'failed': False, 'vdisks_removed': [], 'vdisks_created': [], 'vdisks_by_id': {}}

        good_vdisks = {}
        for controller in current_disks:
            clear_foreign = False
            for vdisk in controller['vdisks']:
                if vdisk['Name'] not in configuration['storage'] or not dell_same_config(vdisk, configuration['storage'][vdisk['Name']]):
                    call_with_output(["omconfig", "storage", "vdisk", "action=deletevdisk", "controller=%s" % controller['ID'], "vdisk=%s" % vdisk['ID'], "force=yes"], "Failed to remove vdisk %s:%s: %%(returncode)d\n%%(out)s%%(err)s" % (controller['ID'], vdisk['ID']))
                    result['vdisks_removed'].append(vdisk)
                else:
                    good_vdisks[vdisk['Name']] = vdisk
                    result['vdisks_by_id'][vdisk['Name']] = vdisk['DeviceName']

            for pdisk in controller['pdisks']:
                if pdisk['State'] == 'Foreign':
                    clear_foreign = True
            if clear_foreign:
                call_with_output(["omconfig", "storage", "controller", "action=clearforeignconfig", "controller=%s" % controller['ID']], "Failed to clear foreign config: %(returncode)s\n%(out)s%(err)s")

        for disk in sorted(configuration['storage'].iteritems(), key=lambda v: 0 if v[0] == 'os' else 1):
            disk_name, disk = disk
            if disk_name in good_vdisks:
                continue
            controller = [controller for controller in current_disks if controller['ID'] == disk['controller_id']][0]

            if disk['raid'] == "Non-RAID":
                for pdisk_id in disk['pdisks']:
                    pdisk = [pdisk for pdisk in controller['pdisks'] if pdisk['ID'] == pdisk_id['id']][0]
                    if pdisk['State'] != "Non-RAID":
                        call_with_output(["omconfig", "storage", "controller", "action=convertraidtononraid", "controller=%s" % disk['controller_id'], "pdisk=%s" % pdisk_id['id']], "Failed to convert %s to non-RAID: %%(returncode)s\n%%(out)s%%(err)s" % pdisk_id['id'])
                continue
            if disk['raid'] == "Spare":
                for pdisk_id in disk['pdisks']:
                    pdisk = [pdisk for pdisk in controller['pdisks'] if pdisk['ID'] == pdisk_id['id']][0]
                    if pdisk['State'] == 'Non-RAID':
                        call_with_output(["omconfig", "storage", "controller", "action=convertnonraidtoraid", "controller=%s" % disk['controller_id'], "pdisk=%s" % pdisk_id['id']], "Failed to convert %s to non-RAID: %%(returncode)s\n%%(out)s%%(err)s" % pdisk_id['id'])
                    if pdisk['HotSpare'] != 'Global':
                        call_with_output(["omconfig", "storage", "pdisk", "action=assignglobalhotspare", "controller=%s" % disk['controller_id'], "pdisk=%s" % pdisk_id['id'], "assign=yes"], "Failed to mark %s as hot spare: %%(returncode)s\n%%(out)s%%(err)s" % pdisk_id['id'])

            raid_level = {
                'RAID-0': 'r0',
                'RAID-1': 'r1',
                'RAID-5': 'r5',
                'RAID-6': 'r6',
                'RAID-10': 'r10',
            }.get(disk['raid'], None)
            if raid_level is None:
                fail_json("Unsupported RAID level %s for disk %s" % (disk['raid'], disk_name))
            if controller['Name'] == 'PERCH310Mini':
                stripesize = '64'
            else:
                stripesize = '256'
            for pdisk_id in disk['pdisks']:
                pdisk = [pdisk for pdisk in controller['pdisks'] if pdisk['ID'] == pdisk_id['id']][0]
                if pdisk['State'] == 'Non-RAID':
                    call_with_output(["omconfig", "storage", "controller", "action=convertnonraidtoraid", "controller=%s" % disk['controller_id'], "pdisk=%s" % pdisk_id['id']], "Failed to convert %s to non-RAID: %%(returncode)s\n%%(out)s%%(err)s" % pdisk_id['id'])
                if pdisk['HotSpare'] == 'Global':
                    call_with_output(["omconfig", "storage", "pdisk", "action=assignglobalhotspare", "controller=%s" % disk['controller_id'], "pdisk=%s" % pdisk_id['id'], "assign=no"], "Failed to mark %s as hot spare: %%(returncode)s\n%%(out)s%%(err)s" % pdisk_id['id'])

            call_with_output(["omconfig", "storage", "controller", "action=createvdisk", "controller=%s" % disk['controller_id'], "raid=%s" % raid_level, "pdisk=%s" % ",".join(map(lambda x: x['id'], disk['pdisks'])), "stripesize=%skb" % disk.get('stripesize', stripesize), "name=%s" % disk_name, "size=max"], "Failed to create vdisk %s: %%(returncode)s\n%%(out)s%%(err)s" % disk_name)
            vdisks = parse_om("storage vdisk controller=%s" % disk['controller_id'], ['ID', 'Name', 'Layout', 'Size', 'DeviceName'])
            vdisk = filter(lambda x: x['Name'] == disk_name, vdisks)[0]
            vdisk['DeviceName'] = find_by_id_symlink(vdisk['DeviceName'])
            vdisk_id = vdisk['ID']
            result['vdisks_created'].append(vdisk)
            result['vdisks_by_id'][vdisk['Name']] = vdisk['DeviceName']
            # These will fail, and that's okay.
            p = subprocess.Popen(["omconfig", "storage", "vdisk", "action=cancelbginitialize", "controller=%s" % disk['controller_id'], "vdisk=%s" % vdisk_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.communicate()
            p = subprocess.Popen(["omconfig", "storage", "vdisk", "action=fastinit", "controller=%s" % disk['controller_id'], "vdisk=%s" % vdisk_id], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            p.communicate()
            if disk_name == 'os':
                call_with_output(["/opt/MegaRAID/perccli/perccli64", "/c%s/v%s" % (disk['controller_id'], vdisk_id), "set", "bootdrive=on"], "Failed to set os as bootdrive: %(returncode)d\n%(out)s%(err)s")

        result['vdisks_unchanged'] = good_vdisks.values()

        json.dump(result, sys.stdout)

    elif system_manufacturer == 'HP':
        current_disks = hp_disks()
        result = {'success': True, 'failed': False, 'vdisks_removed': [], 'vdisks_created': [], 'vdisks_by_id': {}}

        good_vdisks = []
        for controller in current_disks:
            for vdisk in controller['vdisks']:
                disk_name = hp_same_config(vdisk, configuration['storage'])
                if not disk_name:
                    call_with_output(["hpssacli", "controller", "slot=%s" % controller['Slot'], "logicaldrive", vdisk['ID'], "delete", "forced"], "Failed to delete vdisk %s:%s: %%(returncode)d\n%%(out)s%%(err)s" % (controller['Slot'], vdisk['ID']))
                    result['vdisks_removed'].append(vdisk)
                else:
                    good_vdisks.append(disk_name)
                    result['vdisks_by_id'][disk_name] = vdisk['DiskName']


        for disk in sorted(configuration['storage'].iteritems(), key=lambda v: 0 if v[0] == 'os' else 1):
            disk_name, disk = disk
            if disk_name in good_vdisks:
                continue

            if disk['raid'] == 'Spare':
                call_with_output(["hpssacli", "controller", "slot=%s" % disk['controller_id'], "array", "all", "add", "spares=%s" % (",".join(map(lambda x: x['id'], disk['pdisks'])))], 'Failed to make %s as hot spare: %%(returncode)s\n%%(out)s%%(err)s' % disk_name)
                continue

            raid_level = HP_RAID_LEVELS.get(disk['raid'], None)
            if raid_level is None:
                fail_json("Unsupported RAID level %s for disk %s" % (disk['raid'], disk_name))

            call_with_output(["hpssacli", "controller", "slot=%s" % disk['controller_id'], "create", "type=ld", "drives=%s" % (",".join(map(lambda x: x['id'], disk['pdisks']))), "raid=%s" % raid_level, "stripsize=%s" % disk.get("stripesize", "256")], "Failed creating new vdisk %s: %%(returncode)s\n%%(out)s%%(err)s" % disk_name)
            result['vdisks_created'].append(disk_name)


        result['vdisks_unchanged'] = good_vdisks

        for controller in hp_disks():
            for vdisk in controller['vdisks']:
                disk_name = hp_same_config(vdisk, configuration['storage'])
                if disk_name and disk_name not in result['vdisks_by_id']:
                    result['vdisks_by_id'][disk_name] = vdisk['DiskName']

        json.dump(result, sys.stdout)

    elif system_manufacturer == 'Supermicro':
        current_disks = generic_disks()
        result = {'success': True, 'failed': False, 'vdisks_removed': [], 'vdisks_created': [], 'vdisks_by_id': {}}

        good_vdisks = []
        for controller in current_disks:
            for vdisk in controller['vdisks']:
                if vdisk['name'] not in configuration['storage'] or not generic_same_config(vdisk, configuration['storage'][vdisk['name']]):
                    rc, out, err = call_with_output(["/opt/MegaRAID/storcli/storcli64", "/c%s/v%s" % (controller['id'], vdisk['id'].split("/")[1]), "del", "force"], "Failed to delete volume %(returncode)d:\n%(out)s\n%(err)s")
                    open("/tmp/log", "a").write(out)
                    open("/tmp/log", "a").write(err)
                    result['vdisks_removed'].append(vdisk)
                else:
                    good_vdisks.append(vdisk['name'])
                    result['vdisks_by_id'][vdisk['name']] = vdisk['by_id']

        for disk in sorted(configuration['storage'].iteritems(), key=lambda v: 0 if v[0] == 'os' else 1):
            disk_name, disk = disk
            if disk_name in good_vdisks:
                continue
            controller = [controller for controller in current_disks if controller['id'] == disk['controller_id']][0]
            if controller['type'] == 'storcli':
                call_with_output(["/opt/MegaRAID/storcli/storcli64", "/c%s" % controller['id'], "add", "vd", "type=%s" % disk['raid'].replace("RAID-", "r"), "name=%s" % disk_name, "drives=%s" % ",".join(map(lambda x: x['id'], disk['pdisks']))], "Failed to create VD %(returncode)d:\n%(out)s\n%(err)s")
                rc, out, err = call_with_output(["/opt/MegaRAID/storcli/storcli64", "/c%s" % controller['id'], "show", "J"], "Failed to list drives %(returncode)d:\n%(out)s\n%(err)s")
                data = json.loads(out)
                for vd in data['Controllers'][0]['Response Data']['VD LIST']:
                    if vd['Name'] == disk_name:
                        rc, out, err = call_with_output(["/opt/MegaRAID/storcli/storcli64", "/c%s/v%s" % (controller['id'], vd['DG/VD'].split("/")[1]), "show", "all", "J"], "Failed to get name of drive %(returncode)d:\n%(out)s\n%(err)s")
                        data = json.loads(out)
                        result['vdisks_by_id'][disk_name] = find_by_id_symlink(data['Controllers'][0]['Response Data']['VD%s Properties' % vd['DG/VD'].split("/")[1]]['OS Drive Name'].replace("/dev/", ""))
                        break
            elif controller['type'] == 'direct':
                result['vdisks_by_id'][disk_name] = 'disk/by-id/md-name-%s' % disk_name
            result['vdisks_created'].append(disk_name)

        result['vdisks_unchanged'] = good_vdisks

        json.dump(result, sys.stdout)

    else:
        fail_json('Unknown manufacturer: %s' % system_manufacturer)

if __name__ == "__main__":
    main(*sys.argv[1:])
