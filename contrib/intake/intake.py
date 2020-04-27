#!/usr/bin/python -tt

import os
import sys
import subprocess
import json
import netifaces
import base64
import time
from common import *

def main(system_manufacturer, model, asset_tag, configuration_file):
    dev_null = open("/dev/null", "w")
    is_efi = os.path.exists("/sys/firmware/efi")
    interfaces = filter(lambda x: not x.startswith("lo"), netifaces.interfaces())
    lshw_rc, lshw_out, lshw_err = call_with_output(["lshw", "-json"], 'Failed to run lshw with %(returncode)d:\n%(err)s')
    lshw_dict = json.loads(lshw_out)

    if system_manufacturer == "HP":
        for interface in interfaces:
            macaddr = netifaces.ifaddresses(interface)[netifaces.AF_LINK][0]['addr'].replace(":", "-")
            for param in ["DCBXState", "TxState", "RxState"]:
                subprocess.call(["brcmhbacmd", "SetDCBParam", macaddr, param, "0"], stdout=dev_null, stderr=dev_null)
        subprocess.call(["service", "lldpad", "restart"], stdout=dev_null, stderr=dev_null)

    for interface in interfaces:
        subprocess.call(["ip", "link", "set", interface, "up"], stdout=dev_null, stderr=dev_null)
        subprocess.call(["lldptool", "-L", "-i", interface, "adminStatus=rxtx"], stdout=dev_null, stderr=dev_null)

    start_wait = time.time()

    dmidecode_rc, dmidecode_out, dmidecode_err = call_with_output(["dmidecode", "--dump-bin", "/tmp/dmidecode"], 'Failed to run dmidecode with %(returncode)d:\n%(err)s')
    dmidecode = base64.b64encode(open("/tmp/dmidecode", "rb").read())

    subprocess.call(["modprobe", "ipmi_devintf"])
    time.sleep(3)

    ipmicfg = {}
    if system_manufacturer == "Dell":
        controllers = dell_disks()
    elif system_manufacturer == "HP":
        controllers = hp_disks()
    elif system_manufacturer == "Supermicro":
        controllers = generic_disks()
        ipmicfg_fru_rc, ipmicfg_fru_out, ipmicfg_fru_err = call_with_output(["/opt/ipmicfg/IPMICFG-Linux.x86_64", "-fru", "list"], 'Failed to run ipmicfg -fru list with %(returncode)d:\n%(err)s')
        ipmicfg_nodeid_rc, ipmicfg_nodeid_out, ipmicfg_nodeid_err = call_with_output(["/opt/ipmicfg/IPMICFG-Linux.x86_64", "-tp", "nodeid"], 'Failed to run ipmicfg -tp nodeid with %(returncode)d:\n%(err)s', success=[0, 13])
        ipmicfg_tp_info_rc, ipmicfg_tp_info_out, ipmicfg_tp_info_err = call_with_output(["/opt/ipmicfg/IPMICFG-Linux.x86_64", "-tp", "info"], 'Failed to run ipmicfg -tp info with %(returncode)d:\n%(err)s', success=[0, 13])
        ipmicfg = {
            'fru': dict([(k.strip(), v.strip()) for k, v in [line.split("=", 1) for line in ipmicfg_fru_out.splitlines()]]),
        }
        if ipmicfg_nodeid_rc == 0:
            ipmicfg['nodeid'] = ipmicfg_nodeid_out.strip()
        if ipmicfg_tp_info_rc == 0:
            ipmicfg['tp_info'] = ipmicfg_tp_info_out.strip()
            m = re.search(r'Chassis S/N\s+:\s([^\n]+)\n', ipmicfg['tp_info'], re.DOTALL)
            if m and m.group(1) != '(Empty)':
                ipmicfg['chassis'] = m.group(1)

    oob = {}
    subprocess.call(["modprobe", "ipmi_devintf"])
    time.sleep(3)

    p = subprocess.Popen(["ipmitool", "mc", "info"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ipmitool_mc_out, ipmitool_mc_err = p.communicate()
    if p.returncode == 0:
        ipmitool_mc = dict([map(lambda x: x.strip(), line.split(":", 1)) for line in ipmitool_mc_out.splitlines() if ":" in line])
        oob['version'] = ipmitool_mc['Firmware Revision']

    p = subprocess.Popen(["ipmitool", "lan", "print"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    ipmitool_lan_out, ipmitool_lan_err = p.communicate()
    if p.returncode == 0:
        ipmitool_lan = dict([map(lambda x: x.strip(), line.split(":", 1)) for line in ipmitool_lan_out.splitlines() if ":" in line])
        oob['mac'] = ipmitool_lan['MAC Address']
        oob['ip'] = ipmitool_lan['IP Address']

    by_id_map = {}
    for symlink in os.listdir("/dev/disk/by-id"):
        dest = os.path.realpath("/dev/disk/by-id/" + symlink)
        by_id_map[symlink] = dest

    end_wait = time.time()
    waited = end_wait - start_wait
    if waited < 65:
        time.sleep(65 - waited)

    lldp_rc = {}
    lldp_out = {}
    lldp_err = {}
    for interface in interfaces:
        lldp_rc[interface], lldp_out[interface], lldp_err[interface] = call_with_output(["lldptool", "-t", "-n", "-i", interface], 'Failed to run lldptool on %s with %%(returncode)d:\n%%(err)s' % interface, success=[0, 1])
        ip_rc, ip_out, ip_err = call_with_output(["ip", "link", "show", "dev", interface], "Failed to list interface %s with %%(returncode)d:\n%%(err)s" % interface)
        if 'LOWER_UP' in ip_out and 'Agent instance for device not found' in lldp_out[interface]:
            fail_json("Failed to get LLDP data for interface %s" % interface)

    json.dump({
        'success': True,
        'model': model,
        'failed': False,
        'lshw': lshw_dict,
        'lldp': lldp_out,
        'dmidecode': dmidecode,
        'storage': controllers,
        'by_id_map': by_id_map,
        'oob': oob,
        'ipmicfg': ipmicfg,
        'efi': is_efi,
    }, sys.stdout)

if __name__ == "__main__":
    main(*sys.argv[1:])
