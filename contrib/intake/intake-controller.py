#!/usr/bin/python -tt

import os
import subprocess
import sys
import json
import daemon
import dmidecode
import requests
import optparse
import time

def run(options, steps):
    if not steps:
        steps = ["fw-updates", "oob-config", "intake", "reboot"]

    try:
        system = dmidecode.system()
        system_manufacturer = [v for k, v in system.items() if 'Manufacturer' in v['data']][0]['data']['Manufacturer']
        if system_manufacturer.startswith("HP"):
            system_manufacturer = "HP"
            model = [v for k, v in system.items() if 'Product Name' in v['data']][0]['data']['Product Name'].strip()
            asset_tag = [v for k, v in system.items() if 'Serial Number' in v['data']][0]['data']['Serial Number'].strip()
        elif system_manufacturer.startswith("Dell"):
            system_manufacturer = "Dell"
            model = [v for k, v in system.items() if 'Product Name' in v['data']][0]['data']['Product Name'].strip()
            asset_tag = [v for k, v in system.items() if 'Serial Number' in v['data']][0]['data']['Serial Number'].strip()
        elif system_manufacturer.startswith("Supermicro"):
            system_manufacturer = "Supermicro"
            baseboard = dmidecode.baseboard()
            model = [v for k, v in system.items() if 'Product Name' in v['data']][0]['data']['Product Name'].strip()
            if model in ('Super Server', 'To be filled by O.E.M.'):
                model = [v for k, v in baseboard.items() if 'Product Name' in v['data']][0]['data']['Product Name'].strip()
            asset_tag = [v for k, v in baseboard.items() if 'Serial Number' in v['data']][0]['data']['Serial Number'].strip()
        else:
            raise Exception("Unknown")
    except:
        system_manufacturer = "Unknown"
        model = "Unknown"
        asset_tag = "Unknown"

    security_qs = {}
    if options.hmac:
        security_qs['hmac'] = options.hmac
    if options.nonce:
        security_qs['nonce'] = options.nonce

    while True:
        try:
            response = requests.get("%sconfig/%s" % (options.url, asset_tag), params=security_qs, verify=False, headers={"Accept": "application/json"})
        except:
            response = None
        if response is not None and response.status_code == 200:
            break
        else:
            time.sleep(5)

    configuration = response.text
    configuration_file = "/tmp/sot.conf"
    with open(configuration_file, 'w') as f:
        f.write(configuration)

    for step in steps:
        # Special steps implemented here
        data = None
        if step == 'reboot':
            subprocess.call(["/sbin/shutdown", "-r", "+1"])
            data = {'msg': 'rebooting'}
            ret = 1
        elif step == 'poweroff':
            subprocess.call(["/sbin/shutdown", "-h", "+1"])
            data = {'msg': 'powering off'}
            ret = 1
        else:
            p = subprocess.Popen([os.path.join(options.path, step), system_manufacturer, model, asset_tag, configuration_file], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            ret = p.returncode
            try:
                data = json.loads(stdout)
            except:
                pass
        report = {'step': step, 'data': data, 'returncode': p.returncode, 'stderr': stderr}
        response = requests.post("%sintake/%s" % (options.url, asset_tag), data=json.dumps(report), params=security_qs, verify=False, headers={"Content-Type": "application/json", "Accept": "application/json"})
        if ret != 0 or data is None or ('failed' in data and data['failed']) or response.status_code not in [200, 201]:
            sys.stderr.write("Failed to run step %s, report %r, response code is %s\n" % (step, report, response.status_code))
            break

def main(args=sys.argv[1:]):
    parser = optparse.OptionParser()
    parser.add_option("-p", dest="path", help="Path to step scripts", default="/usr/libexec/intake")
    parser.add_option("-u", dest="url", help="Base URL for Socrates", default="http://localhost/")
    parser.add_option("-H", dest="hmac", help="HMAC token to include")
    parser.add_option("-n", dest="nonce", help="Nonce token to include")
    parser.add_option("-d", dest="daemonize", action="store_true", help="Daemonize")
    options, args = parser.parse_args(args)
    if options.daemonize:
        with daemon.DaemonContext(stderr=open("/var/log/intake-controller.log", "w+")):
            run(options, args)
    else:
        run(options, args)

if __name__ == "__main__":
    main()
