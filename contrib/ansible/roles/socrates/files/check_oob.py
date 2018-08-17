#!/usr/bin/python -tt

import gevent
import gevent.monkey
gevent.monkey.patch_all()
import sys
import optparse
import requests
import getpass
import datetime
import pyghmi.ipmi.command, pyghmi.exceptions
import socket
import time

parser = optparse.OptionParser()
parser.add_option("-r", "--rethinkdb", action="store_true", dest="rethinkdb")
parser.add_option("-u", "--username", action="store", dest="username")
parser.add_option("-p", "--password", action="store", dest="password")
parser.add_option("-w", "--warning", action="store", dest="warning", type="int", default=0)
parser.add_option("-c", "--critical", action="store", dest="critical", type="int", default=5)
options, args = parser.parse_args()

if not options.rethinkdb:
    if not options.password:
        options.password = getpass.getpass()

    r = requests.get("https://sot.fqdn.tld/asset/?asset_type=server", auth=(options.username, options.password))
    if r.status_code != 200:
        print "UNKNOWN: Unable to talk to Socrates: %s" % r.status_code
        sys.exit(3)
    assets = r.json()
else:
    import rethinkdb as r
    conn = r.connect(db='socrates')
    assets = r.table("assets").filter(lambda asset: (asset['asset_type'] == "server") & (asset['state'] != "deleted")).run(conn)

def check_ipmi(asset):
    failure = None
    for i in range(0, 3):
        try:
            pyghmi.ipmi.command.Command(bmc=asset['service_tag'] + '.oobdomain.example.fqdn.tld', userid=asset['oob']['username'], password=asset['oob']['password']).get_power()
            return None
        except (pyghmi.exceptions.IpmiException, socket.error, socket.gaierror) as e:
            failure = e.message or str(e)
            time.sleep(1)
    else:
        return asset['service_tag'], failure

jobs = []
unmanaged = 0
for asset in assets:
    if 'oob' in asset and 'username' in asset['oob']:
        jobs.append(gevent.spawn(check_ipmi, asset))
    else:
        unmanaged += 1

results = gevent.joinall(jobs)
reachable = 0
unreachable = 0
failures = []
for result in results:
    if result.value is None:
        reachable += 1
    else:
        unreachable += 1
        failures.append("Unable to reach %s: %s" % (result.value[0], result.value[1]))

if unreachable > options.critical:
    ret = 2
    label = "CRITICAL"
elif unreachable > options.warning:
    ret = 1
    label = "WARNING"
else:
    ret = 0
    label = "OK"
print "%s: %d reachable, %d unreachable, %d unmanaged | reachable=%d unreachable=%d unmanaged=%d" % (label, reachable, unreachable, unmanaged, reachable, unreachable, unmanaged)
print "\n".join(failures)
sys.exit(ret)
