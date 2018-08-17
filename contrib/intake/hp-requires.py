#!/usr/bin/python -tt

import os
import sys
import subprocess
import re

p = subprocess.Popen(["dmidecode"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = p.communicate()

if p.returncode != 0:
    print >>sys.stderr, "Failed to run dmidecode"

# Get BIOS version
in_bios = False
system_name = None
for line in stdout.splitlines():
    if line.startswith("BIOS Information"):
        in_bios = True
    if line.startswith("Handle"):
        in_bios = False
    if in_bios and line.strip().startswith("Version:"):
        system_name = line.strip().split()[-1].lower()

if system_name is not None:
    print "firmware(hp:system:%s)" % system_name
else:
    print >>sys.stderr, "Unable to determine system type"

# Get iLO version
p = subprocess.Popen(["hponcfg", "-g"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = p.communicate()

if p.returncode != 0:
    print >>sys.stderr, "Failed to run hponcfg"

start = stdout.find("Device type =") + 14
end = stdout.find("Driver name =")
ilo_version = stdout[start:end].strip().replace(" ", "").lower()

print "hp-firmware-%s" % ilo_version

# Get PCI devices
p = subprocess.Popen(["lspci", "-vn"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = p.communicate()

if p.returncode != 0:
    print >>sys.stderr, "Failed to run lspci"

device_re = re.compile("^([0-9a-f]{2}:[0-9a-f]{2}.[0-9a-f]) ([0-9a-f]{4}): ([0-9a-f]{4}):([0-9a-f]{4}).*\n\s+Subsystem: ([0-9a-f]{4}):([0-9a-f]{4})", re.MULTILINE)
for device in device_re.findall(stdout):
    print "firmware(pci:v0000%sd0000%ssv0000%ssd0000%sbc*sc*i*)" % (device[2], device[3], device[4], device[5])
    print "firmware(pci:v0000%sd0000%ssv0000%ssd0000%sbc*sc*i*)" % (device[2].upper(), device[3].upper(), device[4].upper(), device[5].upper())

# Get disks
os.environ['INFOMGR_BYPASS_NONSA'] = "1"
p = subprocess.Popen(["hpssacli", "controller", "all", "show", "detail"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
stdout, stderr = p.communicate()

if p.returncode not in (0, 1):
    print >>sys.stderr, "Failed to run hpssacli controller all show detail"

slots = re.findall("^\s+Slot: ([0-9]+)\s*$", stdout, re.MULTILINE)

model_re = re.compile("^\s+Model: (.*)$", re.MULTILINE)
disks = set()
for slot in slots:
    p = subprocess.Popen(["hpssacli", "controller", "slot=%s" % slot, "physicaldrive", "all", "show", "detail"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate()

    if p.returncode != 0:
        print >>sys.stderr, "Failed to run hpssacli slot=%s physicaldrive all show detail" % slot

    for model in model_re.findall(stdout):
        model = model.split()[-1].lower()
        disks.add("firmware(hp:sd:sas:%s)" % model)
        disks.add("firmware(hp:sd:sata:%s)" % model)
        disks.add("firmware(hp:sas:%s)" % model)
        disks.add("firmware(hp:sata:%s)" % model)

for disk in disks:
    print disk
