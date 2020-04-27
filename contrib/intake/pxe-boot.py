#!/usr/bin/python -tt

import sys
import json
import re
from common import call_with_output

def main(system_manufacturer, model, asset_tag, configuration_file):
    if system_manufacturer == "Dell":
        bootseq_mode = "BootSeq"
        rc, out, err = call_with_output(['racadm', 'get', 'BIOS.BiosBootSettings'], 'Failed to get BIOS boot mode: %(returncode)s\n%(out)s%(err)s', success=[0, 1, 2])
        for line in out.splitlines():
            if re.match('^BootMode=Uefi', line, re.I):
                bootseq_mode = "UefiBootSeq"
        rc, out, err = call_with_output(["racadm", "get", "BIOS.BiosBootSettings.{0}".format(bootseq_mode)], "Failed to list BIOS boot devices: %(returncode)s\n%(out)s%(err)s", success=[0, 1, 2])
        if rc == 0:
            if bootseq_mode != 'UefiBootSeq':
                call_with_output(["racadm", "set", "BIOS.OneTimeBoot.OneTimeBootMode", "OneTimeBootSeq"], "Failed to enable one-time-boot: %(returncode)s\n%(out)s%(err)s")
                one_time_boot = filter(lambda x: not x.startswith("HardDisk") and not x.startswith("RAID"),
                        filter(lambda x: x.startswith("BootSeq="), out.splitlines())[0][8:].split(",")
                    )[0]
                call_with_output(["racadm", "set", "BIOS.OneTimeBoot.OneTimeBootSeqDev", one_time_boot], "Failed to enable one-time-boot: %(returncode)s\n%(out)s%(err)s")
            else:
                call_with_output(["racadm", "set", "BIOS.OneTimeBoot.OneTimeBootMode", "OneTimeUefiBootSeq"], "Failed to enable one-time-boot: %(returncode)s\n%(out)s%(err)s")
                call_with_output(["racadm", "set", "BIOS.OneTimeBoot.OneTimeUefiBootSeqDev", 'NIC.PxeDevice.1-1'], "Failed to enable one-time-boot: %(returncode)s\n%(out)s%(err)s")
            call_with_output(["racadm", "jobqueue", "create", "BIOS.Setup.1-1", "-r", "pwrcycle", "-s", "TIME_NOW", "-e", "TIME_NA"], "Failed to schedule BIOS job: %(returncode)s\n%(out)s%(err)s")
    else:
        rc = 1
    if rc != 0:
        call_with_output(["ipmitool", "-I", "open", "chassis", "bootdev", "pxe"], "Failed to set next boot to PXE: %(returncode)s\n%(out)s%(err)s")
    json.dump({'success': True, 'failed': False}, sys.stdout)

if __name__ == "__main__":
    main(*sys.argv[1:])
