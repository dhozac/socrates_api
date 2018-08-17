#!/usr/bin/python -tt

import sys
import subprocess
import json
import re
import string
import random
import time

def fail_json(msg):
    json.dump({'failed': True, 'msg': msg}, sys.stdout)
    sys.exit(1)

def call_with_output(command, error_msg, input=None, success=[0]):
    p = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = p.communicate(input)
    if p.returncode not in success:
        fail_json(error_msg % {"returncode": p.returncode, "out": stdout, "err": stderr})
    return p.returncode, stdout, stderr

def main(system_manufacturer, model, asset_tag, configuration_file):
    configuration = json.load(open(configuration_file, 'r'))
    password = "".join(random.sample(string.letters + string.digits, 19))
    if system_manufacturer == 'Dell':
        replacements = {'password': password, 'empxe': 'off', 'hyperthreading': 'enabled' if configuration.get('hyperthreading', False) else 'disabled', 'intnic': 'disabledos', 'intpxe': 'none'}
        ip_route_rc, ip_route_out, ip_route_err = call_with_output(["ip", "route", "get", "8.8.8.8"], 'Getting default route failed with %(returncode)d:\n%(err)s')
        m = re.search(r" dev ([a-z0-9-_]*) ", ip_route_out)
        default_nic = m.group(1)
        if default_nic[:2] == "em":
            replacements['empxe'] = 'pxeboth'
            replacements['intnic'] = 'enabled'
            replacements['intpxe'] = 'pxe'

        attempts = 0
        while attempts < 3:
            biossetup_rc, biossetup_out, biossetup_err = call_with_output(["omreport", "chassis", "biossetup", "display=shortnames"], 'Getting BIOS configuration failed with %(returncode)d:\n%(out)s%(err)s', success=[0, 1, 255])
            if biossetup_rc == 255:
                biossetup_rc, biossetup_out, biossetup_err = call_with_output(["omreport", "chassis", "biossetup"], 'Getting BIOS configuration failed with %(returncode)d:\n%(out)s%(err)s')
            if biossetup_rc == 1:
                # Often srvadmin needs a restart before this works. Due to systemd, we don't know when it is done, so ENTERPRISE SLEEP!
                with open("/dev/null", "r+") as dev_null:
                    subprocess.call(["srvadmin-services.sh", "restart"], stdout=dev_null, stderr=dev_null)
                time.sleep(300)
            elif biossetup_rc == 0:
                break
            attempts += 1

        racadm_f = open("/tmp/racadm.txt", "w")
        racadm_f.write("""[cfgLanNetworking]
cfgDNSServersFromDHCP=1
cfgDNSRacName=%s
cfgDNSDomainNameFromDHCP=1
cfgDNSRegisterRac=1
[cfgRacTuning]
cfgRacTunePlugintype=1
""" % asset_tag)
        racadm_f.close()
        bios_commands = """
omconfig chassis remoteaccess config=nic enable=true enablenic=true enableipmi=true ipsource=dhcp nicselection=dedicated
omconfig chassis remoteaccess config=serialoverlan enable=true baudrate=115200
omconfig chassis remoteaccess config=user id=2 name=root
omconfig chassis remoteaccess config=user id=2 newpw=%(password)s confirmnewpw=%(password)s
omconfig chassis remoteaccess config=user id=2 lanaccesslevel=administrator
omconfig chassis remoteaccess config=user id=2 serialaccesslevel=administrator
omconfig chassis remoteaccess config=user id=2 enableserialoverlan=true
omconfig chassis remoteaccess config=user id=2 dracusergroup=admin
omconfig chassis remoteaccess config=user id=2 extipmiusergroup=admin
omconfig chassis biossetup attribute=serialportaddr setting=default
omconfig chassis biossetup attribute=serialcom setting=com2
omconfig chassis biossetup attribute=extserial setting=serialdev1
omconfig chassis biossetup attribute=fbr setting=115200
omconfig chassis biossetup attribute=crab setting=enabled
""" % replacements
        if 'LogicalProc' in biossetup_out:
            bios_commands += """
omconfig chassis biossetup attribute=LogicalProc setting=%(hyperthreading)s
omconfig chassis biossetup attribute=ProcVirtualization setting=enabled
omconfig chassis biossetup attribute=IntegratedNetwork1 setting=%(intnic)s
omconfig chassis biossetup attribute=IntNic1Port1BootProto setting=%(intpxe)s
omconfig chassis biossetup attribute=IntNic1Port2BootProto setting=%(intpxe)s
omconfig chassis biossetup attribute=IntNic1Port3BootProto setting=%(intpxe)s
omconfig chassis biossetup attribute=IntNic1Port4BootProto setting=%(intpxe)s
omconfig chassis biossetup attribute=SysProfile setting=PerfOptimized
""" % replacements
            in_bootseq = False
            devices = []
            for line in biossetup_out.splitlines():
                if in_bootseq:
                    if line.strip() == '':
                        in_bootseq = False
                    else:
                        devices.append(line.split()[-1])
                elif 'BootSeq' in line:
                    in_bootseq = True
            devices.sort()
            bios_commands += "omconfig chassis biossetup attribute=BootSeq sequence=" + ",".join(devices) + "\n"
        else:
            bios_commands += """
omconfig chassis biossetup attribute=cpuvt setting=enabled
omconfig chassis biossetup attribute=cpuht setting=%(hyperthreading)s
omconfig chassis biossetup attribute=dualnic setting=%(empxe)s
omconfig chassis biossetup attribute=dualnic1 setting=%(empxe)s
omconfig chassis biossetup attribute=dualnic2 setting=%(empxe)s
omconfig chassis biossetup attribute=cpuxdsupport setting=enabled
omconfig chassis biossetup attribute=cstates setting=disabled
omconfig chassis biossetup attribute=cpuc1e setting=disabled
omconfig chassis biossetup attribute=ErrPrompt setting=disabled
omconfig chassis pwrmanagement config=profile profile=maxperformance
""" % replacements
            bootorder_rc, bootorder_out, bootorder_err = call_with_output(["racadm", "get", "BIOS.BiosBootSettings.Bootseq"], "Failed to get bootorder via racadm with %(bootorder_rc)d:\n%(bootorder_out)s%(bootorder_err)s")
            devices = []
            for line in bootorder_out.splitlines():
                devices.append(line)
            devices.sort()
            bootdevices = devices[1].strip('BootSeq=').split(',')
            setboot_rc, setboot_out, setboot_err = call_with_output(["racadm", "set", "BIOS.BiosBootSettings.Bootseq", ",".join(bootdevices)], "Failed to set bootorder via racadm with %(setboot_rc)d:\n%(setboot_out)s%(setboot_err)s")
            jobqueue_rc, jobqueue_out, jobqueue_err = call_with_output(["racadm", "jobqueue", "create", "BIOS.Setup.1-1", "-r", "none", "-s", "TIME_NOW", "-e", "TIME_NA"], "Failed to schedule BIOS job: %(jobqueue_rc)s\n%(jobqueue_out)s%(jobqueue_err)s",success=range(0, 256))
        bios_config_rc = []
        bios_config_out = []
        bios_config_err = []
        for command in bios_commands.splitlines():
            if not command:
                continue
            rc, out, err = call_with_output(command.split(), 'Failed running %s with %%(returncode)d:\n%%(err)s' % command, success=[0, 255])
            bios_config_rc.append(rc)
            bios_config_out.append(out)
            bios_config_err.append(err)
        rc, out, err = call_with_output(["racadm", "config", "-f", "/tmp/racadm.txt"], 'Failed running racadm %(returncode)d:\n%(err)s', success=range(0, 256))
        bios_config_rc.append(rc)
        bios_config_out.append(out)
        bios_config_err.append(err)

        json.dump({'success': True, 'failed': False, 'username': 'root', 'password': password, 'msg': 'Configured BIOS/iDRAC', 'log': "\n".join(["\n".join(bios_config_out), "\n".join(bios_config_err)])}, sys.stdout)

    elif system_manufacturer == 'HP':
        add_user = """
   <ADD_USER
     USER_NAME = "root"
     USER_LOGIN = "root"
     PASSWORD = "%(password)s">
    <ADMIN_PRIV value = "Y"/>
    <REMOTE_CONS_PRIV value = "Y"/>
    <RESET_SERVER_PRIV value = "Y"/>
    <VIRTUAL_MEDIA_PRIV value = "Y"/>
    <CONFIG_ILO_PRIV value = "Y"/>
   </ADD_USER>
"""
        mod_user = """
   <MOD_USER
     USER_LOGIN = "root">
    <PASSWORD value = "%(password)s"/>
    <ADMIN_PRIV value = "Y"/>
    <REMOTE_CONS_PRIV value = "Y"/>
    <RESET_SERVER_PRIV value = "Y"/>
    <VIRTUAL_MEDIA_PRIV value = "Y"/>
    <CONFIG_ILO_PRIV value = "Y"/>
  </MOD_USER>
"""
        contents = """
<RIBCL VERSION="2.1">
 <LOGIN USER_LOGIN="Administrator" PASSWORD="password">
  <RIB_INFO MODE="write">
   <MOD_NETWORK_SETTINGS>
    <DHCP_ENABLE VALUE = "Y"/>
    <DHCP_GATEWAY VALUE = "Y"/>
    <DHCP_DNS_SERVER VALUE = "Y"/>
    <DNS_NAME VALUE = "%%(asset_tag)s"/>
   </MOD_NETWORK_SETTINGS>
  </RIB_INFO>
  <USER_INFO MODE="write">
  %s
  </USER_INFO>
 </LOGIN>
</RIBCL>
"""
        replacements = {'asset_tag': asset_tag, 'password': password}

        with open("/tmp/hp-ilo.xml", "w") as f:
            f.write((contents % add_user) % replacements)
        errmsg = 'Failed running hponcfg with %(returncode)d:\n%(err)s'
        rc, out, err = call_with_output(["hponcfg", "-f", "/tmp/hp-ilo.xml"], errmsg, success=[0, 1])
        if rc == 1 and 'Cannot add user' in err and 'already exists' in err:
            with open("/tmp/hp-ilo.xml", "w") as f:
                f.write((contents % mod_user) % replacements)
            rc, out, err = call_with_output(["hponcfg", "-f", "/tmp/hp-ilo.xml"], errmsg)
        elif rc == 1:
            fail_json(errmsg % {"returncode": rc, "out": out, "err": err})

        json.dump({'success': True, 'failed': False, 'username': 'root', 'password': password, 'msg': 'Configured iLO', 'log': "\n".join([out, err])}, sys.stdout)

    else:
        fail_json('Unknown manufacturer: %s' % system_manufacturer)

if __name__ == "__main__":
    main(*sys.argv[1:])
