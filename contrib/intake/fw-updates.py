#!/usr/bin/python -tt

import os
import sys
import subprocess
import json
import pty
import atexit
import time

def fail_json(msg):
    json.dump({'failed': True, 'msg': msg}, sys.stdout)
    sys.exit(1)

def umount(mountpoint):
    subprocess.call(["umount", mountpoint])

def mount_tmpfs(mountpoint, options="rw"):
    rc = subprocess.call(["mount", "-t", "tmpfs", "-o", options, "none", mountpoint])
    if rc != 0:
        fail_json('Failed to mount tmpfs on %s' % mountpoint)
    atexit.register(umount, mountpoint)

def main(system_manufacturer, model, asset_tag, configuration_file):
    mount_tmpfs("/var/cache/yum")
    if system_manufacturer == "Dell":
        if not os.path.exists("/usr/libexec/dell_dup"):
            os.makedirs("/usr/libexec/dell_dup")
        mount_tmpfs("/usr/libexec/dell_dup")
        if not os.path.exists("/opt/dell/dup64"):
            os.makedirs("/opt/dell/dup64")
        mount_tmpfs("/opt/dell/dup64")

        # Wait until the inventory collection is complete, as it interferes with dsu
        while True:
            p = subprocess.Popen(["pidof", "invcol"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = p.communicate()
            if p.returncode != 0:
                break
            time.sleep(10)

        (pid, fd) = pty.fork()
        update_out = ""
        if pid == 0:
            os.execvp("dsu", ["dsu", "-n", "-u"])
            os._exit(42)
        else:
            while True:
                try:
                    buf = os.read(fd, 1024)
                except OSError:
                    break
                if not buf:
                    break
                update_out += buf
            pid, update_rc, rusage = os.wait4(pid, 0)
            update_rc = os.WEXITSTATUS(update_rc)
        if update_rc not in (0, 1, 8):
            fail_json("Updating firmware failed with %d:\n%s" % (update_rc, update_out))

        json.dump({'success': True, 'failed': False, 'msg': 'All firmware patched', 'log': update_out}, sys.stdout)

    elif system_manufacturer == "HP":
        for i in ["/usr/lib/x86_64-linux-gnu", "/usr/lib/i386-linux-gnu"]:
            os.makedirs(i)
            mount_tmpfs(i)

        p = subprocess.Popen([os.path.dirname(os.path.realpath(__file__)) + "/hp-requires"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        firmwares, fw_err = p.communicate()
        if p.returncode != 0:
            fail_json("Figuring out firmware to install failed with %d:\n%s" % (p.returncode, fw_err))
        firmwares = firmwares.split()

        p = subprocess.Popen(["yum", "-y", "install", "HP-CNA-FC-Emulex-Enablement-Kit", "HP-CNA-FC-hpqlgc-Enablement-Kit"] + firmwares, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        yum_out, yum_err = p.communicate()
        if p.returncode != 0:
            fail_json("Installing firmware failed with %d:\n%s" % (p.returncode, yum_err))

        p = subprocess.Popen([os.path.dirname(os.path.realpath(__file__)) + "/hp-apply"], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        update_out, update_err = p.communicate()

        json.dump({'success': True, 'failed': False, 'msg': 'All firmware patched', 'log': "\n".join([fw_err, yum_out, yum_err, update_out, update_err])}, sys.stdout)

    else:
        fail_json('Unknown manufacturer: %s' % system_manufacturer)

if __name__ == "__main__":
    main(*sys.argv[1:])
