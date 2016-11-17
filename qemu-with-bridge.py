#!/usr/bin/python3
"""
Runs QEMU with dnsmasq and bridge
"""
import argparse
import ipaddress
import itertools
import os
import signal
import subprocess
import sys
import tempfile
import time
import threading

from collections import namedtuple
from distutils import spawn


def ip_set_last(ip, last):
    "sets the last quadret of the IP"
    return (ip - ip.packed[-1] + last).exploded


def default_gateway_iface():
    "returns the name of the default gateway interface, crashes if none"
    return subprocess.check_output(['awk', '$2 == 00000000 { print $1 }',
                                    '/proc/net/route']).split(b'\n')[0]


def main():
    parser = argparse.ArgumentParser(
        description='Run qemu, automatically run DHCP server, ' +
        'automatically create bridge and add a binded interface')
    parser.add_argument('cmd', nargs='*')
    parser.add_argument(
        '--net',
        '-n',
        help='network address of the interface, default mask /24')
    parser.add_argument('--kill-cgroup',
                        '-k',
                        dest='kill_cgroup',
                        action='store_true',
                        help='kills all process in cgroup from previous run')
    parser.add_argument('--no-cgroup',
                        '-C',
                        dest='cgroup',
                        action='store_false',
                        help='store all processes in cgroup, ' +
                        'refuse to run if cgroup processes already exist')
    parser.set_defaults(cgroup=True)
    parser.add_argument(
        '--no-kill-children-at-exit',
        dest='kill_children',
        action='store_false',
        help='By default will spawn a process to kill all cgroup' +
        'children when the main Qemu process exited')
    parser.set_defaults(kill_children=True)
    parser.add_argument('--ssh-key',
                        '-S',
                        dest='ssh_key',
                        action='store_true',
                        help='just print SSH key')
    args = parser.parse_args()
    if args.ssh_key:
        sys.stdout.buffer.write(VAGRANT_PRIV)
        return
    ip = ipaddress.ip_address(args.net)
    gateway = ip_set_last(ip, 199)
    cgroup_name = 'qemu_' + ip_set_last(ip, 0)
    cgroups = Cgroup()

    def kill_all():
        "kill all cgroup processes"
        if not args.cgroup:
            return
        time.sleep(0.3)  # give child time to print output
        for pid in (p for p in cgroups.cgroup_procs(cgroup_name)
                    if p != os.getpid()):
            os.kill(pid, signal.SIGINT)
        time.sleep(1)
        for pid in (p for p in cgroups.cgroup_procs(cgroup_name)
                    if p != os.getpid()):
            os.kill(pid, signal.SIGKILL)

    if args.kill_cgroup:
        kill_all()
        sys.exit(0)
    if args.cgroup:
        if not cgroups.is_cgroup_empty(cgroup_name):
            sys.stderr.write('Processes for net %s are running:\n' %
                             cgroup_name)
            for pid in cgroups.cgroup_procs(cgroup_name):
                commandline = 'cannot find pid %d' % pid
                try:
                    with open('/proc/%d/cmdline' % pid, 'r') as fileobj:
                        commandline = fileobj.read().replace('\0', ' ')
                except Exception as e:
                    pass  #whatever happens - nevermind, just debug info
                sys.stderr.write('%d: %s\n' % (pid, commandline))
            sys.exit(2)
        cgroups.join_cgroup(cgroup_name)
    devname = 'br_' + ip_set_last(ip, 0)
    # can fail, since it might not exist
    subprocess.call(['ip', 'link', 'del', 'dev', devname])
    subprocess.check_call(
        ['ip', 'link', 'add', 'dev', devname, 'type', 'bridge'])
    subprocess.check_call(
        ['sudo', 'ip', 'link', 'set', 'dev', devname, 'up'])
    subprocess.check_call(
        ['ip', 'addr', 'add', gateway + '/24', 'dev', devname])

    def masquerade():
        Iptables.masquarade_all_to(default_gateway_iface())

    masquerade()
    if os.fork() == 0:
        repeat_every(5, masquerade)
        signal.sigwait([signal.SIGINT])
        sys.exit(0)
    first_guest = ip_set_last(ip, 10)
    last_guest = ip_set_last(ip, 198)
    run_dnsmasq(devname, gateway, first_guest, last_guest)
    run_sshd(gateway)
    if 'bridge0' not in ' '.join(args.cmd):
        subprocess.call([
            args.cmd[0], '-netdev', 'type=bridge,id=bridge0,br=' + devname,
            '-device',
            'virtio-net-pci,netdev=bridge0,mac=DE:AD:BE:EF:43:1F'
        ] + args.cmd[1:])
    else:
        subprocess.call([
            args.cmd[0], '-netdev', 'type=bridge,id=bridge0,br=' + devname
        ] + args.rest[1:])


class Iptables(object):
    "access to iptables information via iptables command"
    entry = namedtuple(
        'iptable_entry',
        ['pkts', 'bytes', 'target', 'prot', 'opt', 'in_', 'out', 'src', 'dst'])

    @classmethod
    def get_postrouting(cls):
        "returns the POSTROUTING table lines"
        txt = subprocess.check_output(
            ['iptables', '-v', '-t', 'nat', '-L', 'POSTROUTING'])
        return [cls.entry(*x.split()[:9])
                for x in txt.strip().split(b'\n')[2:]]

    @classmethod
    def is_entry_masquerade_to(cls, ent, iface):
        "returns true if iptables' entry masquarade all traffic to given iface"
        return all([ent.prot == b'all', ent.target == b'MASQUERADE',
                    ent.in_ == b'any', ent.src == b'anywhere',
                    ent.dst == b'anywhere', ent.out == iface])

    @classmethod
    def has_masquerade_to(cls, iface):
        "do we have masquerade rule for interface iface?"
        for ent in cls.get_postrouting():
            if cls.is_entry_masquerade_to(ent, iface):
                return True
        return False

    @classmethod
    def masquarade_all_to(cls, iface):
        "add masquerade rule to interface iface if needed"
        if not cls.has_masquerade_to(iface):
            print('adding masquarade rule for interface', iface)
            subprocess.check_call(['iptables', '-t', 'nat', '-A',
                                   'POSTROUTING', '-o', iface, '-j',
                                   'MASQUERADE'])


def repeat_every(seconds, func, *args, **kwargs):
    "call func every seconds seconds"

    def and_again():
        func(*args, **kwargs)
        t = threading.Timer(seconds, and_again)
        t.daemon = True
        t.start()

    t = threading.Timer(seconds, and_again)
    t.daemon = True
    t.start()


def run_dnsmasq(devname, gateway, first_guest, last_guest):
    "runs dnsmasq"
    if os.fork() != 0:
        return
    leasefile = tempfile.NamedTemporaryFile()
    os.execlp('dnsmasq', 'dnsmasq', '-d', '-z', '-I', 'lo', '-i', devname,
              '-a', gateway, '-A', '/gateway/' + gateway,
              '--dhcp-sequential-ip', '-l', leasefile.name, '-F',
              first_guest + ',' + last_guest)
    sys.stderr.write('ERROR RUNNING dnsmasq\n')


def run_sshd(gateway):
    "runs sshd on interface"
    if os.fork() != 0:
        return
    vagrant_priv = tempfile.NamedTemporaryFile()
    vagrant_priv.write(VAGRANT_PRIV)
    vagrant_priv.flush()
    vagrant_pub = tempfile.NamedTemporaryFile(dir='/var/run')
    os.chmod(vagrant_pub.name, 0o644)
    vagrant_pub.write(VAGRANT_PUB)
    vagrant_pub.flush()
    os.chmod(vagrant_pub.name, 0o644)
    sshd_path = spawn.find_executable('sshd')
    os.execlp(sshd_path, sshd_path, '-D', '-h', vagrant_priv.name, '-f',
              '/dev/null', '-o', 'Port=2222', '-o', 'ListenAddress=' + gateway,
              '-e', '-o', 'AuthorizedKeysFile=' + vagrant_pub.name, '-o',
              'Subsystem=sftp internal-sftp', '-o', 'PermitEmptyPasswords=yes',
              '-o', 'UsePAM=yes')
    sys.stderr.write('ERROR RUNNING sshd\n')
    sys.exit(1)


class Cgroup(object):
    """Cgroup allows creation and manipulation
    of cgroup v1 through filesystem"""

    def mk_cgroup(self, name):
        "create a new cgroup"
        new_cgroup = os.path.join(self.cgrouproot, name)
        if not os.path.exists(new_cgroup):
            os.mkdir(new_cgroup)
        return new_cgroup

    def cgroup_procs(self, name):
        'list of pids in cgroup'
        cgroup_procs = os.path.join(self.mk_cgroup(name), 'cgroup.procs')
        with open(cgroup_procs, 'r') as fileobj:
            return [int(x) for x in fileobj.readlines()]

    def is_cgroup_empty(self, name):
        "is_cgroup_empty returns true if no processes belong there"
        cgroup_procs = os.path.join(self.mk_cgroup(name), 'cgroup.procs')
        with open(cgroup_procs, 'r') as fileobj:
            return fileobj.read().strip() == ''

    def join_cgroup(self, name):
        "create and join a cgroup"
        cgroup_procs = os.path.join(self.mk_cgroup(name), 'cgroup.procs')
        with open(cgroup_procs, 'w') as fileobj:
            fileobj.write('%s\n' % os.getpid())

    def __init__(self):
        self.cgrouproot = self.find_create_cgroup()

    @classmethod
    def find_create_cgroup(cls):
        "tries to fetch systemd cgroup, creates new dir if can't find"
        cgroup_dir = '/sys/fs/cgroup/systemd'
        if not cls.is_cgroup_mount_entry(cgroup_dir):
            cgroup_dir = tempfile.NamedTemporaryFile(dir='/var/run').name
            subprocess.check_call(['mount', '-t', 'cgroup', '-o',
                                   'none,name=systemd,xattr', 'systemd',
                                   cgroup_dir])
        return cgroup_dir

    @classmethod
    def is_cgroup_mount_entry(cls, path):
        "returns true if path is mounted as cgroup"
        if not os.path.exists(path):
            return False
        path = os.path.realpath(path)
        mount_entries = cls.mount_entries()
        return mount_entries[path].type_ == 'cgroup'

    @classmethod
    def mount_entries(cls):
        "return list of mount entries"
        with open('/proc/mounts') as fileobj:
            return {cls.mount_entry(line).dir_: cls.mount_entry(line)
                    for line in fileobj.readlines()}

    @classmethod
    def mount_entry(cls, line):
        "parse /proc/mounts entry to MountEntry object"
        fsname, dir_, type_, opts, freq, passno = line.split()
        return cls.MountEntry(fsname=fsname,
                              dir_=dir_,
                              type_=type_,
                              opts=opts,
                              freq=freq,
                              passno=passno)

    MountEntry = namedtuple(
        'MountEntry', ['fsname', 'dir_', 'type_', 'opts', 'freq', 'passno'])


VAGRANT_PRIV = b'''
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzI
w+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoP
kcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2
hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NO
Td0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcW
yLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQIBIwKCAQEA4iqWPJXtzZA68mKd
ELs4jJsdyky+ewdZeNds5tjcnHU5zUYE25K+ffJED9qUWICcLZDc81TGWjHyAqD1
Bw7XpgUwFgeUJwUlzQurAv+/ySnxiwuaGJfhFM1CaQHzfXphgVml+fZUvnJUTvzf
TK2Lg6EdbUE9TarUlBf/xPfuEhMSlIE5keb/Zz3/LUlRg8yDqz5w+QWVJ4utnKnK
iqwZN0mwpwU7YSyJhlT4YV1F3n4YjLswM5wJs2oqm0jssQu/BT0tyEXNDYBLEF4A
sClaWuSJ2kjq7KhrrYXzagqhnSei9ODYFShJu8UWVec3Ihb5ZXlzO6vdNQ1J9Xsf
4m+2ywKBgQD6qFxx/Rv9CNN96l/4rb14HKirC2o/orApiHmHDsURs5rUKDx0f9iP
cXN7S1uePXuJRK/5hsubaOCx3Owd2u9gD6Oq0CsMkE4CUSiJcYrMANtx54cGH7Rk
EjFZxK8xAv1ldELEyxrFqkbE4BKd8QOt414qjvTGyAK+OLD3M2QdCQKBgQDtx8pN
CAxR7yhHbIWT1AH66+XWN8bXq7l3RO/ukeaci98JfkbkxURZhtxV/HHuvUhnPLdX
3TwygPBYZFNo4pzVEhzWoTtnEtrFueKxyc3+LjZpuo+mBlQ6ORtfgkr9gBVphXZG
YEzkCD3lVdl8L4cw9BVpKrJCs1c5taGjDgdInQKBgHm/fVvv96bJxc9x1tffXAcj
3OVdUN0UgXNCSaf/3A/phbeBQe9xS+3mpc4r6qvx+iy69mNBeNZ0xOitIjpjBo2+
dBEjSBwLk5q5tJqHmy/jKMJL4n9ROlx93XS+njxgibTvU6Fp9w+NOFD/HvxB3Tcz
6+jJF85D5BNAG3DBMKBjAoGBAOAxZvgsKN+JuENXsST7F89Tck2iTcQIT8g5rwWC
P9Vt74yboe2kDT531w8+egz7nAmRBKNM751U/95P9t88EDacDI/Z2OwnuFQHCPDF
llYOUI+SpLJ6/vURRbHSnnn8a/XG+nzedGH5JGqEJNQsz+xT2axM0/W/CRknmGaJ
kda/AoGANWrLCz708y7VYgAtW2Uf1DPOIYMdvo6fxIB5i9ZfISgcJ/bbCUkFrhoH
+vq/5CIWxCPp0f85R4qxxQ5ihxJ0YDQT9Jpx4TMss4PSavPaBH3RXow5Ohe+bYoQ
NE5OgEXk2wVfZczCZpigBKbKZHNYcelXtTt/nP3rsCuGcM4h53s=
-----END RSA PRIVATE KEY-----
'''
VAGRANT_PUB = b'''
ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant insecure public key
'''

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print('Exit Due to keyboard interrupt')
        sys.exit(1)
