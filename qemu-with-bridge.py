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
import tempfile
import threading

from collections import namedtuple

import ctypes
from ctypes.util import find_library
PR_SET_PDEATHSIG = 1


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
    parser.add_argument('cmd', nargs='+')
    parser.add_argument(
        '--net',
        '-n',
        help='network address of the interface, default mask /24')
    args = parser.parse_args()
    ip = ipaddress.ip_address(args.net)
    gateway = ip_set_last(ip, 199)
    first_guest = ip_set_last(ip, 10)
    last_guest = ip_set_last(ip, 198)
    devname = 'br_' + args.net
    # can fail, since it might not exist
    subprocess.call(['ip', 'link', 'del', 'dev', devname])
    subprocess.check_call(
        ['ip', 'link', 'add', 'dev', devname, 'type', 'bridge'])
    subprocess.check_call(['sudo', 'ip', 'link', 'set', 'dev', devname, 'up'])
    subprocess.check_call(
        ['ip', 'addr', 'add', gateway + '/24', 'dev', devname])
    dnsmasq_pidfile = '/tmp/' + devname + '.pid'
    if os.path.exists(dnsmasq_pidfile):
        with open(dnsmasq_pidfile) as fp:
            dnsmasq_pid = fp.read().strip()
        subprocess.call(['sudo', 'kill', dnsmasq_pid])
        subprocess.call(['sudo', 'kill', '-9', dnsmasq_pid])
    subprocess.call(
        ['sudo', 'bash', '-c', 'pgrep -f "i ' + devname + '"|xargs sudo kill'])
    def masquerade():
        Iptables.masquarade_all_to(default_gateway_iface())
    masquerade()
    repeat_every(5, masquerade)
    if os.fork() == 0:
        libc = ctypes.CDLL(find_library('c'))
        libc.prctl(PR_SET_PDEATHSIG, signal.SIGINT)
        leasefile = tempfile.NamedTemporaryFile()
        os.execlp('dnsmasq', 'dnsmasq', '-d', '-z', '-I', 'lo', '-i', devname,
                  '-a', gateway, '--dhcp-sequential-ip', '-l', leasefile.name,
                  '-F', first_guest + ',' + last_guest)
        print('ERROR RUNNING dnsmasq')
        return
    if 'bridge0' not in ' '.join(args.cmd):
        os.execlp(args.cmd[0], args.cmd[0], '-netdev',
                  'type=bridge,id=bridge0,br=' + devname, '-device',
                  'virtio-net-pci,netdev=bridge0,mac=DE:AD:BE:EF:43:1F',
                  *args.cmd[1:])
    os.execlp(args.cmd[0], args.cmd[0], '-netdev',
              'type=bridge,id=bridge0,br=' + devname, *args.rest[1:])


class Iptables:
    "access to iptables information via iptables command"
    entry = namedtuple(
        'iptable_entry',
        ['pkts', 'bytes', 'target', 'prot', 'opt', 'in_', 'out', 'src', 'dst'])

    @staticmethod
    def get_postrouting(txt=None):
        "returns the POSTROUTING table lines"
        if not txt:
            txt = subprocess.check_output(
                ['iptables', '-v', '-t', 'nat', '-L', 'POSTROUTING'])
        return [Iptables.entry(*x.split()[:9])
                for x in txt.strip().split(b'\n')[2:]]

    @staticmethod
    def is_entry_masquerade_to(ent, iface):
        "returns true if iptables' entry masquarade all traffic to given iface"
        return all([ent.prot == b'all', ent.target == b'MASQUERADE',
                    ent.in_ == b'any', ent.src == b'anywhere',
                    ent.dst == b'anywhere', ent.out == iface])

    @staticmethod
    def has_masquerade_to(iface):
        "do we have masquerade rule for interface iface?"
        for ent in Iptables.get_postrouting():
            if Iptables.is_entry_masquerade_to(ent, iface):
                return True
        return False

    @staticmethod
    def masquarade_all_to(iface):
        "add masquerade rule to interface iface if needed"
        if not Iptables.has_masquerade_to(iface):
            print('adding masquarade rule for interface', iface)
            subprocess.check_call(
                ['iptables', '-t', 'nat', '-A', 'POSTROUTING', '-o', iface,
                 '-j', 'MASQUERADE'])


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


if __name__ == '__main__':
    main()
