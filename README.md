# QEMU-with-bridge

## Purpose

Many times, you want to run a guest, or a couple of guests, on an isolated
network, with internet access.

One way to do that, is to setup a bridge, configure NAT for this bridge, and
add guest's network interface to the bridge.

Interop from the host is also needed during development. I configured an SSH
server on the host, that would allow the guest to mount host via sshfs.

Automatically configuring the guests network is also vital, the script loads
dnsqmasq on the bridge and allow guest to be configured with DHCP.

This configuration is not trivial, and henced I merged all the required steps
to a single python script.

WARNING: for development purposes only, allows root access on host through guest.

## Example Use Case

Run the same image 10 times, and wait for one of them to crash.

## Usage Examples

Running a single KVM on 192.167.1.10

    $ qemu-with-bridge.py -n 192.168.1.0 -- kvm -drive file=hd.qcow,if=virtio

Running two machines on 192.168.2.10, 192.168.1.11, the first with virtio network
device, the second with default `e1000`

    $ qemu-with-bridge.py -V -n 192.168.1.0 -- kvm -snaphsot -drive file=hd.qcow,if=virtio
    $ # waiting for first VM to get IP from builtin DHCP
    $ qemu-with-bridge.py -a -n 192.168.1.0 -- kvm -snaphsot -drive file=hd.qcow,if=virtio

## How it works

This scripts creates an isolated network environment,
and adds necessary configuration to the given QEMU command line to run
in this network.

Typical Usage

    $ qemu-with-bridge.py -n 192.168.1.0 -- kvm -drive file=hd.qcow,if=virtio

This would:

    0. Verify no previous VM on 192.168.1.0/24 is running, by checking
       a cgroup in a known name.
    1. Create a new bridge
    2. Set it up, and give its BR0 address of 192.168.1.199
    3. Run dnsmasq on 192.168.1.199, set it to give addresses from
       192.168.1.10 to DHCP requests
    4. Run sshd on 192.168.1.199:2222, set it up to accept vagrant
       insecure SSH key for root. Useful for sshfs from guest.
    5. Adds itself, and hence all children to a cgroup whose name
       is derived from 192.168.1.0/24 subnet.
    6. Runs a thread that sets NAT to the default gateway every 5
       seconds. This is done so that internet would still work even
       if laptop default gateway changes, e.g., wifi, or VPN.
       This is a hack, which will be fixed in future.
    7. Takes the given command line, adds command line to set a new
       tap device on bridge for qemu, and run the resulting command line.

This gives an easy way to run many identical VMs in isolated network.
