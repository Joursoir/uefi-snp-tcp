#!/usr/bin/env bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 
   exit 1
fi

qemu-system-x86_64 \
	-drive if=pflash,format=raw,readonly=off,file=bins/OVMF-debug-full-network-stack.fd \
	-drive format=raw,file=fat:rw:hd \
	-machine q35 \
	-netdev tap,id=mynet0,ifname=tap0,script=no,downscript=no \
	-device e1000,netdev=mynet0,mac=52:55:00:d1:55:02 \
  	-global isa-debugcon.iobase=0x402 \
  	-debugcon file:debug.log &
sleep 2s
ip addr add 192.168.0.1/24 dev tap0
ip link set up dev tap0
tail -f debug.log

# Create a network backend:
# -netdev TYPE,id=NAME,... 
#
# Create a tap network backend with id `mynet0`. This will connect to a tap 
# interface `tap0` which must be already setup. Do not use any network configuration scripts.

# Create a virtual network device:
# -device TYPE,netdev=NAME
#
# Create a NIC (model e1000) and connect to `mynet0` backend created by the previous parameter.
# Also specify a mac address for the NIC.

# Disable the iPXE support:
# --global e1000.romfile="" -global virtio-net-pci.romfile="" -global i82557b.romfile=""
#
# For OVMF, each virtual network device (e.g. e1000, virtio-net-pci, i82557b) can utilize an
# included iPXE stack (ROMFILE) and UEFI networking. iPXE is enabled by default. You can use
# the "romfile=" to disable the iPXE support so OVMF only utilizes the EDK II network stack.