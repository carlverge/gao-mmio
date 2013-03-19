#!/bin/bash

rmmod e1000e
#rmmod e1000
rmmod gaommio
insmod gaommio.ko
insmod e1000e/e1000e.ko
#insmod e1000/e1000.ko
ifconfig eth1 up promisc
ifconfig eth2 up promisc
#ifconfig eth3 up
