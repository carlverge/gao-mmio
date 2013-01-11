#!/bin/bash

rmmod e1000e
insmod e1000e/e1000e.ko
ifconfig eth1 up
