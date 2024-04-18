#!/bin/bash
sudo rmmod sha2563
make clean

make
sudo insmod sha2563.ko
echo "success\n"


