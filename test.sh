#!/bin/bash 

make
kill -9 $(pidof attacker)

echo -e "\nStarting attacker on core 0: "
./attacker 0x55555554123 0x55555555345 0 &



echo -e "\nTesting victim on core 0: "
sudo nice -n -19 ./victim-PRCTL 0x55555554123 0x55555555345 0


echo -e "\nkilling attacker"
kill -9 $(pidof attacker)

make clean