#!/bin/bash

E1000E="e1000e"
E1000="e1000"



echo "=== Cleaning GAO Module ==="
make clean

echo "=== Cleaning e1000e Driver ==="
cd $E1000E
make clean
cd ..

echo "=== Cleaning e1000 Driver ==="
cd $E1000
make clean
cd ..


echo "=== Building GAO Module ==="
make

cp Module.symvers $E1000E/
cp Module.symvers $E1000/

echo "=== Building e1000e Driver ==="
cd $E1000E
make
cd ..

#echo "=== Building e1000 Driver ==="
#cd $E1000
#make
#cd ..

echo "=== Done ==="

