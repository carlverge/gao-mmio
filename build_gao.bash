#!/bin/bash

echo "=== Cleaning GAO Module ==="
make clean

echo "=== Cleaning e1000e Driver ==="
cd e1000e
make clean
cd ..

echo "=== Cleaning e1000 Driver ==="
cd e1000
make clean
cd ..


echo "=== Building GAO Module ==="
make

cp Module.symvers e1000e/
cp Module.symvers e1000/

echo "=== Building e1000e Driver ==="
cd e1000e
make
cd ..

echo "=== Building e1000 Driver ==="
cd e1000
make
cd ..

echo "=== Done ==="

