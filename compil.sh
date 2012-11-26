#!/bin/bash
clear
gcc *.c -o Checksum_Correcteur -std=c99 -lpcap -D_GNU_SOURCE
