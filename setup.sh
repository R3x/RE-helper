#!/bin/bash

usage()
{
	echo "Usage   : $0 [ OPTIONS ]"
	echo "Options :  "
	echo "     -s : Setup"
	echo "     -m : Make"
	echo "     -t : Test"
}

if [ $# -eq 0 ]
then
	usage
	exit
fi

while getopts "smt" opt ;do
	case "${opt}" in
		s)
			echo "Installing Intel PIN"
			URL=https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz

			wget $URL -O pin.tar.gz 
			tar -xvf pin.tar.gz
			rm pin.tar.gz
			#Install Ubuntu Dependencies
			sudo apt-get install gcc-multilib g++-multilib libc6-dev-i386
			#Rename pin directory
			mv pin-* pin
			mkdir out/
			cd src
			export PIN_ROOT=../pin/
			make
			mv obj-intel64/ ../out
			echo "=================================================="
			echo "                 Setup Completed                  "
			echo "=================================================="
			echo " Now run with : pin/pin -t obj/maintrace.so -o <logfile> -- <file to be traced>"
			;;
		m) 
			rm -rf out/
			cd src 
			export PIN_ROOT=../pin/
			make
			mv obj-intel64/ ../out
			echo "=================================================="
			echo "                 Make Completed                  "
			echo "=================================================="
			echo " Now run with : pin/pin -t obj/maintrace.so -o <logfile> -- <file to be traced>"
			;;
		t)
			rm -rf out/
			cd src 
			export PIN_ROOT=../pin/
			make
			mv obj-intel64/ ../out
			cd ..
			./pin/pin -t out/main_trace.so -o out.log -- test/basic1/basic1 
			;;
		*)
			echo "Invalid Option"
			usage
			;;
	esac
done
