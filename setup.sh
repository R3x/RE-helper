#!/bin/bash

usage()
{
	echo "Usage   : $0 [ OPTIONS ]"
	echo "Options :  "
	echo "     -s : Setup"
	echo "     -m : Make"
	echo "     -t <test number> : Test"
	echo "     -c : Clean"
}

if [ $# -eq 0 ]
then
	usage
	exit
fi

while getopts "smt:c" opt ;do
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
			echo "=================================================="
			echo "                 Make Completed                  "
			echo "=================================================="
			if [ ${OPTARG} = "1" ]; then
				echo "Now running : ./pin/pin -t out/main_trace.so -o out.log -- test/basic1/basic1"
				./pin/pin -t out/main_trace.so -o out.log -- test/basic1/basic1
			fi
			if [ ${OPTARG} = "2" ]; then
				echo "Now running : ./pin/pin -t out/main_trace.so -o out.log -- test/basic2/basic2"
				./pin/pin -t out/main_trace.so -o out.log -- test/basic2/basic2
			fi
			if [ ${OPTARG} = "3" ]; then
				echo "Now running : ./pin/pin -t out/main_trace.so -o out.log -- test/basic3/basic3"
				./pin/pin -t out/main_trace.so -o out.log -- test/basic3/basic3
			fi
			;;
		c)
			rm -rf out/
			rm status.log out.log syscall.log pin.log
			;;
		*)
			echo "Invalid Option"
			usage
			;;
	esac
done
