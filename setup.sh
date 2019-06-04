#!/bin/bash

usage()
{
        echo "Usage   : $0 [ OPTIONS ]"
        echo "Options :  "
        echo "     -s : Setup"
}

if [ $# -eq 0 ]
then
        usage
        exit
fi

while getopts "s" opt ;do
        case "${opt}" in
                s)
						echo "Installing Intel PIN"
						URL=https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.7-97619-g0d0c92f4f-gcc-linux.tar.gz

						wget $URL -O pin.tar.gz 
						tar -xvf pin.tar.gz

						#Install Ubuntu Dependencies
						sudo apt-get install gcc-multilib g++-multilib libc6-dev-i386
						
						#Rename pin directory
						mv pin-* pin
						
						sudo apt install python3-pip
						pip3 install ipython
						;;
				*)
						echo "Invalid Option"
						usage
						;;
		esac
done
