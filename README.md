# RE-helper

This tool is made with the intention of helping with solving Reverse Engineering
challenges during CTFs (Capture the Flag) contest.

< This repository is still a Work in Progress >

## Enivironment Setup 

- Clone the repository to your system `git clone https://github.com/R3x/RE-helper.git ~/RE-helper`
- Go to the folder containing the Setup `cd ~/RE-helper`
- Run `setup.sh` to setup the tool environment and build the tool. 
	- Initially to setup the tool enviroment run `./setup.sh -t`. This would give you the tool build at out/
	- If you have made some modifications to the source and want to `rebuild` the tool you can use `./setup.sh -m`
	- If you want to `test` the tool with the existing test programs to see the result - `./setup.sh -t <testno>`
	- To clean all the built executables and files you can run `./setup.sh -c`
- After you have setup the tool, you can run it on an executable of your choice using 
	`./pin/pin -t out/main_trace.so -o out.log -- <path/to/executable>`
- Start racking up points on the scoreboard

### Note
* This repository is still under active development and the commands are subject to change.
* The tool is written with amd64 architecture kept in mind.

## TODO

A lot of work is left to be done :
- Improve Tainting
- Imporve Syscall logging (Add functions, arguments etc) 

# About the Author

This repository is maintaned by **Siddharth Muralee**(@R3x).

Contact :
- Twitter : @Tr3x\_\_
- Gmail: siddharth DOT muralee AT gmail DOT com

