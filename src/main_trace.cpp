#include "pin.H"
#include <asm/unistd.h>
#include <iostream>
#include <fstream>
#include <list>

#define TRACE_MAX 100
#define TAINT_BASIC 20
#define LIBC_BASE 0x70000000000
/*
 * VARIABLES
 */

std::ofstream TraceFile;
std::ofstream StatusFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
				"o", "trace.out", "specify trace file name");

static unsigned int sys_lock;
static bool status_lock;
static bool status_flag;
static unsigned int status_ctr;

/*
 * STRUCTURES FOR TAINTING
 */

/* bytes range tainted */
struct range
{
		UINT64 start;
		UINT64 size;
};

std::list<struct range> bytesTainted;
std::list<UINT64> addressTainted;
std::list<REG> regsTainted;

enum {
		MODE_READ,
		MODE_WRITE,
		MODE_FOLLOW,
		MODE_SPREAD,
		MODE_MAX };

/*
 * PIN BASED FUNCTIONS  
 */

INT32 Usage()
{
		cerr << "This tool tries to help a CTF player to find useful information";

		cerr << KNOB_BASE::StringKnobSummary();

		cerr << endl;

		return -1;	

}

/*
   static VOID syscallInstructionInstrumentation (THREADID tid, CONTEXT * ctx)
   {
   cout << "[IP2]\t\t 0x" << static_cast<UINT64>((PIN_GetContextReg(ctx, REG_INST_PTR))) << endl;
   cout << "[RDX]\t\t 0x" << static_cast<UINT64>((PIN_GetContextReg(ctx, REG_RDX))) << endl;
   cout << "[RAX]\t\t 0x" << static_cast<UINT64>((PIN_GetContextReg(ctx, REG_RAX))) << endl;
   }
   */


bool checkAlreadyRegTainted(REG reg)
{
		list<REG>::iterator i;

		for(i = regsTainted.begin(); i != regsTainted.end(); i++){
				if (*i == reg){
						return true;
				}
		}
		return false;
}

bool addressinlibc(UINT64 addr)
{
		/*
		 * NOTE - this technique is really crude - figure out a better alternative
		 */  
		if (addr > LIBC_BASE) {
				return true;
		}
		return false;
}

VOID removeMemTainted(UINT64 addr)
{
		addressTainted.remove(addr);
		//std::cout << std::hex << "\t\t\t" << addr << " is now freed" << std::endl;
		// status flag 
		status_flag = true;
}

VOID addMemTainted(UINT64 addr)
{
		bool taint_flag = false;
		list<struct range>::iterator i;
		struct range taint;
		
		addressTainted.push_back(addr);
		// If address in range 
		for(i = bytesTainted.begin(); i != bytesTainted.end(); i++) {
				if (((struct range) *i).start <= addr && ((struct range) *i).size + ((struct range) *i).start >= addr) {
					// Address already in tainted region
					taint_flag = true;
					break;
				}
		}
	
		if (taint_flag == false) {
			// Address hasn't been tainted earlier
			taint.start = addr;
			taint.size = TAINT_BASIC;
			bytesTainted.push_back(taint);
		}

		std::cout << std::hex << "\t\t\t" << addr << " is now tainted" << std::endl;
		// status flag 
		status_flag = true;
}


bool taintReg(REG reg)
{
		if (checkAlreadyRegTainted(reg) == true){
				//std::cout << "\t\t\t" << REG_StringShort(reg) << " is already tainted" << std::endl;
				return false;
		}

		switch(reg){

				case REG_RAX:  regsTainted.push_front(REG_RAX);
				case REG_EAX:  regsTainted.push_front(REG_EAX);
				case REG_AX:   regsTainted.push_front(REG_AX);
				case REG_AH:   regsTainted.push_front(REG_AH);
				case REG_AL:   regsTainted.push_front(REG_AL);
							   break;

				case REG_RBX:  regsTainted.push_front(REG_RBX);
				case REG_EBX:  regsTainted.push_front(REG_EBX);
				case REG_BX:   regsTainted.push_front(REG_BX);
				case REG_BH:   regsTainted.push_front(REG_BH);
				case REG_BL:   regsTainted.push_front(REG_BL);
							   break;

				case REG_RCX:  regsTainted.push_front(REG_RCX);
				case REG_ECX:  regsTainted.push_front(REG_ECX);
				case REG_CX:   regsTainted.push_front(REG_CX);
				case REG_CH:   regsTainted.push_front(REG_CH);
				case REG_CL:   regsTainted.push_front(REG_CL);
							   break;

				case REG_RDX:  regsTainted.push_front(REG_RDX);
				case REG_EDX:  regsTainted.push_front(REG_EDX);
				case REG_DX:   regsTainted.push_front(REG_DX);
				case REG_DH:   regsTainted.push_front(REG_DH);
				case REG_DL:   regsTainted.push_front(REG_DL);
							   break;

				case REG_RDI:  regsTainted.push_front(REG_RDI);
				case REG_EDI:  regsTainted.push_front(REG_EDI);
				case REG_DI:   regsTainted.push_front(REG_DI);
				case REG_DIL:  regsTainted.push_front(REG_DIL);
							   break;

				case REG_RSI:  regsTainted.push_front(REG_RSI);
				case REG_ESI:  regsTainted.push_front(REG_ESI);
				case REG_SI:   regsTainted.push_front(REG_SI);
				case REG_SIL:  regsTainted.push_front(REG_SIL);
							   break;

				default:
							   //std::cout << "\t\t\t" << REG_StringShort(reg) << " can't be tainted" << std::endl;
							   return false;
		}
		//std::cout << "\t\t\t" << REG_StringShort(reg) << " is now tainted" << std::endl;
		// status flag 
		status_flag = true;
		return true;
}

bool removeRegTainted(REG reg)
{
		switch(reg){

				case REG_RAX:  regsTainted.remove(REG_RAX);
				case REG_EAX:  regsTainted.remove(REG_EAX);
				case REG_AX:   regsTainted.remove(REG_AX);
				case REG_AH:   regsTainted.remove(REG_AH);
				case REG_AL:   regsTainted.remove(REG_AL);
							   break;

				case REG_RBX:  regsTainted.remove(REG_RBX);
				case REG_EBX:  regsTainted.remove(REG_EBX);
				case REG_BX:   regsTainted.remove(REG_BX);
				case REG_BH:   regsTainted.remove(REG_BH);
				case REG_BL:   regsTainted.remove(REG_BL);
							   break;

				case REG_RCX:  regsTainted.remove(REG_RCX);
				case REG_ECX:  regsTainted.remove(REG_ECX);
				case REG_CX:   regsTainted.remove(REG_CX);
				case REG_CH:   regsTainted.remove(REG_CH);
				case REG_CL:   regsTainted.remove(REG_CL);
							   break;

				case REG_RDX:  regsTainted.remove(REG_RDX);
				case REG_EDX:  regsTainted.remove(REG_EDX);
				case REG_DX:   regsTainted.remove(REG_DX);
				case REG_DH:   regsTainted.remove(REG_DH);
				case REG_DL:   regsTainted.remove(REG_DL);
							   break;

				case REG_RDI:  regsTainted.remove(REG_RDI);
				case REG_EDI:  regsTainted.remove(REG_EDI);
				case REG_DI:   regsTainted.remove(REG_DI);
				case REG_DIL:  regsTainted.remove(REG_DIL);
							   break;

				case REG_RSI:  regsTainted.remove(REG_RSI);
				case REG_ESI:  regsTainted.remove(REG_ESI);
				case REG_SI:   regsTainted.remove(REG_SI);
				case REG_SIL:  regsTainted.remove(REG_SIL);
							   break;

				default:
							   return false;
		}
		//std::cout << "\t\t\t" << REG_StringShort(reg) << " is now freed" << std::endl;
		// status flag 
		status_flag = true;
		return true;
}

VOID report(int mode, UINT64 addr, UINT64 insAddr, std::string insDis, bool isLibc) {
		if (isLibc) 
				return;
		switch (mode) {
				case MODE_READ:
						std::cout << std::hex << "[READ in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
						break;
				case MODE_WRITE:
						std::cout << std::hex << "[WRITE in " << addr << "]\t" << insAddr << ": " << insDis << std::endl;
						break;
				case MODE_FOLLOW:
						std::cout << "[FOLLOW]\t\t" << insAddr << ": " << insDis << std::endl;
						break;	
				case MODE_SPREAD:
						std::cout << "[SPREAD]\t\t" << insAddr << ": " << insDis << std::endl;
						break;	
				default:
						cerr << "[*] Internal Error - Mode not found";
						break;
		}
}

/*
 * Function for load instructions (Instructions that read from memory)
 * type = mov reg1, [reg2]
 *
 */
VOID ReadMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
		list<UINT64>::iterator i;
		UINT64 addr = memOp;

		if (opCount != 2)
				return;

		for(i = addressTainted.begin(); i != addressTainted.end(); i++){
				if (addr == *i){
						report(MODE_READ, addr, insAddr, insDis, addressinlibc(insAddr));
						taintReg(reg_r);
						return ;
				}
		}
		/* if mem != tained and reg == taint => free the reg */
		if (checkAlreadyRegTainted(reg_r)){
				report(MODE_READ, addr, insAddr, insDis, addressinlibc(insAddr));
				removeRegTainted(reg_r);
		}
}

/*
 * Function for store instructions (Instructions that read from memory)
 * type = mov [reg1], reg2
 *
 */
VOID WriteMem(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, UINT64 memOp)
{
		list<UINT64>::iterator i;
		UINT64 addr = memOp;

		if (opCount != 2)
				return;

		for(i = addressTainted.begin(); i != addressTainted.end(); i++){
				if (addr == *i){
						report(MODE_WRITE, addr, insAddr, insDis, addressinlibc(insAddr));
						if (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))
								removeMemTainted(addr);
						return ;
				}
		}

		if (checkAlreadyRegTainted(reg_r)){
				report(MODE_WRITE, addr, insAddr, insDis, addressinlibc(insAddr));
				addMemTainted(addr);
		}
}

VOID spreadRegTaint(UINT64 insAddr, std::string insDis, UINT32 opCount, REG reg_r, REG reg_w)
{
		if (opCount != 2)
				return;

		if (REG_valid(reg_w)){
				if (checkAlreadyRegTainted(reg_w) && (!REG_valid(reg_r) || !checkAlreadyRegTainted(reg_r))){
						report(MODE_SPREAD, 0xdeadbeef, insAddr, insDis, addressinlibc(insAddr));
						std::cout << "\t\t\toutput: "<< REG_StringShort(reg_w) << " | input: " << (REG_valid(reg_r) ? REG_StringShort(reg_r) : "constant") << std::endl;
						removeRegTainted(reg_w);
				}
				else if (!checkAlreadyRegTainted(reg_w) && checkAlreadyRegTainted(reg_r)){
						report(MODE_SPREAD, 0xdeadbeef, insAddr, insDis, addressinlibc(insAddr));
						std::cout << "\t\t\toutput: " << REG_StringShort(reg_w) << " | input: "<< REG_StringShort(reg_r) << std::endl;
						taintReg(reg_w);
				}
		}
}

VOID followData(UINT64 insAddr, std::string insDis, REG reg)
{
		if (!REG_valid(reg))
				return;

		if (checkAlreadyRegTainted(reg)){
				report(MODE_FOLLOW, 0xdeadbeef, insAddr, insDis, addressinlibc(insAddr));
		}
}

VOID dump_data(UINT64 addr, UINT64 size, char * data_region) {
		UINT64 i;

		std::cout << "\t[ADDR - 0x" << std::hex << addr << "]\n" 
				<< "\t-- [STRING] : " << data_region << "\n\t-- [HEX] :\n\t";

		for ( i = 0; i < ((size > TRACE_MAX) ? TRACE_MAX : size) ; i++ ) {
				printf("%02x ", data_region[i]);
				if ( i != 0 && (i + 1) % 10 == 0 ) {
						cout << "\n\t";
				}
		}
		cout << "\n";
		return;
}

VOID dump_registers(CONTEXT * ctx) {
		list<REG>::iterator i;
		list<REG>::iterator reg;
		std::list<REG> regsUnique;
		bool reg_flag;

        for(i = regsTainted.begin(); i != regsTainted.end(); i++){
			reg_flag = false;
			REG x = REG_FullRegName(*i);
			for(reg = regsUnique.begin(); reg != regsUnique.end(); reg++) {
					if (*reg == x) {
						reg_flag = true;
						break;
					}
			}
			if (reg_flag == false) {
					regsUnique.push_back(x);
			}
		}		
		for(reg = regsUnique.begin(); reg != regsUnique.end(); reg++) {
			char buffer[100];
			sprintf(buffer, "[ %s ] :\t 0x%016lx { String display coming soon }\n",  REG_StringShort(*reg).c_str(), static_cast<UINT64>((PIN_GetContextReg(ctx, *reg))));
			//std::cout << "[" << REG_StringShort(*reg) << "]  :\t" << static_cast<UINT64>((PIN_GetContextReg(ctx, *reg))) << endl;
			std::cout << buffer;
		}
}

VOID DisplayStatus(THREADID tid, CONTEXT * ctx) {
		list<struct range>::iterator i;
		char * data_region;

		std::cout << "========================STATUS "<< status_ctr << "=====================\n";
		std::cout << "[IP]\t\t 0x" << static_cast<UINT64>((PIN_GetContextReg(ctx, REG_INST_PTR))) << endl;

		std::cout << endl << "## REGISTERS" << endl;
		dump_registers(ctx);	

		std::cout << endl << "## TAINTED MEMORY" << endl;
		
		for(i = bytesTainted.begin(); i != bytesTainted.end(); i++) {
				data_region = new char[((struct range) *i).size];
				
				PIN_SafeCopy(data_region, (void *)((struct range) *i).start, ((struct range) *i).size);
				dump_data(((struct range) *i).start, ((struct range) *i).size, data_region);	
				
				delete data_region;
		} 

		std::cout << "====================END OF STATUS=========================\n";
		status_ctr++;
}

VOID Trace(TRACE trace, VOID *v)
{
		/*
		 * Iterate through every branch
		 */
		for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
		{
				string traceString = "";

				/*
				 * Iterate through every instruction 
				 */
				for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
				{
						/*
						// If instruction is a syscall
						if (INS_IsSyscall(ins)) {
								INS_InsertCall (ins, IPOINT_BEFORE, (AFUNPTR)syscallInstructionInstrumentation,
								IARG_THREAD_ID, IARG_CONTEXT, IARG_END);
						}
						*/

						// If a status message hasn't been printed
						if (status_flag && status_lock) {
								INS_InsertCall(
												ins, IPOINT_BEFORE, (AFUNPTR)DisplayStatus,
												IARG_ADDRINT, IARG_THREAD_ID, IARG_CONTEXT, IARG_END);
								status_flag = false;
						}

						if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsRead(ins, 0) && INS_OperandIsReg(ins, 0)){
								INS_InsertCall(
												ins, IPOINT_BEFORE, (AFUNPTR)ReadMem,
												IARG_ADDRINT, INS_Address(ins),
												IARG_PTR, new string(INS_Disassemble(ins)),
												IARG_UINT32, INS_OperandCount(ins),
												IARG_UINT32, INS_OperandReg(ins, 0),
												IARG_MEMORYOP_EA, 0,
												IARG_END);
						}
						else if (INS_OperandCount(ins) > 1 && INS_MemoryOperandIsWritten(ins, 0)){
								INS_InsertCall(
												ins, IPOINT_BEFORE, (AFUNPTR)WriteMem,
												IARG_ADDRINT, INS_Address(ins),
												IARG_PTR, new string(INS_Disassemble(ins)),
												IARG_UINT32, INS_OperandCount(ins),
												IARG_UINT32, INS_OperandReg(ins, 1),
												IARG_MEMORYOP_EA, 0,
												IARG_END);
						}
						else if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
								INS_InsertCall(
												ins, IPOINT_BEFORE, (AFUNPTR)spreadRegTaint,
												IARG_ADDRINT, INS_Address(ins),
												IARG_PTR, new string(INS_Disassemble(ins)),
												IARG_UINT32, INS_OperandCount(ins),
												IARG_UINT32, INS_RegR(ins, 0),
												IARG_UINT32, INS_RegW(ins, 0),
												IARG_END);
						}

						if (INS_OperandCount(ins) > 1 && INS_OperandIsReg(ins, 0)){
								INS_InsertCall(
												ins, IPOINT_BEFORE, (AFUNPTR)followData,
												IARG_ADDRINT, INS_Address(ins),
												IARG_PTR, new string(INS_Disassemble(ins)),
												IARG_UINT32, INS_RegR(ins, 0),
												IARG_END);
						}
						traceString +=  "%" + INS_Disassemble(ins) + "\n";
				}

				//cout << traceString << endl;
		}
}

VOID Syscall_entry(THREADID thread_id, CONTEXT *ctx, SYSCALL_STANDARD std, void *v)
{
		unsigned int i;
		struct range taint;

		if (PIN_GetSyscallNumber(ctx, std) == __NR_read){

				if (sys_lock++ == 0) {
						return;
				}

				taint.start = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 1)));
				taint.size  = static_cast<UINT64>((PIN_GetSyscallArgument(ctx, std, 2)));

				for (i = 0; i < taint.size; i++)
						addressTainted.push_back(taint.start+i);

				bytesTainted.push_back(taint);

				// updates status lock
				status_lock = true;

				std::cout << "[IP]\t\t 0x" << static_cast<UINT64>((PIN_GetContextReg(ctx, REG_INST_PTR))) << endl;		
				std::cout << "[TAINT]\t\t\tbytes tainted from " << std::hex << "0x" << taint.start << " to 0x" << taint.start + taint.size << " (via read)"<< std::endl;
		}
}

VOID Fini(INT32 code, VOID *v)
{
		TraceFile << "# eof" << endl;

		TraceFile.close();
}

/*
 * MAIN CODE
 */

int  main(int argc, char *argv[])
{
		string trace_header = string("#===============================\n"
						"# RE-helper trace File\n"
						"# by Siddharth Muralee (@R3x)\n"
						"#===============================\n");

		string status_header = string("#===============================\n"
						"# RE-helper status File\n"
						"# by Siddharth Muralee (@R3x)\n"
						"#===============================\n");

		/* 
		 *  Initializing constants
		 */

		status_flag = true;
		status_lock = false;

		/*
		 * Pin main 
		 */

		if( PIN_Init(argc,argv) )
		{
				return Usage();
		}

		PIN_SetSyntaxIntel();

		TraceFile.open(KnobOutputFile.Value().c_str());
		TraceFile.write(trace_header.c_str(),trace_header.size());

		StatusFile.open("status.log");
		StatusFile.write(status_header.c_str(),status_header.size());

		PIN_AddSyscallEntryFunction(Syscall_entry, 0);
		TRACE_AddInstrumentFunction(Trace, 0);
		PIN_AddFiniFunction(Fini, 0);

		// Never returns

		PIN_StartProgram();

		return 0;
}

