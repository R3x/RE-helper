#include "pin.H"
#include <iostream>
#include <fstream>

std::ofstream TraceFile;

KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool",
		"o", "trace.out", "specify trace file name");

INT32 Usage()
{
	cerr << "This tool tries to help a CTF player to find useful information";

	cerr << KNOB_BASE::StringKnobSummary();

	cerr << endl;

	return -1;	

}

VOID Trace(TRACE trace, VOID *v)
{
	for (BBL bbl = TRACE_BblHead(trace); BBL_Valid(bbl); bbl = BBL_Next(bbl))
	{
		string traceString = "";

		for ( INS ins = BBL_InsHead(bbl); INS_Valid(ins); ins = INS_Next(ins))
		{
			traceString +=  "%" + INS_Disassemble(ins) + "\n";
		}
	}
}

VOID Fini(INT32 code, VOID *v)
{
	TraceFile << "# eof" << endl;

	TraceFile.close();
}

int  main(int argc, char *argv[])
{
	string trace_header = string("#\n"
			"# RE-helper trace File\n"
			"# Siddharth Muralee (@R3x)\n"
			"#\n");


	if( PIN_Init(argc,argv) )
	{
		return Usage();
	}


	TraceFile.open(KnobOutputFile.Value().c_str());
	TraceFile.write(trace_header.c_str(),trace_header.size());


	TRACE_AddInstrumentFunction(Trace, 0);
	PIN_AddFiniFunction(Fini, 0);

	// Never returns

	PIN_StartProgram();

	return 0;
}

