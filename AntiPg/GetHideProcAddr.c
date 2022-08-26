#include "a.h"

PVOID64 Get_Proc_Address(IN PCWSTR FuncStr)
{
#if AMD64
	PUCHAR addr;
	UNICODE_STRING pslookup;
#else
	PUCHAR addr;
	UNICODE_STRING pslookup;
#endif



	RtlInitUnicodeString(&pslookup, FuncStr);

	addr = (PVOID64)MmGetSystemRoutineAddress(&pslookup);
	if (!addr)return -1;

	return addr;
}


