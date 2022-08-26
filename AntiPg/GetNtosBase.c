#include "GetNtosBase.h"
#include "AddrSafe.h"



ULONG GetNtosBase64bitAndDllBase(IN PDRIVER_OBJECT pDriverObject, OUT PVOID64 *pDllBase)
{
	PLDR_DATA_TABLE_ENTRYSS pFirstLdr = NULL, pShow = NULL;
	ULONG32 lCount = 0;
	/*
	WCHAR IsTargetNtoskrnlString[] = { 0x6e, 0x00, 0x74, 0x00, 0x6f, 0x00, 0x73, 0x00, 0x6b, 0x00, 0x72,\
	0x00, 0x6e, 0x00, 0x6c, 0x00, 0x2e, 0x00, 0x65, 0x00, 0x78, 0x00, 0x65 };*/
	PVOID64 pCurrentLdr = NULL;

	if (!_IsAddrSafe(pDriverObject) | !_IsAddrSafe(pDllBase))return NULL64;
	pShow = pCurrentLdr = pFirstLdr = (PLDR_DATA_TABLE_ENTRYSS)pDriverObject->DriverSection;


	do
	{
		if (!_IsAddrSafe(pCurrentLdr))return NULL;

		if (++lCount == 3 && *(PUCHAR)(pShow->BaseDllName.Buffer) == 0x6E)
		{
			*pDllBase = pShow->DllBase;
			return pShow->SizeOfImage;
		}
#if DDBBGG

		DbgPrint("GetNtosBase64bit SYS Name:%S\n", pShow->BaseDllName.Buffer);
		DbgPrint("GetNtosBase64bit SYS DLLBASE:%p\n", pShow->DllBase);
		DbgPrint("GetNtosBase64bit SYS SizeOfImage:%p\n", pShow->SizeOfImage);
		DbgPrint("\r\n");
#endif

		pCurrentLdr = (PVOID64)(*(PULONG64)pCurrentLdr);

		pShow = (PLDR_DATA_TABLE_ENTRYSS)pCurrentLdr;
	} while (pCurrentLdr != pFirstLdr);



	return NULL64;
}



BOOLEAN ViolentSerchProc	(
							IN  ULONG64 pCurrentIndexAndStartIndex,
							IN  UCHAR Code[],
							IN  UCHAR CodeIndex[],
							IN  ULONG SerchLimite,
							IN  ULONG CompleteNum,
							OUT  PVOID * pRet
							)
{
	ULONG64 ntosknlEndAddr = pCurrentIndexAndStartIndex + SerchLimite;


	PUCHAR i = 0;
	ULONG j = 0, CodeAndCodeIndexLength = CompleteNum -1; 

	for (i = pCurrentIndexAndStartIndex; i <= ntosknlEndAddr; i++)
	{
		if (!_IsAddrSafe((PVOID64)(i + CodeIndex[j])))break;

		if (*(i + CodeIndex[j]) == Code[j])
		{
			if (j == CodeAndCodeIndexLength)
			{
				*pRet = (PVOID)i;

				return TRUE;
			}
			j++;
			--i;
		}
		else
		{
			j = 0;
		}
	}




	return FALSE;
}