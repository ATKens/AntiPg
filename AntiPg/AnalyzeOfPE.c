#include "AnalyzeOfPE.h"
#include "AddrSafe.h"
#include "GetNtosBase.h"


//获取rdata和.data驱动两个模块之间的最小地址和两个模块之间的最大地址(little endian)
NTSTATUS GetStartAndEnd(IN PUCHAR pCurrent,OUT PVOID * pStartR,OUT PVOID * pLimiteR)
{
	//2e 72 64 61 74 61
	UCHAR uCode_rdata[] = {0x2e,0x72,0x64,0x61,0x74,0x61};
	UCHAR uCode_data[] = {0x2e,0x64,0x61,0x74,0x61};
	UCHAR uIndex_rdata[] = { 0, 1, 2, 3, 4, 5 };
	UCHAR uIndex_data[] = { 0, 1, 2, 3, 4};


	PUCHAR pSerchStart = NULL, p = NULL;
	PVOID pRet1 = NULL, pRet2 = NULL;
	

	if (!_IsAddrSafe((PVOID)pCurrent) && !_IsAddrSafe((PVOID)pStartR) \
		&& !_IsAddrSafe((PVOID)pLimiteR) && !_IsAddrSafe(*pStartR) && !_IsAddrSafe(*pLimiteR))return NTSTATUS_END_250;
	
	
	pSerchStart = pCurrent + 0x18 + 0x108 + sizeof(IMAGE_OPTIONAL_HEADER64SS);
    	
	ViolentSerchProc(pSerchStart, uCode_rdata, uIndex_rdata, 0x500, 6, &pRet1);

		if (!_IsAddrSafe(pRet1))return NTSTATUS_END_251;

		ViolentSerchProc(pSerchStart, uCode_data, uIndex_data, 0x500, 5, &pRet2);

		if (!_IsAddrSafe(pRet2))return NTSTATUS_END_251;


	*pStartR =  ((PIMAGE_SECTION_HEADER)pRet1)->VirtualAddress <((PIMAGE_SECTION_HEADER)pRet2)->VirtualAddress ? \
		pCurrent + ((PIMAGE_SECTION_HEADER)pRet1)->VirtualAddress :pCurrent + ((PIMAGE_SECTION_HEADER)pRet2)->VirtualAddress;

	/*
	*pLimiteR = ((PIMAGE_SECTION_HEADER)pRet1)->SizeOfRawData + ((PIMAGE_SECTION_HEADER)pRet1)->Misc.VirtualSize >\
		((PIMAGE_SECTION_HEADER)pRet2)->SizeOfRawData + ((PIMAGE_SECTION_HEADER)pRet2)->Misc.VirtualSize ?\
		((PIMAGE_SECTION_HEADER)pRet1)->SizeOfRawData >((PIMAGE_SECTION_HEADER)pRet1)->Misc.VirtualSize ?\
		 ((PIMAGE_SECTION_HEADER)pRet1)->SizeOfRawData:((PIMAGE_SECTION_HEADER)pRet1)->Misc.VirtualSize:\
		((PIMAGE_SECTION_HEADER)pRet2)->SizeOfRawData >((PIMAGE_SECTION_HEADER)pRet2)->Misc.VirtualSize ? \
		 ((PIMAGE_SECTION_HEADER)pRet2)->SizeOfRawData:((PIMAGE_SECTION_HEADER)pRet2)->Misc.VirtualSize;
		 */
	
	*pLimiteR = 0x100000;
	return NTSTATUS_END_300;
}