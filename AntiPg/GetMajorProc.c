#include "GetMajorProc.h"
#include "AnalyzeOfPE.h"
#include "GetNtosBase.h"
#include "AddrSafe.h"

GD g_data = { 0 };


static const void* EtwpDebuggerData = NULL;// Test is delet




//��ȡӲ�����ַ�� EtwpDebuggerData ���������ǡ�?? ?? 2c 08 04 38 0c�� Ҳ����2c�ĵ�ַ
NTSTATUS EtwpDebuggerDataPoint
(
IN PDRIVER_OBJECT pDriverObject,
IN UCHAR Code[],
__in UCHAR CodeIndex[],
__in ULONG CompleteNum,
__out PVOID * pRet)
{
	
	NTSTATUS ntStatus = NTSTATUS_END_300;
	PVOID64 pDllBase = NULL;
	PVOID pStartR = NULL, pLimiteR = NULL;



	if (!_IsAddrSafe(pDriverObject))
	{
		if (!_IsAddrSafe(Code))
		{
			if (!_IsAddrSafe(CodeIndex))
			{
				if (!_IsAddrSafe(pRet))
				{
					return NTSTATUS_END_250;
				}
			}
		}
	}

	 GetNtosBase64bitAndDllBase(pDriverObject,&pDllBase);
	 if (!_IsAddrSafe(pDllBase))return NTSTATUS_END_251;
	 


	 ntStatus = GetStartAndEnd(pDllBase, &pStartR, &pLimiteR);

	 if (ntStatus < NTSTATUS_END_300)
	 {
#if DDBBGG
		 KdPrint(("EtwpDebuggerDataSiloPoint ntStatus <NTSTATUS_END_300\n");
#endif
		 return NTSTATUS_END_252;

	 }
	 else if (!_IsAddrSafe(pStartR) || !_IsAddrSafe(pLimiteR))return NTSTATUS_END_253;


	 return ViolentSerchProc(
		 pStartR,
		 Code,
		 CodeIndex,
		 (ULONG)pLimiteR,
		 CompleteNum,
		 pRet
		 );
}




BOOLEAN
GetGD 
(
IN  PVOID EtwpDebuggerDataPoint_pRet
)
{

	PVOID EtwpDebuggerData = EtwpDebuggerDataPoint_pRet;
	UINT_PTR EtwpDebuggerDataSilo = 0;



	PVOID CkclWmiLoggerContext = NULL;//Test is delet
	PVOID* EtwpDebuggerDataSilosss = NULL;
	if (!_IsAddrSafe(EtwpDebuggerDataPoint_pRet))return FALSE;


	
	// Test is delet
	// This is offset by 2 bytes due to where the signature starts.
	//
	EtwpDebuggerData = (PVOID)((uintptr_t)EtwpDebuggerData - 2);

	//
	// Get the silos of EtwpDebuggerData.
	//
	 EtwpDebuggerDataSilosss = *(PVOID**)((uintptr_t)EtwpDebuggerData + 0x10);

	//
	// Pull out the circular kernel context logger.
	//
	CkclWmiLoggerContext = EtwpDebuggerDataSilosss[2];




	/*
	g_data.g_EtwpDebuggerDataPoint_pRet = EtwpDebuggerDataPoint_pRet;

	g_data.g_pEtwpDebuggerData  = pEtwpDebuggerData = (PVOID)((PUCHAR)EtwpDebuggerDataPoint_pRet - 2) ;


	if (!_IsAddrSafe((PUCHAR)pEtwpDebuggerData + 0x10))return FALSE;
	g_data.g_EtwpDebuggerDataSilo = EtwpDebuggerDataSilo = *(PUINT_PTR)((PUCHAR)pEtwpDebuggerData + 0x10);

	if (!_IsAddrSafe(EtwpDebuggerDataSilo + 0x10))return FALSE;

	g_data.g_CkclWmiLoggerContext = *(PUINT_PTR)(EtwpDebuggerDataSilo + 0x10);*/


	return TRUE;
}



NTSTATUS FindTrulySyscallEntryPoint()
{
	//������ܳ���kisystemcall64shadow�������Ҫ���������

	UINT_PTR pSyscallEntry = (UINT_PTR)__readmsr(MSR_LSTAR);

	if (!_IsAddrSafe(pSyscallEntry))return NTSTATUS_END_250;

	     g_data.g_SystemCallEntryPage =  PAGE_ALIGN(pSyscallEntry);
		 g_data.g_SystemCallEntryPage -= PAGE_SIZE;
		 return NTSTATUS_END_300;
}





BOOLEAN SaveHookProcAddr(IN PVOID * pTargetProcAddr)
{
	if (!IsAddressSafe(pTargetProcAddr))return FALSE;
	*g_data.g_HookProc = pTargetProcAddr;
  return TRUE;
}


//��һ��������ҪHOOK��Ŀ�꺯�����ڶ���������溯���ļٺ���
NTSTATUS SyscallDispatch(__in PVOID * pHookTarget,__in PVOID * pAntiTarget)
{
	if (!_IsAddrSafe(pHookTarget) || !_IsAddrSafe(pAntiTarget))return  NTSTATUS_END_250;

	if (*g_data.g_SyscallTarget == pHookTarget)

		*g_data.g_SyscallTarget = pAntiTarget;

	return NTSTATUS_END_300;
}

UINT_PTR FakeGetCpuClock()
{
	if (ExGetPreviousMode() == KernelMode) 
		return __rdtsc();
	
	PVOID *StackBase = (PVOID*)__readgsqword(0x1A8);
	PVOID *StackFrame = (PVOID*)_AddressOfReturnAddress();
	PVOID *StackCurrent = NULL;
	PVOID CurrentPage = NULL;
	PVOID *SyscallTarget = NULL;
	NTSTATUS ntStatus = 0;


	

	
	//�ж�����ֻ�� Syscall ���òŻ�����ı�־����֮���ָ���Ƿ����� SyscallEntry ������Χ�ڣ��Դ���ȷ�����Ƿ���һ�� Syscall �����¼�
	for (StackCurrent = StackBase; StackCurrent > StackFrame; StackCurrent--)
	{
		// ���Syscall���б�־
		if (*(ULONG*)StackCurrent != (ULONG)0x501802 || *(USHORT*)(StackCurrent - 1) != (USHORT)0xF33) 
			continue;
		

		// ���ر���
		for (StackCurrent--; StackCurrent < StackBase; ++StackCurrent)
		{
			CurrentPage = PAGE_ALIGN(*StackCurrent);
			
			// ������2��ҳ�Ĵ�С�ж�һ���Ƿ���Syscall����
			if (CurrentPage < g_data.g_SystemCallEntryPage ||
				CurrentPage >= (PVOID)(g_data.g_SystemCallEntryPage + PAGE_SIZE * 2)){
				continue;
			}

			// �������������ȷ��ΪSyscall�¼���

			g_data.g_SyscallTarget = &StackCurrent[9];
			
			

			//�жϺ��޸��Լ��ĺ���
			ntStatus = SyscallDispatch(g_data.g_HookProc,&FakeNtOpenProcess);
			
		}
	}
	


	return __rdtsc();


}


NTSTATUS FakeNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId)
{
	//if (ClientId->UniqueProcess == (HANDLE)123) {
		KdPrint(("Target process is being opened.!!!!!!!!!!!!-_-_-_-_-____----___"));
		//return STATUS_ACCESS_DENIED;
	//}



	return NtOpenProcess( ProcessHandle,  DesiredAccess,  ObjectAttributes,  ClientId);
}


PVOID ReplaceGetCpuClock(PVOID TargetAddr)
{
	PVOID *pEtwpGetCycleCount = (PVOID*)(g_data.g_CkclWmiLoggerContext + 0x28);
	PVOID Result = *pEtwpGetCycleCount;
	*pEtwpGetCycleCount = TargetAddr;
	return Result;
}




////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


NTSTATUS MajorProcMain
(
	IN PDRIVER_OBJECT pDriverObject,
	IN UCHAR Code[],
	__in UCHAR CodeIndex[],
	__in ULONG CompleteNum,
	__out PVOID * pRet,
	__in PCWSTR pTargetStr
)
{
	PVOID64 pHookProc = NULL64;
	NTSTATUS ntStatus = 0;
	UINT_PTR rdtsc = 0;
	PVOID pReplaceGetCpuClock = NULL;

	

	//��ʼ���׶�
	ntStatus = EtwpDebuggerDataPoint
		(
		pDriverObject,
		Code,
		CodeIndex,
		CompleteNum,
		pRet);

	if (!_IsAddrSafe(pRet))return NTSTATUS_END_250;

	if (!GetGD(*pRet))return NTSTATUS_END_251;

	if (!_IsAddrSafe(pTargetStr))return NTSTATUS_END_252;

	pHookProc = Get_Proc_Address(pTargetStr);

	if (!_IsAddrSafe(pHookProc))return NTSTATUS_END_253;

	if (!SaveHookProcAddr(&pHookProc))return NTSTATUS_END_254;


	//�޸Ľ׶�

	//1.�޸�GetCpuClock
	pReplaceGetCpuClock = ReplaceGetCpuClock(FakeGetCpuClock);



	rdtsc = FakeGetCpuClock();
	

	



	return NTSTATUS_END_300;
}