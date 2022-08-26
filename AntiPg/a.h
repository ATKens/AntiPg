#pragma once 
#include <ntifs.h>


#define NTSTATUS_END_250         0x18250
#define NTSTATUS_END_251         0x18251
#define NTSTATUS_END_252         0x18252
#define NTSTATUS_END_253         0x18253
#define NTSTATUS_END_254         0x18254


#define NTSTATUS_END_300         0x18300


#define NTSTATUS_WIN_700         0x18700
#define NTSTATUS_WIN_701         0x18701
#define NTSTATUS_WIN_702         0x18702
#define NTSTATUS_WIN_703         0x18703




#define TG(a)\
KdPrint(("%s(%d).%s:%s", __FILE__, __LINE__, __FUNCTION__, (x)))


#define TARGET_SERCH_CODE_COMPLETENUM 5  //\x2c\x08\x04\x38\x0c
#define HOOK_TARGET_FUNCTION_NAMEW "NtOpenProcess"


EXTERN_C AsmInt3();

PVOID64 Get_Proc_Address(IN PCWSTR FuncStr);


/*
NTSTATUS EtwpDebuggerDataPoint
(
IN PDRIVER_OBJECT pDriverObject,
IN UCHAR Code[],
__in UCHAR CodeIndex[],
__in ULONG SerchLimite,
__in ULONG CompleteNum,
__out PVOID * pRet);*/