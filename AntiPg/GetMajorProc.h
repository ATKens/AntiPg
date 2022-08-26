#pragma once 
#include "a.h"
#include <intrin.h>


#define MSR_LSTAR           0xC0000082
//0x440 bytes (sizeof)
typedef struct _WMI_LOGGER_CONTEXTSS
{
	ULONG LoggerId;                                                         //0x0
	ULONG BufferSize;                                                       //0x4
	ULONG MaximumEventSize;                                                 //0x8
	ULONG LoggerMode;                                                       //0xc
	LONG AcceptNewEvents;                                                   //0x10
	ULONG EventMarker[2];                                                   //0x14
	ULONG ErrorMarker;                                                      //0x1c
	ULONG SizeMask;                                                         //0x20
	LONGLONG(*GetCpuClock)();                                              //0x28
	struct _ETHREAD* LoggerThread;                                          //0x30
	LONG LoggerStatus;                                                      //0x38
	ULONG FailureReason;                                                    //0x3c
}WMI_LOGGER_CONTEXTSS, *PWMI_LOGGER_CONTEXTSS;

typedef struct _GD
{
  PVOID g_EtwpDebuggerDataPoint_pRet;
  PVOID  g_pEtwpDebuggerData;
  UINT_PTR  g_EtwpDebuggerDataSilo;
  UINT_PTR  g_CkclWmiLoggerContext;
  UINT_PTR g_SystemCallEntryPage;
  PVOID * g_HookProc;
  PVOID * g_SyscallTarget;
}GD,* PGD;






typedef NTSTATUS (*NTOPENPROCESS)(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);
extern NTOPENPROCESS pFunc_NtOpenProcess;



NTSTATUS EtwpDebuggerDataPoint
(
IN PDRIVER_OBJECT pDriverObject,
IN UCHAR Code[],
__in UCHAR CodeIndex[],
__in ULONG CompleteNum,
__out PVOID * pRet);


NTSTATUS EtwpDebuggerDataPoint
(
IN PDRIVER_OBJECT pDriverObject,
IN UCHAR Code[],
__in UCHAR CodeIndex[],
__in ULONG CompleteNum,
__out PVOID * pRet);


BOOLEAN
GetGD(
IN  PVOID EtwpDebuggerDataPoint_pRet);


NTSTATUS FindTrulySyscallEntryPoint();

BOOLEAN SaveHookProcAddr(IN PVOID * pTargetProcAddr);

NTSTATUS SyscallDispatch(__in PVOID* pHookTarget, __in PVOID* pAntiTarget);

UINT_PTR FakeGetCpuClock();

NTSTATUS FakeNtOpenProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PCLIENT_ID ClientId);

NTSTATUS MajorProcMain
(
IN PDRIVER_OBJECT pDriverObject,
IN UCHAR Code[],
__in UCHAR CodeIndex[],
__in ULONG CompleteNum,
__out PVOID * pRet,
__in PCWSTR pTargetStr
);

PVOID ReplaceGetCpuClock(PVOID TargetAddr);

extern GD g_data;