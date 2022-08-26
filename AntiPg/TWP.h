#ifndef _START_TRACE_H_
#define _START_TRACE_H_

#include "a.h"



#define EtwpStartTrace     1
#define EtwpStopTrace      2
#define EtwpQueryTrace     3
#define EtwpUpdateTrace    4
#define EtwpFlushTrace     5


/*
pProperty->Wnode.BufferSize = PAGE_SIZE;
pProperty->Wnode.ClientContext = 3;
pProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
pProperty->Wnode.Guid = CkclSessionGuid;*/

typedef enum CKCL_TRACE_OPERATION
{
	CKCL_TRACE_START,
	CKCL_TRACE_END,
	CKCL_TRACE_SYSCALL,

}CKCL_TRACE_OPERATION;


typedef struct _CKCL_TRACE_PROPERTIES_SS {
	CHAR Wnode[48];
	//WNODE_HEADER Wnode;
	ULONG        BufferSize;
	ULONG        MinimumBuffers;
	ULONG        MaximumBuffers;
	ULONG        MaximumFileSize;
	ULONG        LogFileMode;
	ULONG        FlushTimer;
	ULONG        EnableFlags;
	LONG         AgeLimit;
	ULONG        NumberOfBuffers;
	ULONG        FreeBuffers;
	ULONG        EventsLost;
	ULONG        BuffersWritten;
	ULONG        LogBuffersLost;
	ULONG        RealTimeBuffersLost;
	HANDLE       LoggerThreadId;
	ULONG        LogFileNameOffset;
	ULONG        LoggerNameOffset;
	//自己添加的
	CHAR Padding[24];
	UNICODE_STRING InstanceName;
} CKCL_TRACE_PROPERTIES_SS, *PCKCL_TRACE_PROPERTIES_SS;

EXTERN_C
NTSYSCALLAPI
NTSTATUS
NTAPI
NtTraceControl(
_In_ ULONG FunctionCode,
_In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
_In_ ULONG InBufferLen,
_Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
_In_ ULONG OutBufferLen,
_Out_ PULONG ReturnLength
);



typedef NTSTATUS (*NTTRACECONTROL)
(_In_ ULONG FunctionCode,
 _In_reads_bytes_opt_(InBufferLen) PVOID InBuffer,
 _In_ ULONG InBufferLen,
 _Out_writes_bytes_opt_(OutBufferLen) PVOID OutBuffer,
 _In_ ULONG OutBufferLen,
 _Out_ PULONG ReturnLength
 );

extern NTTRACECONTROL pNtTraceControlFuction;

NTSTATUS StartCkclEventTrace();
NTSTATUS EventTraceControl(CKCL_TRACE_OPERATION Operation);
#endif