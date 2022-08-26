

#define DEVICE_NAME L"\\device\\AntiPg"
#define LINK_NAME L"\\??\\AntiPg"
#define IOCTRL_BASE 0x800       
#define MYIOCTRL_CODE(i) \
    CTL_CODE(FILE_DEVICE_UNKNOWN, IOCTRL_BASE + i,     METHOD_BUFFERED,FILE_ANY_ACCESS)
#define CTL_HELLO MYIOCTRL_CODE(0)
#define CTL_PRINT MYIOCTRL_CODE(1)
#define CTL_BYE MYIOCTRL_CODE(2)


#include "TWP.h"
#define INITGUID  // Include this #define to use SystemTraceControlGuid in Evntrace.h.

#include <stdio.h>
#include <conio.h>
#include <strsafe.h>
#include <wmistr.h>
#include <evntrace.h>
#include <Evntrace.h>

#define LOGFILE_PATH L"<FULLPATHTOTHELOGFILE.etl>"

//#include "a.h"
#include "GetNtosBase.h"
#include "GetMajorProc.h"
#include "AddrSafe.h"

NTTRACECONTROL pNtTraceControlFuction = NULL;



VOID DriverUnload(PDRIVER_OBJECT pDriverObject);
NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp);
NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp);




/**/

NTSTATUS StartCkclEventTrace()
{
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	
	pNtTraceControlFuction = (NTTRACECONTROL)Get_Proc_Address(L"NtTraceControl");

	if (!_IsAddrSafe((PVOID)pNtTraceControlFuction))return NTSTATUS_END_250;

	// 测试 CKCL 会话是否已经启动
	Status = EventTraceControl(CKCL_TRACE_SYSCALL);
	if (!NT_SUCCESS(Status)) {
		// 没有启动 尝试打开
		Status = EventTraceControl(CKCL_TRACE_START);
		if (!NT_SUCCESS(Status)) {
			//LOG_ERROR("Start CKCL failed.", Status);
			return Status;
		}

		Status = EventTraceControl(CKCL_TRACE_SYSCALL);
		if (!NT_SUCCESS(Status)) {
			//LOG_ERROR("Start CKCL failed.", Status);
			return Status;
		}
	}

	//LOG_INFO("CKCL is running", 0);

	return Status;
}

NTSTATUS EventTraceControl(CKCL_TRACE_OPERATION Operation)
{
	NTSTATUS Status = NTSTATUS_END_300;
	ULONG ReturnLength = 0;
	// 54dea73a-ed1f-42a4-af713e63d056f174
	//const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };//??????

	const UCHAR CkclSessionGuid[0x10] = {0x3A,0xA7,0xDE,0x54,0x1F,0xED,0xA4,0x42,0xAF,0x71,0x3E,0x63,0xD0,0x56,0xF1,0x74};


	//const GUID CkclSessionGuid = { 0x54dea73a, 0xed1f, 0x42a4, { 0xaf, 0x71, 0x3e, 0x63, 0xd0, 0x56, 0xf1, 0x74 } };
	PCKCL_TRACE_PROPERTIES_SS pProperty = (PCKCL_TRACE_PROPERTIES_SS)ExAllocatePoolWithTag(NonPagedPool, PAGE_SIZE, "ABCD");

	if (pProperty == NULL) {
		KeBugCheckEx(HAL_MEMORY_ALLOCATION, PAGE_SIZE, 0, NULL, 0);
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlZeroMemory(pProperty, PAGE_SIZE);

	UNICODE_STRING InstanceName;
	RtlInitUnicodeString(&InstanceName, L"Circular Kernel Context Logger");
	

	/*
	kd> dt _WNODE_HEADER
	Wdf01000!_WNODE_HEADER
	+0x000 BufferSize       : Uint4B
	+0x004 ProviderId       : Uint4B
	+0x008 HistoricalContext : Uint8B
	+0x008 Version          : Uint4B
	+0x00c Linkage          : Uint4B
	+0x010 CountLost        : Uint4B
	+0x010 KernelHandle     : Ptr64 Void
	+0x010 TimeStamp        : _LARGE_INTEGER
	+0x018 Guid             : _GUID
	+0x028 ClientContext    : Uint4B
	+0x02c Flags            : Uint4B*/

	*(PULONG)pProperty->Wnode = PAGE_SIZE;
	*(PULONG)(pProperty->Wnode + 0x28) = 3;
	*(PULONG)(pProperty->Wnode + 0x2c) = WNODE_FLAG_TRACED_GUID;
	*(PULONG)(pProperty->Wnode + 0x18) = CkclSessionGuid;


	/*
	pProperty->Wnode.BufferSize = PAGE_SIZE;
	pProperty->Wnode.ClientContext = 3;
	pProperty->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
	pProperty->Wnode.Guid = CkclSessionGuid;*/

	pProperty->BufferSize = sizeof(ULONG);
	pProperty->LogFileMode = EVENT_TRACE_BUFFERING_MODE;
	pProperty->MinimumBuffers = pProperty->MaximumBuffers = 2;
	pProperty->InstanceName = InstanceName;

	switch (Operation)
	{
	case CKCL_TRACE_START:
#if DBG
		AsmInt3();
#endif
		Status = pNtTraceControlFuction(EtwpStartTrace, pProperty, PAGE_SIZE, pProperty, PAGE_SIZE, &ReturnLength);
		break;
	case CKCL_TRACE_END:
#if DBG
		AsmInt3();
#endif
		Status = pNtTraceControlFuction(EtwpStopTrace, pProperty, PAGE_SIZE, pProperty, PAGE_SIZE, &ReturnLength);
		break;
	case CKCL_TRACE_SYSCALL:
		// 这里添加更多标志可以捕获更多事件
#if DBG
		AsmInt3();
#endif
		pProperty->EnableFlags = EVENT_TRACE_FLAG_SYSTEMCALL;
		Status = pNtTraceControlFuction(EtwpUpdateTrace, pProperty, PAGE_SIZE, pProperty, PAGE_SIZE, &ReturnLength);



		break;
	default:
		Status = STATUS_UNSUCCESSFUL;
		break;
	}

	ExFreePool(pProperty);
	return Status;
}










NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING RegistryPath)
{

	UNICODE_STRING uDeviceName = { 0 };      //初始化设备名字
	UNICODE_STRING uLinkName = { 0 };       //符号连接
	NTSTATUS  ntStatus = 0;
	PDEVICE_OBJECT pDeviceObject = NULL;  //设备对象指针
	ULONG i = 0;

	///////////////////////////////////////////////////
#if DBG
	AsmInt3();
#endif
	//UCHAR Code[] = "\x2c\x08\x04\x38\x0c";
	UCHAR Code[] = { 0x2c, 0x08, 0x04, 0x38, 0x0c };
	UCHAR CodeIndex[] = { 0, 1, 2, 3, 4 };
	PVOID pRet = NULL;


	DbgPrint("Driver load begin\n");

	RtlInitUnicodeString(&uDeviceName, DEVICE_NAME);

	RtlInitUnicodeString(&uLinkName, LINK_NAME);

	ntStatus = IoCreateDevice(pDriverObject, 0, &uDeviceName, FILE_DEVICE_UNKNOWN, 0, FALSE, &pDeviceObject);



	if (!NT_SUCCESS(ntStatus))
	{
		DbgPrint("IoCreateDevice failed(Device Create Error Printf Error Number):%x\n", ntStatus);
		return ntStatus;
	}


	pDeviceObject->Flags |= DO_BUFFERED_IO;


	ntStatus = IoCreateSymbolicLink(&uLinkName, &uDeviceName);
	if (!NT_SUCCESS(ntStatus)) {

		IoDeleteDevice(pDeviceObject);
		DbgPrint("IoCreateSymbolicLink failed(createSymbolicErrorDeleteThis):%x\n", ntStatus);
		return ntStatus;
	}



	for (i = 0; i < IRP_MJ_MAXIMUM_FUNCTION + 1; i++)
	{
		pDriverObject->MajorFunction[i] = DispatchCommon;
	}



	pDriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctrl;

	pDriverObject->DriverUnload = DriverUnload;
	DbgPrint("Driver load ok\n");


	

	

	



	 StartCkclEventTrace();




	  MajorProcMain
		 (
		  pDriverObject,
		  Code,
		  CodeIndex,
		  TARGET_SERCH_CODE_COMPLETENUM,
		  &pRet,
		  HOOK_TARGET_FUNCTION_NAMEW
		 );







	return STATUS_SUCCESS;
}

NTSTATUS DispatchCommon(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;

	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;

}




NTSTATUS DispatchIoctrl(PDEVICE_OBJECT pObject, PIRP pIrp)
{
	ULONG uControlCode = 0;
	PVOID pInputBuff = NULL;
	PVOID pOutputBuffer = NULL;
	ULONG uInputLength = 0;
	ULONG uOutputLength = 0;
	PIO_STACK_LOCATION pStack = NULL;

	pInputBuff = pOutputBuffer = pIrp->AssociatedIrp.SystemBuffer;
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	uInputLength = pStack->Parameters.DeviceIoControl.InputBufferLength;
	uOutputLength = pStack->Parameters.DeviceIoControl.OutputBufferLength;
	uControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;

	switch (uControlCode)
	{
	case CTL_HELLO:
		DbgPrint("Hello IoControl\n");
		break;
	case CTL_PRINT:
		DbgPrint("%ws\n", pInputBuff);
		break;
	case CTL_BYE:
		DbgPrint("Goodbye IoControl\n");
		break;
	default:
		DbgPrint("Unknown IoControl\n");
	}

	pIrp->IoStatus.Status = STATUS_SUCCESS;
	pIrp->IoStatus.Information = 0;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

VOID DriverUnload(PDRIVER_OBJECT pDriverObject)
{
	UNICODE_STRING          deviceLinkUnicodeString;




	DbgPrint("OnUnload\n");

	RtlInitUnicodeString(&deviceLinkUnicodeString, LINK_NAME);
	IoDeleteSymbolicLink(&deviceLinkUnicodeString);
	IoDeleteDevice(pDriverObject->DeviceObject);

	return STATUS_SUCCESS;

}





