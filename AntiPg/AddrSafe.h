#pragma once
#include "a.h"
int PTESize;
UINT_PTR PAGE_SIZE_LARGE;
UINT_PTR MAX_PDE_POS;
UINT_PTR MAX_PTE_POS;


struct PTEStruct
{
	unsigned P : 1; // present (1 = present)
	unsigned RW : 1; // read/write
	unsigned US : 1; // user/supervisor
	unsigned PWT : 1; // page-level write-through
	unsigned PCD : 1; // page-level cache disabled
	unsigned A : 1; // accessed
	unsigned Reserved : 1; // dirty
	unsigned PS : 1; // page size (0 = 4-KB page)
	unsigned G : 1; // global page
	unsigned A1 : 1; // available 1 aka copy-on-write
	unsigned A2 : 1; // available 2/ is 1 when paged to disk
	unsigned A3 : 1; // available 3
	unsigned PFN : 20; // page-frame number
};

void InitMemSafe();

BOOLEAN IsAddressSafe(UINT_PTR StartAddress);
BOOLEAN _IsAddrSafe(IN PVOID TargetCheckPoint);
BOOLEAN _IsAddrSafeSole(IN PVOID TargetCheckPoint);