#include "AddrSafe.h"





void InitMemSafe()
{
#ifndef AMD64
	ULONG cr4reg;
	//determine if PAE is used
	cr4reg = (ULONG)__readcr4();
	if ((cr4reg & 0x20) == 0x20)
	{
		PTESize = 8; //pae
		PAGE_SIZE_LARGE = 0x200000;
		MAX_PDE_POS = 0xC0604000;
		MAX_PTE_POS = 0xC07FFFF8;
	}
	else
	{
		PTESize = 4;
		PAGE_SIZE_LARGE = 0x400000;
		MAX_PDE_POS = 0xC0301000;
		MAX_PTE_POS = 0xC03FFFFC;
	}
#else
	PTESize = 8; //pae
	PAGE_SIZE_LARGE = 0x200000;
	MAX_PTE_POS = 0xFFFFF6FFFFFFFFF8ULL;
	MAX_PDE_POS = 0xFFFFF6FB7FFFFFF8ULL;
#endif
}

BOOLEAN IsAddressSafe(UINT_PTR StartAddress)
{
#ifdef AMD64
	//cannonical check. Bits 48 to 63 must match bit 47
	UINT_PTR toppart = (StartAddress >> 47);
	if (toppart & 1)
	{
		//toppart must be 0x1ffff
		if (toppart != 0x1ffff)
			return FALSE;
	}
	else
	{
		//toppart must be 0
		if (toppart != 0)
			return FALSE;

	}
#endif
	//PDT+PTE judge
	{
#ifdef AMD64
		UINT_PTR kernelbase = 0x7fffffffffffffffULL;
		if (StartAddress<kernelbase)
		{
			return TRUE;
		}
		else
		{
			PHYSICAL_ADDRESS physical;
			physical.QuadPart = 0;
			physical = MmGetPhysicalAddress((PVOID)StartAddress);
			return (physical.QuadPart != 0);
		}
		return TRUE; //for now untill I ave figure out the win 4 paging scheme
#else
		ULONG kernelbase = 0x7ffe0000;
		UINT_PTR PTE, PDE;
		struct PTEStruct *x;
		if (StartAddress < kernelbase)
		{
			return TRUE;
		}
		PTE = (UINT_PTR)StartAddress;
		PTE = PTE / 0x1000 * PTESize + 0xc0000000;
		//now check if the address in PTE is valid by checking the page table directory at 0xc0300000 (same location as CR3 btw)
		PDE = PTE / 0x1000 * PTESize + 0xc0000000; //same formula
		x = (struct PTEStruct *)PDE;
		if ((x->P == 0) && (x->A2 == 0))
		{
			//Not present or paged, and since paging in this area isn't such a smart thing to do just skip it
			//perhaps this is only for the 4 mb pages, but those should never be paged out, so it should be 1
			//bah, I've got no idea what this is used for
			return FALSE;
		}
		if (x->PS == 1)
		{
			//This is a 4 MB page (no pte list)
			//so, (startaddress/0x400000*0x400000) till ((startaddress/0x400000*0x400000)+(0x400000-1) ) ) is specified by this page
		}
		else //if it's not a 4 MB page then check the PTE
		{
			//still here so the page table directory agreed that it is a usable page table entry
			x = (PVOID)PTE;
			if ((x->P == 0) && (x->A2 == 0))
				return FALSE; //see for explenation the part of the PDE
		}
		return TRUE;
#endif
	}
}

BOOLEAN _IsAddrSafe(IN PVOID TargetCheckPoint)
{
	if (!TargetCheckPoint)return FALSE;
	for (int i = 0; i < sizeof(PVOID); i++)
	{

		if (!IsAddressSafe((UINT_PTR)TargetCheckPoint + i))
		{
			if (!MmIsAddressValid((UINT_PTR)TargetCheckPoint + i))
			{
				return FALSE;

			}
		}
	}

	return TRUE;
}

BOOLEAN _IsAddrSafeSole(IN PVOID TargetCheckPoint)
{

	if (!TargetCheckPoint)return FALSE;

	if (!IsAddressSafe((UINT_PTR)TargetCheckPoint))
	{
		if (!MmIsAddressValid((UINT_PTR)TargetCheckPoint))
		{
			return FALSE;

		}
	}


	return TRUE;
}