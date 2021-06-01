#pragma once

#ifndef OVERTOOLS
#define OVERTOOLS

#include "DriverEntry.h"
	
typedef struct _KernelMdouleInfo
{
	ULONG_PTR Base; // ��ַ
	ULONG_PTR Size; // ��С
}KernelMdouleInfo, *PKernelMdouleInfo;

// �ر� CR0 д����
VOID RemovWP();
// ���� Cr0 д����
VOID UndoWP();

// �ڴ��������ҵ�ַ
PVOID MmFindByCode(UCHAR * szCode, size_t szSize);

// ��ȡ�ں�ģ���ַ����С
NTSTATUS GetKernelMoudleBaseAndSize(PULONG_PTR szBase, PULONG_PTR szSize);

// ��ʼ��������
NTSTATUS InitOverTools(PDRIVER_OBJECT DriverObject);

#endif



