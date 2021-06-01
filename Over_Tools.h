#pragma once

#ifndef OVERTOOLS
#define OVERTOOLS

#include "DriverEntry.h"
	
typedef struct _KernelMdouleInfo
{
	ULONG_PTR Base; // 基址
	ULONG_PTR Size; // 大小
}KernelMdouleInfo, *PKernelMdouleInfo;

// 关闭 CR0 写保护
VOID RemovWP();
// 开启 Cr0 写保护
VOID UndoWP();

// 内存特征查找地址
PVOID MmFindByCode(UCHAR * szCode, size_t szSize);

// 获取内核模块基址、大小
NTSTATUS GetKernelMoudleBaseAndSize(PULONG_PTR szBase, PULONG_PTR szSize);

// 初始化工具类
NTSTATUS InitOverTools(PDRIVER_OBJECT DriverObject);

#endif



