#include "Over_Tools.h"
#include <intrin.h>

KIRQL g_irQl; // 储存 IRQL
PDRIVER_OBJECT g_Over_Tools_DriverObject;
KernelMdouleInfo g_Over_Tools_KernelInfo;

// 关闭写保护
VOID RemovWP()
{
	// (PASSIVE_LEVEL)提升 IRQL 等级为DISPATCH_LEVEL，并返回旧的 IRQL
	g_irQl = KeRaiseIrqlToDpcLevel();
	// 内联函数：读取Cr0寄存器的值, 相当于: mov eax,  cr0;
	ULONG_PTR cr0 = __readcr0();
	// 将第16位（WP位）清0，消除写保护
	cr0 &= ~0x10000; // ~ 按位取反
	__writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax	
	_disable(); // 清除中断标记, 相当于 cli 指令，修改 IF标志位
}

// 开启写保护
VOID UndoWP()
{
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000; // WP复原为1
	_enable();
	__writecr0(cr0); // 将cr0变量数据重新写入Cr0寄存器中，相当于: mov cr0, eax
	// 恢复IRQL等级
	KeLowerIrql(g_irQl);
}

// 获取内核模块基址、大小
NTSTATUS GetKernelMoudleBaseAndSize(PULONG_PTR szBase, PULONG_PTR szSize)
{
	NTSTATUS dwStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING dwKernelMoudleName;
	RtlInitUnicodeString(&dwKernelMoudleName, L"ntoskrnl.exe");

	// 获取驱动链表
	PLDR_DATA_TABLE_ENTRY dwEentry = (PLDR_DATA_TABLE_ENTRY)(g_Over_Tools_DriverObject->DriverSection);
	PLIST_ENTRY  dwFirstentry = NULL;
	PLIST_ENTRY  dwpCurrententry = NULL;
	PLDR_DATA_TABLE_ENTRY pCurrentModule = NULL;

	if (dwEentry)
	{
		dwFirstentry = dwEentry->InLoadOrderLinks.Flink;
		dwpCurrententry = dwFirstentry->Flink;

		while (dwFirstentry != dwpCurrententry)
		{
			//获取LDR_DATA_TABLE_ENTRY结构
			pCurrentModule = CONTAINING_RECORD(dwpCurrententry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

			if (pCurrentModule->BaseDllName.Buffer != 0)
			{
				if (RtlCompareUnicodeString(&dwKernelMoudleName, &(pCurrentModule->BaseDllName), FALSE) == 0)
				{
					*szBase = (__int64)pCurrentModule->DllBase;
					*szSize = (__int64)pCurrentModule->SizeOfImage;

					dwStatus = STATUS_SUCCESS;					
					return dwStatus;
				}
			}

			// 下一个
			dwpCurrententry = dwpCurrententry->Flink;
		}
	}	

	return dwStatus;
}

// 内存特征查找地址
// szCode: 特征码
// szSize: 特征码大小
PVOID MmFindByCode(UCHAR * szCode, size_t szSize)
{
	if (szCode && szSize)
	{
		PCHAR dwKernelBase = (PCHAR)g_Over_Tools_KernelInfo.Base;
		BOOLEAN dwSuccessFlag = FALSE;

		for (unsigned __int64 i = 0; i < g_Over_Tools_KernelInfo.Size; i++)
		{
			// 判断内核地址是否可读
			if (!MmIsAddressValid(&dwKernelBase[i]))
			{
				continue; // 不可读, 开始下一轮
			}

			for (unsigned __int64 j = 0x0; j < szSize; j++)
			{
				// 判断内核地址是否可读
				if (!MmIsAddressValid(&dwKernelBase[i + j]))
				{
					continue; // 不可读, 开始下一轮
				}

				// 支持模糊搜索
				if (szCode[j] == '*')
				{
					// 继续循环
					continue;
				}

				if (dwKernelBase[i + j] != szCode[j])
				{
					// 有一个内存比较不相等，跳出当前循环
					break;
				}
				
				if (j + 1 == szSize)
				{
					// 返回地址
					return (PVOID)(&dwKernelBase[i]);
				}
			}
		}
	}

	return NULL;
}

// 初始化工具类
NTSTATUS InitOverTools(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS dwStatus = STATUS_SUCCESS;
	g_Over_Tools_DriverObject = DriverObject;

	// 获取内核模块信息
	dwStatus = GetKernelMoudleBaseAndSize(&g_Over_Tools_KernelInfo.Base, &g_Over_Tools_KernelInfo.Size);
	if (!NT_SUCCESS(dwStatus))
	{
		KdPrint(("GetKernelMoudleBaseAndSize Error: [%X]", dwStatus));
		return dwStatus;
	}

	return dwStatus;
}

