#include "Over_Tools.h"
#include <intrin.h>

KIRQL g_irQl; // ���� IRQL
PDRIVER_OBJECT g_Over_Tools_DriverObject;
KernelMdouleInfo g_Over_Tools_KernelInfo;

// �ر�д����
VOID RemovWP()
{
	// (PASSIVE_LEVEL)���� IRQL �ȼ�ΪDISPATCH_LEVEL�������ؾɵ� IRQL
	g_irQl = KeRaiseIrqlToDpcLevel();
	// ������������ȡCr0�Ĵ�����ֵ, �൱��: mov eax,  cr0;
	ULONG_PTR cr0 = __readcr0();
	// ����16λ��WPλ����0������д����
	cr0 &= ~0x10000; // ~ ��λȡ��
	__writecr0(cr0); // ��cr0������������д��Cr0�Ĵ����У��൱��: mov cr0, eax	
	_disable(); // ����жϱ��, �൱�� cli ָ��޸� IF��־λ
}

// ����д����
VOID UndoWP()
{
	ULONG_PTR cr0 = __readcr0();
	cr0 |= 0x10000; // WP��ԭΪ1
	_enable();
	__writecr0(cr0); // ��cr0������������д��Cr0�Ĵ����У��൱��: mov cr0, eax
	// �ָ�IRQL�ȼ�
	KeLowerIrql(g_irQl);
}

// ��ȡ�ں�ģ���ַ����С
NTSTATUS GetKernelMoudleBaseAndSize(PULONG_PTR szBase, PULONG_PTR szSize)
{
	NTSTATUS dwStatus = STATUS_UNSUCCESSFUL;
	UNICODE_STRING dwKernelMoudleName;
	RtlInitUnicodeString(&dwKernelMoudleName, L"ntoskrnl.exe");

	// ��ȡ��������
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
			//��ȡLDR_DATA_TABLE_ENTRY�ṹ
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

			// ��һ��
			dwpCurrententry = dwpCurrententry->Flink;
		}
	}	

	return dwStatus;
}

// �ڴ��������ҵ�ַ
// szCode: ������
// szSize: �������С
PVOID MmFindByCode(UCHAR * szCode, size_t szSize)
{
	if (szCode && szSize)
	{
		PCHAR dwKernelBase = (PCHAR)g_Over_Tools_KernelInfo.Base;
		BOOLEAN dwSuccessFlag = FALSE;

		for (unsigned __int64 i = 0; i < g_Over_Tools_KernelInfo.Size; i++)
		{
			// �ж��ں˵�ַ�Ƿ�ɶ�
			if (!MmIsAddressValid(&dwKernelBase[i]))
			{
				continue; // ���ɶ�, ��ʼ��һ��
			}

			for (unsigned __int64 j = 0x0; j < szSize; j++)
			{
				// �ж��ں˵�ַ�Ƿ�ɶ�
				if (!MmIsAddressValid(&dwKernelBase[i + j]))
				{
					continue; // ���ɶ�, ��ʼ��һ��
				}

				// ֧��ģ������
				if (szCode[j] == '*')
				{
					// ����ѭ��
					continue;
				}

				if (dwKernelBase[i + j] != szCode[j])
				{
					// ��һ���ڴ�Ƚϲ���ȣ�������ǰѭ��
					break;
				}
				
				if (j + 1 == szSize)
				{
					// ���ص�ַ
					return (PVOID)(&dwKernelBase[i]);
				}
			}
		}
	}

	return NULL;
}

// ��ʼ��������
NTSTATUS InitOverTools(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS dwStatus = STATUS_SUCCESS;
	g_Over_Tools_DriverObject = DriverObject;

	// ��ȡ�ں�ģ����Ϣ
	dwStatus = GetKernelMoudleBaseAndSize(&g_Over_Tools_KernelInfo.Base, &g_Over_Tools_KernelInfo.Size);
	if (!NT_SUCCESS(dwStatus))
	{
		KdPrint(("GetKernelMoudleBaseAndSize Error: [%X]", dwStatus));
		return dwStatus;
	}

	return dwStatus;
}

