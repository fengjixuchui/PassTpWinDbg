#pragma once

#ifndef OVERDOUBLEMC
#define OVERDOUBLEMC

#include "DriverEntry.h"

// ����ָ��
typedef NTSTATUS(*pKdpTrap)(
	IN PKTRAP_FRAME 	TrapFrame,
	IN PKEXCEPTION_FRAME 	ExceptionFrame,
	IN PEXCEPTION_RECORD 	ExceptionRecord,
	IN PCONTEXT 	ContextRecord,
	IN KPROCESSOR_MODE 	PreviousMode,
	IN BOOLEAN 	SecondChanceException);

typedef NTSTATUS (*pKdpStub)(
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChanceException
);

typedef PMDL(*pIoAllocateMdl)(
	__drv_aliasesMem PVOID VirtualAddress,
	ULONG Length,
	BOOLEAN SecondaryBuffer,
	BOOLEAN  ChargeQuota,
	PIRP Irp);

// ˫�����Ժ�������
typedef struct _OverDoubleMcSymbol
{
	pKdpTrap KdpTrap; // �洢ԭ��������ַ
	pKdpTrap uKdpTrap; // �洢�º�����ַ

	pKdpStub KdpStub;
	pKdpStub uKdpStub;

	pIoAllocateMdl IoAllocateMdl;
	pIoAllocateMdl uIoAllocateMdl;
}OverDoubleMcSymbol, *POverDoubleMcSymbol;
OverDoubleMcSymbol g_OverDoubleMcSymol;

// ������ Tp ˫������
NTSTATUS StartOverDoubleMc(PDRIVER_OBJECT DriverObject);

// 1�����Ƚ�� WinDbg �Ĳ��ϵ��� The context is partially valid.Only x86 user - mode context is available.
VOID HookKdpTrap(PVOID szMyAddress, PVOID szTargetAddress);

// 2����ֹ��ȫ�������ʧ��
VOID DisableKdDebuggerEnabled();

// 3��TP ������ȫ�� KdDebuggerEnabled, ������һ��ÿ��һ��Ķ�ʱ��
VOID RepairKdDebuggerEnabledByTimer(PDRIVER_OBJECT DriverObject);

// 4���������� kdcom����ֹkdcom�ڴ汻��յ��º�windbgͨѶ����
VOID HideKdcomDriver(PDRIVER_OBJECT DriverObject);

// 5��Hook KdpStub
VOID HookKdpStub(PVOID szMyAddress, PVOID szTargetAddress);

// 6������ TP ����(KdEnteredDebugger ��־)
VOID HookIoAllocateMdl(PVOID szMyAddress, PVOID szTargetAddress);

// 7. ���� INT 1 (KiDebugTrapOrFault)�ϵ�� HOOK
VOID HookKiDebugTrapOrFault(PVOID szMyAddress, PVOID szTargetAddress);

#endif


