#pragma once

#ifndef OVERDOUBLEMC
#define OVERDOUBLEMC

#include "DriverEntry.h"

// 函数指针
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

// 双机调试函数符号
typedef struct _OverDoubleMcSymbol
{
	pKdpTrap KdpTrap; // 存储原来函数地址
	pKdpTrap uKdpTrap; // 存储新函数地址

	pKdpStub KdpStub;
	pKdpStub uKdpStub;

	pIoAllocateMdl IoAllocateMdl;
	pIoAllocateMdl uIoAllocateMdl;
}OverDoubleMcSymbol, *POverDoubleMcSymbol;
OverDoubleMcSymbol g_OverDoubleMcSymol;

// 启动过 Tp 双机调试
NTSTATUS StartOverDoubleMc(PDRIVER_OBJECT DriverObject);

// 1、首先解决 WinDbg 的不断弹出 The context is partially valid.Only x86 user - mode context is available.
VOID HookKdpTrap(PVOID szMyAddress, PVOID szTargetAddress);

// 2、防止安全组件加载失败
VOID DisableKdDebuggerEnabled();

// 3、TP 会清零全局 KdDebuggerEnabled, 这里做一个每隔一秒的定时器
VOID RepairKdDebuggerEnabledByTimer(PDRIVER_OBJECT DriverObject);

// 4、断链隐藏 kdcom，防止kdcom内存被清空导致和windbg通讯不了
VOID HideKdcomDriver(PDRIVER_OBJECT DriverObject);

// 5、Hook KdpStub
VOID HookKdpStub(PVOID szMyAddress, PVOID szTargetAddress);

// 6、处理 TP 蓝屏(KdEnteredDebugger 标志)
VOID HookIoAllocateMdl(PVOID szMyAddress, PVOID szTargetAddress);

// 7. 处理 INT 1 (KiDebugTrapOrFault)断点的 HOOK
VOID HookKiDebugTrapOrFault(PVOID szMyAddress, PVOID szTargetAddress);

#endif


