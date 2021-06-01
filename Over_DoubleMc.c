#include "Over_DoubleMc.h"
#include "Over_Tools.h"

// ��������
PVOID pKdEnteredDebugger;
PULONG32 pKdDebuggerEnabled;

// IOʱ�ӻص�
KTIMER g_Over_DoubleMc_IOTimer;
LARGE_INTEGER g_Over_DoubleMc_IOTimeout;

// �豸����
PDEVICE_OBJECT g_Over_DoubleMc_DeviceObject;

// ��ʼ�� OverDoubleMc ����
VOID InitOverDoubleMcSymbol()
{
	/*
	nt!KdpTrap:
		fffff800`0434d010 48895c2408      mov     qword ptr [rsp+8],rbx
		fffff800`0434d015 57              push    rdi
		fffff800`0434d016 4883ec40        sub     rsp,40h
		fffff800`0434d01a 41813803000080  cmp     dword ptr [r8],80000003h
		fffff800`0434d021 498bd9          mov     rbx,r9
		fffff800`0434d024 7426            je      nt!KdpTrap+0x3c (fffff800`0434d04c)
		fffff800`0434d026 8a442478        mov     al,byte ptr [rsp+78h]
		fffff800`0434d02a 88442428        mov     byte ptr [rsp+28h],al
	*/

	// KdpTrap
	UCHAR dwKdpTrapCode[] = "\x48\x89\x5c\x24\x08\x57\x48\x83\xec\x40\x41\x81\x38\x03\x00\x00\x80";
	size_t dwKdpTrapSize = 0x11;
	g_OverDoubleMcSymol.KdpTrap = (pKdpTrap)MmFindByCode(dwKdpTrapCode, dwKdpTrapSize);

	KdPrint(("KdpTrap: [0x%p]", g_OverDoubleMcSymol.KdpTrap));

	/*
	nt!KdpStub:
		fffff800`03f91310 48895c2408      mov     qword ptr [rsp+8],rbx
		fffff800`03f91315 48896c2410      mov     qword ptr [rsp+10h],rbp
		fffff800`03f9131a 4889742418      mov     qword ptr [rsp+18h],rsi
		fffff800`03f9131f 57              push    rdi
		fffff800`03f91320 4883ec30        sub     rsp,30h
		fffff800`03f91324 41813803000080  cmp     dword ptr [r8],80000003h
		fffff800`03f9132b 498bd9          mov     rbx,r9
		fffff800`03f9132e 498bf8          mov     rdi,r8
	*/

	// KdpStub
	UCHAR dwKdpStubCode[] = "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x48\x83\xec\x30\x41\x81\x38\x03\x00\x00\x80";
	size_t dwKdpStubSize = 0x14 + 0x7;
	g_OverDoubleMcSymol.KdpStub = (pKdpStub)MmFindByCode(dwKdpStubCode, dwKdpStubSize);

	KdPrint(("KdpStub: [0x%p]", g_OverDoubleMcSymol.KdpStub));
	/*
	nt!IoAllocateMdl:
		fffff800`03ee5640 48895c2420      mov     qword ptr [rsp+20h],rbx
		fffff800`03ee5645 4488442418      mov     byte ptr [rsp+18h],r8b
		fffff800`03ee564a 55              push    rbp
		fffff800`03ee564b 56              push    rsi
		fffff800`03ee564c 4155            push    r13
		fffff800`03ee564e 4156            push    r14
		fffff800`03ee5650 4157            push    r15
		fffff800`03ee5652 4883ec20        sub     rsp,20h
	*/

	g_OverDoubleMcSymol.IoAllocateMdl = IoAllocateMdl; // nt!IoAllocateMdl

	// ��������
	pKdDebuggerEnabled = (PULONG32)KdDebuggerEnabled;

	UNICODE_STRING dwName = RTL_CONSTANT_STRING(L"KdEnteredDebugger");
	pKdEnteredDebugger = MmGetSystemRoutineAddress(&dwName);

	KdPrint(("KdDebuggerEnabled: [0x%p]", pKdDebuggerEnabled));
	KdPrint(("KdEnteredDebugger: [0x%p]", pKdEnteredDebugger));
}

// Hook KdpTrap ����ԭ��
NTSTATUS MyKdpTrap(
    IN PKTRAP_FRAME TrapFrame,
    IN PKEXCEPTION_FRAME ExceptionFrame,
    IN PEXCEPTION_RECORD ExceptionRecord,
    IN PCONTEXT ContextRecord,
    IN KPROCESSOR_MODE PreviousMode,
    IN BOOLEAN SecondChanceException
)
{
	PEPROCESS dwCurrentProcess = PsGetCurrentProcess();
	if (_stricmp((char *)PsGetProcessImageFileName(dwCurrentProcess), "TASLogin.exe") == 0) {
		// ����� TP ����
		KdPrint(("TP ����!\r\n"));

		return STATUS_SUCCESS;
	}

	return g_OverDoubleMcSymol.uKdpTrap(TrapFrame, ExceptionFrame, ExceptionRecord,
		ContextRecord, PreviousMode, SecondChanceException);
}

// IO ʱ�ӻص�
VOID IoTimerRoutine(
	PDEVICE_OBJECT DeviceObject,
	PVOID Context
)
{
	// Modify KdDebuggerEnabled
	RemovWP(); // �ر�д����
	
	*pKdDebuggerEnabled = 0x1;

	UndoWP();  // ��ԭд����
}

// Hook KdpStub ����ԭ��
NTSTATUS MyKdpStub(
	IN PKTRAP_FRAME TrapFrame,
	IN PKEXCEPTION_FRAME ExceptionFrame,
	IN PEXCEPTION_RECORD ExceptionRecord,
	IN PCONTEXT ContextRecord,
	IN KPROCESSOR_MODE PreviousMode,
	IN BOOLEAN SecondChanceException
	)
{
	PEPROCESS dwCurrentProcess = PsGetCurrentProcess();
	if (_stricmp((char *)PsGetProcessImageFileName(dwCurrentProcess), "TASLogin.exe") == 0) {
		// ����� TP ����
		KdPrint(("TP ����!\r\n"));

		return STATUS_SUCCESS;
	}

	return g_OverDoubleMcSymol.uKdpStub(TrapFrame, ExceptionFrame, ExceptionRecord,
		ContextRecord, PreviousMode, SecondChanceException);
}

// Hook IoAllocateMdl ����ԭ��
PMDL MyIoAllocateMdl(
	__drv_aliasesMem PVOID VirtualAddress,
	ULONG Length,
	BOOLEAN SecondaryBuffer,
	BOOLEAN  ChargeQuota,
	PIRP Irp)
{
	if (VirtualAddress == pKdEnteredDebugger) {
		//DbgPrint("[KdEnteredDebugger] address: %p\n", KdEnteredDebugger);
		VirtualAddress = (PUCHAR)pKdEnteredDebugger + 0x30;  //�ݰ��й۲죬+0x30 ��λ�ú�Ϊ0
	}

	return g_OverDoubleMcSymol.uIoAllocateMdl(VirtualAddress, Length, SecondaryBuffer, ChargeQuota, Irp);
}

// 1�����Ƚ�� WinDbg �Ĳ��ϵ��� The context is partially valid.Only x86 user - mode context is available.
// Hook KdpTrap ����
VOID HookKdpTrap(PVOID szMyAddress, PVOID szTargetAddress)
{
	ULONG_PTR dwMyFunAddr = (ULONG_PTR)szMyAddress;
	ULONG_PTR dwComebackAddress = (ULONG_PTR)g_OverDoubleMcSymol.KdpTrap + 0x11; // �������ĵ�ַ

	// KdpTrap ԭʼ Code + Jmp fffff800`0434d021
	UCHAR KdpTrapShellCode[] = {
		0x48, 0x89, 0x5c, 0x24, 0x08,  // mov qword ptr [rsp+8],rbx
		0x57,						   // push    rdi	
		0x48, 0x83, 0xec, 0x40,        // sub     rsp,40h
		0x41, 0x81, 0x38, 0x03, 0x00, 0x00, 0x80, // cmp dword ptr [r8],80000003h
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, 0xFFFFFFFF
		0xFF, 0xE0					   // jmp rax
	};
	// �滻��ת��ַ
	RtlCopyMemory(KdpTrapShellCode + 19, &(dwComebackAddress), 8);

	// ����ִ�� KdpTrapShellCode ����Ŀռ�
	ULONG_PTR dwSize = sizeof(KdpTrapShellCode);
	g_OverDoubleMcSymol.uKdpTrap = (pKdpTrap)ExAllocatePool(NonPagedPool, dwSize);
	RtlCopyMemory(g_OverDoubleMcSymol.uKdpTrap, KdpTrapShellCode, dwSize);

	// ���� JmpCode
	UCHAR JmpCode[] = {
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, 0xFFFFFFFF
		0xFF, 0xE0 // jmp rax
	};
	// �滻��ת��ַ
	RtlCopyMemory(JmpCode + 2, &dwMyFunAddr, 8);
	// Modify KdpTrap
	RemovWP(); // �ر�д����
	RtlCopyMemory(szTargetAddress, JmpCode, 12);
	UndoWP();  // ��ԭд����
}

// 2����ֹ��ȫ�������ʧ��
VOID DisableKdDebuggerEnabled()
{
	SharedUserData->KdDebuggerEnabled = FALSE;
}

// 3��TP ������ȫ�� KdDebuggerEnabled, ������һ��ÿ��һ��Ķ�ʱ��
VOID RepairKdDebuggerEnabledByTimer(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS dwStatus = STATUS_SUCCESS;

	dwStatus = IoCreateDevice(DriverObject, 0, NULL, FILE_DEVICE_UNKNOWN,
		FILE_AUTOGENERATED_DEVICE_NAME, // �Զ�������������
		FALSE, &g_Over_DoubleMc_DeviceObject
	);
	if (!NT_SUCCESS(dwStatus))
	{
		DbgPrint("�豸����ʧ��,������%d\n", dwStatus);
		return ;
	}

	// ��ʼ�����ö����IO��ʱ��
	// ϵͳÿ��1����Զ�����һ�� IoTimerRoutine ����
	IoInitializeTimer(g_Over_DoubleMc_DeviceObject, IoTimerRoutine, NULL);
	// �����豸�����IO��ʱ��
	IoStartTimer(g_Over_DoubleMc_DeviceObject);	
}

// 4���������� kdcom����ֹkdcom�ڴ汻��յ��º�windbgͨѶ����
VOID HideKdcomDriver(PDRIVER_OBJECT DriverObject)
{
	// ��ʼ��Ҫ����������������
	UNICODE_STRING dwHideDriverName;
	RtlInitUnicodeString(&dwHideDriverName, L"kdcom.dll");

	// ��ȡ��������
	//PKLDR_DATA_TABLE_ENTRY dwEentry = (PKLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	//PLIST_ENTRY dwFirstentry = NULL;
	//PLIST_ENTRY dwCurrentListEntry = NULL;
	//PKLDR_DATA_TABLE_ENTRY pCurrentModule = NULL;

	//if (dwEentry)
	//{
	//	dwFirstentry = &dwEentry->InLoadOrderLinks;
	//	dwCurrentListEntry = dwFirstentry;

	//	while (dwFirstentry->Flink != dwCurrentListEntry)
	//	{
	//		//��ȡLDR_DATA_TABLE_ENTRY�ṹ
	//		pCurrentModule = CONTAINING_RECORD(dwCurrentListEntry, KLDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

	//		if (pCurrentModule->FullDllName.Buffer == 0)
	//			continue;

	//		if (RtlCompareUnicodeString(&dwHideDriverName, &(pCurrentModule->BaseDllName), FALSE) == 0)
	//		{
	//			DbgPrint("�������� %ws �ɹ�!\n", pCurrentModule->BaseDllName.Buffer);
	//			
	//			// �޸� Flink �� Blink ָ��, ��������
	//			*((ULONG_PTR*)pCurrentModule->InLoadOrderLinks.Blink) = (ULONG_PTR)pCurrentModule->InLoadOrderLinks.Flink;
	//			pCurrentModule->InLoadOrderLinks.Flink->Blink = pCurrentModule->InLoadOrderLinks.Blink;

	//			/*
	//				ʹ����������LIST_ENTRY�ṹ���Flink, Blink��ָ���Լ�
	//				��Ϊ�˽ڵ㱾����������, ��ô���ڽӵĽڵ�������ж��ʱ,
	//				ϵͳ��Ѵ˽ڵ��Flink, Blink��ָ�������ڽڵ����һ���ڵ�.
	//				����, ����ʱ�Ѿ�����������, ���������ԭ�����ڵĽڵ�������
	//				ж����, ��ô�˽ڵ��Flink, Blink���п���ָ�����õĵ�ַ, ��
	//				�������Ե�BSoD.
	//			*/
	//			pCurrentModule->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(pCurrentModule->InLoadOrderLinks.Flink);
	//			pCurrentModule->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(pCurrentModule->InLoadOrderLinks.Flink);

	//			break;
	//		}
	//		DbgPrint("[����]: %ws\n", pCurrentModule->BaseDllName.Buffer);
	//		// ��һ��
	//		dwCurrentListEntry = dwCurrentListEntry->Flink;
	//	}
	//}

	PLDR_DATA_TABLE_ENTRY pLdr = NULL;
	PLIST_ENTRY pListEntry = NULL;
	PLIST_ENTRY pCurrentListEntry = NULL;

	PLDR_DATA_TABLE_ENTRY pCurrentModule = NULL;
	pLdr = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	pListEntry = pLdr->InLoadOrderLinks.Flink;
	pCurrentListEntry = pListEntry->Flink;

	while (pCurrentListEntry != pListEntry) //ǰ�����
	{
		//��ȡLDR_DATA_TABLE_ENTRY�ṹ
		pCurrentModule = CONTAINING_RECORD(pCurrentListEntry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

		if (pCurrentModule->BaseDllName.Buffer != 0)
		{
			// Ѱ�� kdcom.dll
			if (RtlCompareUnicodeString(&dwHideDriverName, &(pCurrentModule->BaseDllName), FALSE) == 0)
			{
				DbgPrint("�������� %ws �ɹ�!\n", pCurrentModule->BaseDllName.Buffer);
				// �޸� Flink �� Blink ָ��, ��������
				*((ULONG_PTR*)pCurrentModule->InLoadOrderLinks.Blink) = (ULONG_PTR)pCurrentModule->InLoadOrderLinks.Flink;
				pCurrentModule->InLoadOrderLinks.Flink->Blink = pCurrentModule->InLoadOrderLinks.Blink;

				/*
					ʹ����������LIST_ENTRY�ṹ���Flink, Blink��ָ���Լ�
					��Ϊ�˽ڵ㱾����������, ��ô���ڽӵĽڵ�������ж��ʱ,
					ϵͳ��Ѵ˽ڵ��Flink, Blink��ָ�������ڽڵ����һ���ڵ�.
					����, ����ʱ�Ѿ�����������, ���������ԭ�����ڵĽڵ�������
					ж����, ��ô�˽ڵ��Flink, Blink���п���ָ�����õĵ�ַ, ��
					�������Ե�BSoD.
				*/
				pCurrentModule->InLoadOrderLinks.Flink = (LIST_ENTRY*)&(pCurrentModule->InLoadOrderLinks.Flink);
				pCurrentModule->InLoadOrderLinks.Blink = (LIST_ENTRY*)&(pCurrentModule->InLoadOrderLinks.Flink);

				break;
			}

			/*DbgPrint("ModuleName = %wZ ModuleBase = %p \r\n",
				pCurrentModule->BaseDllName,
				pCurrentModule->DllBase);*/
		}
		// ��һ��
		pCurrentListEntry = pCurrentListEntry->Flink;
	}
}

// 5��Hook KdpStub
VOID HookKdpStub(PVOID szMyAddress, PVOID szTargetAddress)
{
	ULONG_PTR dwMyFunAddr = (ULONG_PTR)szMyAddress;
	ULONG_PTR dwComebackAddress = (ULONG_PTR)g_OverDoubleMcSymol.KdpStub + 0xF; // �������ĵ�ַ

	// KdpStub ԭʼ Code + Jmp fffff800`0434d021
	UCHAR KdpStubShellCode[] = {
		0x48, 0x89, 0x5c, 0x24, 0x08,  // mov     qword ptr [rsp+8],rbx
		0x48, 0x89, 0x6c, 0x24, 0x10,  // mov     qword ptr [rsp+10h],rbp
		0x48, 0x89, 0x74, 0x24, 0x18,  // mov     qword ptr [rsp+18h],rsi
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, 0xFFFFFFFF
		0xFF, 0xE0					   // jmp rax
	};
	// �滻��ת��ַ
	RtlCopyMemory(KdpStubShellCode + 17, &(dwComebackAddress), 8);

	// ����ִ�� KdpTrapShellCode ����Ŀռ�
	ULONG_PTR dwSize = sizeof(KdpStubShellCode);
	g_OverDoubleMcSymol.uKdpStub = (pKdpTrap)ExAllocatePool(NonPagedPool, dwSize);
	RtlCopyMemory(g_OverDoubleMcSymol.uKdpStub, KdpStubShellCode, dwSize);

	// ���� JmpCode
	UCHAR JmpCode[] = {
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, 0xFFFFFFFF
		0xFF, 0xE0 // jmp rax
	};
	// �滻��ת��ַ
	RtlCopyMemory(JmpCode + 2, &dwMyFunAddr, 8);
	// Modify KdpTrap
	RemovWP(); // �ر�д����
	RtlCopyMemory(szTargetAddress, JmpCode, 12);
	UndoWP();  // ��ԭд����
}

// 6������ TP ����(KdEnteredDebugger ��־)
// Hook IoAllocateMdl
VOID HookIoAllocateMdl(PVOID szMyAddress, PVOID szTargetAddress)
{
	ULONG_PTR dwMyFunAddr = (ULONG_PTR)szMyAddress;
	ULONG_PTR dwComebackAddress = (ULONG_PTR)g_OverDoubleMcSymol.IoAllocateMdl + 0xC; // �������ĵ�ַ

	// KdpStub ԭʼ Code + Jmp fffff800`0434d021
	UCHAR IoAllocateMdlShellCode[] = {
		0x48, 0x89, 0x5c, 0x24, 0x20, // mov     qword ptr [rsp+20h],rbx
		0x44, 0x88, 0x44, 0x24, 0x18, // mov     byte ptr [rsp+18h],r8b
		0x55,						  // push    rbp
		0x56,						  // push    rsi	
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, 0xFFFFFFFF
		0xFF, 0xE0					  // jmp rax
	};
	// �滻��ת��ַ
	RtlCopyMemory(IoAllocateMdlShellCode + 14, &(dwComebackAddress), 8);

	// ����ִ�� KdpTrapShellCode ����Ŀռ�
	ULONG_PTR dwSize = sizeof(IoAllocateMdlShellCode);
	g_OverDoubleMcSymol.uIoAllocateMdl = (pIoAllocateMdl)ExAllocatePool(NonPagedPool, dwSize);
	RtlCopyMemory(g_OverDoubleMcSymol.uIoAllocateMdl, IoAllocateMdlShellCode, dwSize);

	// ���� JmpCode
	UCHAR JmpCode[] ={
		0x48, 0xB8, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rax, 0xFFFFFFFF
		0xFF, 0xE0 // jmp rax
	};
	// �滻��ת��ַ
	RtlCopyMemory(JmpCode + 2, &dwMyFunAddr, 8);

	// Modify IoAllocateMdl
	RemovWP(); // �ر�д����
	RtlCopyMemory(szTargetAddress, JmpCode, 12);
	UndoWP();
}

// 7. ���� INT 1 (KiDebugTrapOrFault)�ϵ�� HOOK
// Hook KiDebugTrapOrFault
VOID HookKiDebugTrapOrFault(PVOID szMyAddress, PVOID szTargetAddress)
{

}

// ������ Tp ˫������
NTSTATUS StartOverDoubleMc(PDRIVER_OBJECT DriverObject)
{
	NTSTATUS dwStatus = STATUS_SUCCESS;

	// ��ʼ������
	InitOverDoubleMcSymbol();

	// 1�����Ƚ�� WinDbg �Ĳ��ϵ��� The context is partially valid. Only x86 user-mode context is available.
	HookKdpTrap(MyKdpTrap, g_OverDoubleMcSymol.KdpTrap);

	// 2����ֹ��ȫ�������ʧ��
	DisableKdDebuggerEnabled();

	// 4���������� kdcom����ֹkdcom�ڴ汻��յ��º�windbgͨѶ����
	HideKdcomDriver(DriverObject);

	// 5��Hook KdpStub
	HookKdpStub(MyKdpStub, g_OverDoubleMcSymol.KdpStub);

	// 6. ���� TP ����
	HookIoAllocateMdl(MyIoAllocateMdl, g_OverDoubleMcSymol.IoAllocateMdl);

	// 7. ���� INT 1 (KiDebugTrapOrFault)�ϵ�� HOOK

	// 3��TP ������ȫ�� KdDebuggerEnabled, ������һ��ÿ��һ��Ķ�ʱ��
	RepairKdDebuggerEnabledByTimer(DriverObject);

	
	return dwStatus;
}
