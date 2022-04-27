#include "main.h"

EXTERN_C_START
NTSYSAPI VOID NTAPI KiUserExceptionDispatcher();
NTSYSAPI VOID NTAPI RtlRestoreContext(PCONTEXT ContextRecord, PEXCEPTION_RECORD ExceptionRecord);
EXTERN_C_END

HANDLE file_mapping;
char config_name[256];
char events_name[2][256];
VEHDebugSharedMem* vehmem;

bool veh_debug_active = false;
PVOID exception_handler_handle = nullptr;

DWORD handler_lock;
CriticalSectionLock handler_cs;
HANDLE emergency;

void* SetWow64PrepareForException(void* ptr)
{
	char* excdis = reinterpret_cast<char*>(KiUserExceptionDispatcher);
	int rel = *reinterpret_cast<int*>(excdis + 0x4);
	void** predis = reinterpret_cast<void**>(excdis + rel + 0x8);

	DWORD protect = PAGE_READWRITE;
	VirtualProtect(predis, 8, protect, &protect);
	void* old_predis = *predis;
	*predis = ptr;
	VirtualProtect(predis, 8, protect, &protect);
	return old_predis;
}

void TestAndFixCs()
{
	SetEvent(emergency);
	handler_cs.Enter();
	handler_cs.Leave();
	ResetEvent(emergency);
}

void UnloadVEH()
{
	veh_debug_active = false;
	if (exception_handler_handle)
	{
		if (exception_handler_handle == reinterpret_cast<PVOID>(-1))
		{
			exception_handler_handle = nullptr;
		}
		SetWow64PrepareForException(exception_handler_handle);
		exception_handler_handle = nullptr;
	}
}

LONG InternalHandler(LPEXCEPTION_POINTERS ep, DWORD tid)
{
	LONG result = EXCEPTION_CONTINUE_SEARCH;
	if (!veh_debug_active)
		return result;

	while (handler_lock && handler_lock != GetCurrentThreadId())
		Sleep(50);

	handler_cs.Enter();

	vehmem->Exception.ExceptionCode = ep->ExceptionRecord->ExceptionCode;
	vehmem->Exception.ExceptionFlags = ep->ExceptionRecord->ExceptionFlags;
	vehmem->Exception.ExceptionRecord = ep->ExceptionRecord->ExceptionRecord;
	vehmem->Exception.NumberParameters = ep->ExceptionRecord->NumberParameters;
	for (size_t i = 0; i < ep->ExceptionRecord->NumberParameters; i++)
		vehmem->Exception.ExceptionInformation[i] = ep->ExceptionRecord->ExceptionInformation[i];

	if (ep->ContextRecord)
	{
		RtlCopyMemory(&vehmem->CurrentContext, ep->ContextRecord, sizeof(CONTEXT));
	}
	else
	{
		RtlSecureZeroMemory(&vehmem->CurrentContext, sizeof(CONTEXT));
	}

	vehmem->ProcessID = GetCurrentProcessId();
	vehmem->ThreadID = tid;

	if (SetEvent(vehmem->HasDebugEvent))
	{
		HANDLE handles[2] = { vehmem->HasHandledDebugEvent, emergency };
		uint32_t heartbeat = vehmem->HeartBeat;
		DWORD wr;
		do
		{
			wr = WaitForMultipleObjects(ARRAYSIZE(handles), handles, false, 5000);
			if (wr == WAIT_TIMEOUT && heartbeat == vehmem->HeartBeat)
			{
				UnloadVEH();
				ResetEvent(vehmem->HasDebugEvent);
				handler_cs.Leave();
				return result;
			}
		} while (wr == WAIT_TIMEOUT);

		if ((wr - WAIT_OBJECT_0) == 0)
		{
			if (ep->ContextRecord)
			{
				RtlCopyMemory(ep->ContextRecord, &vehmem->CurrentContext, sizeof(CONTEXT));
				if (vehmem->ContinueMethod == DBG_CONTINUE)
				{
					vehmem->CurrentContext.ContextFlags = CONTEXT_DEBUG_REGISTERS;
					SetThreadContext(GetCurrentThread(), &vehmem->CurrentContext);
				}
			}
		}
		else
		{
			//MessageBoxA(0, "WaitForMultipleObjects failed", "VEH Debug Error", MB_OK);
			result = EXCEPTION_CONTINUE_EXECUTION;
		}

		if (vehmem->ContinueMethod == DBG_CONTINUE)
		{
			result = EXCEPTION_CONTINUE_EXECUTION;
		}
	}

	handler_cs.Leave();

	return result;
}

LONG Handler(LPEXCEPTION_POINTERS ep)
{
	DWORD tid = GetCurrentThreadId();
	for (uint64_t i = 0; i < vehmem->NoBreakListSize; i++)
	{
		if (vehmem->NoBreakList[i] == tid)
		{
			if (ep->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP ||
				ep->ExceptionRecord->ExceptionCode == STATUS_WX86_SINGLE_STEP)
			{
				ep->ContextRecord->EFlags |= (1 << 16);
				return EXCEPTION_CONTINUE_EXECUTION;
			}
			else
			{
				break;
			}
		}
	}
	return InternalHandler(ep, tid);
}

void Wow64PrepareForExceptionHook(PEXCEPTION_RECORD er, PCONTEXT ctx)
{
	EXCEPTION_POINTERS ep = { er,ctx };
	if (Handler(&ep) == EXCEPTION_CONTINUE_EXECUTION)
	{
		RtlRestoreContext(ctx, er);
	}
}

void EmulateInitializeEvents()
{
	EXCEPTION_POINTERS ep;
	EXCEPTION_RECORD er;
	CONTEXT bpc;

	ep.ContextRecord = nullptr;
	ep.ExceptionRecord = &er;
	er.NumberParameters = 0;

	handler_cs.Enter();

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (snapshot != INVALID_HANDLE_VALUE)
	{
		THREADENTRY32 te = { sizeof(THREADENTRY32) };
		if (Thread32First(snapshot, &te))
		{
			DWORD pid = GetCurrentProcessId();
			bool first = true;
			do
			{
				if (te.th32OwnerProcessID == pid)
				{
					if (first)
					{
						er.ExceptionCode = 0xce000000;
						first = false;
					}
					else
					{
						er.ExceptionCode = 0xce000001;
					}
					InternalHandler(&ep, te.th32ThreadID);
				}
			} while (Thread32Next(snapshot, &te));
		}
		CloseHandle(snapshot);
	}

	RtlSecureZeroMemory(&bpc, sizeof(bpc));
	er.ExceptionCode = EXCEPTION_BREAKPOINT;
	ep.ContextRecord = &bpc;
	bpc.Xip = 0xffffffce;
	Handler(&ep);

	handler_cs.Leave();
}

void InitializeVEH()
{
	UnloadVEH();
	TestAndFixCs();

	if (!file_mapping && !(file_mapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, false, config_name)))
		return;

	if (!(vehmem = static_cast<VEHDebugSharedMem*>(MapViewOfFile(file_mapping, FILE_MAP_ALL_ACCESS, 0, 0, 0))))
		return;

	vehmem->VEHVersion = 0xcece0000 + VEHVERSION;
	vehmem->HasDebugEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, events_name[0]);
	vehmem->HasHandledDebugEvent = OpenEventA(EVENT_ALL_ACCESS, FALSE, events_name[1]);

	handler_lock = GetCurrentThreadId();
	handler_cs.Enter();
	veh_debug_active = true;

	if (!exception_handler_handle)
	{
		exception_handler_handle = SetWow64PrepareForException(Wow64PrepareForExceptionHook);
		if (!exception_handler_handle)
		{
			exception_handler_handle = reinterpret_cast<PVOID>(-1);
		}
	}

	EmulateInitializeEvents();

	handler_cs.Leave();
	handler_lock = 0;
}

void DllMain()
{
	handler_cs.Init();
	emergency = CreateEventA(nullptr, true, false, nullptr);
}