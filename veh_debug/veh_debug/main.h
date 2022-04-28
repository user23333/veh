#pragma once
#include <cstdint>
#include <windows.h>
#include <tlhelp32.h>

#define STATUS_WX86_SINGLE_STEP 0x4000001E

#define PADDING(type, name, size) union { type name; char name##_padding[size]; }

#define VEHVERSION 4

#ifdef _WIN64
#define Xip Rip
#else
#define Xip Eip
#endif

struct VEHDebugSharedMem
{
	PADDING(CONTEXT, CurrentContext, 8192);
	PADDING(HANDLE, HasDebugEvent, 8);
	PADDING(HANDLE, HasHandledDebugEvent, 8);
	uint64_t ContinueMethod;
	uint32_t ProcessID;
	uint32_t ThreadID;
	uint64_t ThreadWatchMethod;
	uint64_t ThreadWatchMethodConfig;
	uint32_t VEHVersion;
	uint32_t HeartBeat;
	uint64_t NoBreakListSize;
	uint64_t NoBreakList[64];
	EXCEPTION_RECORD Exception;
};

struct CriticalSectionLock
{
	CRITICAL_SECTION cs;

	void Init()
	{
		InitializeCriticalSection(&cs);
	}

	void Enter()
	{
		EnterCriticalSection(&cs);
	}

	void Leave()
	{
		LeaveCriticalSection(&cs);
	}
};

EXTERN_C_START
NTSYSAPI VOID NTAPI KiUserExceptionDispatcher();
NTSYSAPI VOID NTAPI RtlRestoreContext(PCONTEXT ContextRecord, PEXCEPTION_RECORD ExceptionRecord);
EXTERN_C_END

inline void* SetWow64PrepareForException(void* ptr)
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