#include "main.h"
#include "shellcode.h"

ExportedFunctions ef;
bool veh_debug_enable = false;

int debug_active_step = 0;
char config_name[256];
char events_name[2][256] = { {"{7352E944-F953-45FD-BBBE-873A8BB9C51C}"},{"{EC8CAD60-5C74-439E-8327-98314462046E}"} };
HANDLE file_mapping;
HANDLE has_debug_event;
HANDLE has_handled_debug_event;

char* fm;
char* ConfigName;
char* EventsName;
char* InitializeVEH;
char* UnloadVEH;

HANDLE remote_exec_final;
char* dispatch_table_ptr;
char* dispatch_table;

void* ORIGFN(CreateFileMappingA);
void* ORIGFN(CreateEventA);
void* ORIGFN(DuplicateHandle);
void* ORIGFN(InjectDll);
void* ORIGFN(AutoAssemble);

void DoString(const char* fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	char str[256];
	wvsprintfA(str, fmt, ap);
	va_end(ap);
	luaL_dostring(ef.GetLuaState(), str);
}

void RegisterSymbol(const char* symbol, LPVOID address)
{
	DoString("registerSymbol(\"%s\",0x%p)", symbol, address);
}

void UnRegisterSymbol(const char* symbol)
{
	DoString("unregisterSymbol(\"%s\")", symbol);
}

DWORD WINAPI RemoteExecFinal(LPVOID param)
{
	char* mem = static_cast<char*>(param);
	char* exc = mem + 1024;

	HANDLE process = *ef.OpenedProcessHandle;

	DWORD tick = GetTickCount();
	DWORD once = 0;
	while (GetTickCount() - tick < 4000 && !once)
	{
		ReadProcessMemory(process, exc + 0x59, &once, 4, nullptr);
		Sleep(100);
	}

	WriteProcessMemory(process, dispatch_table_ptr, &dispatch_table, 8, nullptr);
	VirtualFreeEx(process, mem, 0, MEM_RELEASE);

	CloseHandle(remote_exec_final);
	remote_exec_final = 0;

	return 0;
}

BOOL CALLBACK EnumWindowFunc(HWND hwnd, LPARAM param)
{
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);
	if (pid == *ef.OpenedProcessID)
	{
		SendMessageTimeoutW(hwnd, WM_NULL, 0, 0, SMTO_NORMAL, 1, nullptr);
		return FALSE;
	}
	return TRUE;
}

bool RemoteExec(HANDLE process, LPVOID address)
{
	if (remote_exec_final)
	{
		WaitForSingleObject(remote_exec_final, 5000);
	}

	PROCESS_BASIC_INFORMATION pbi;
	if (!NT_SUCCESS(NtQueryInformationProcess(process, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr)))
		return false;

	char* peb = reinterpret_cast<char*>(pbi.PebBaseAddress);
	dispatch_table_ptr = peb + 0x58;
	dispatch_table = nullptr;
	if (!ReadProcessMemory(process, dispatch_table_ptr, &dispatch_table, 8, nullptr) || !dispatch_table)
		return false;

	char* mem = static_cast<char*>(VirtualAllocEx(process, nullptr, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (!mem)
		return false;

	char* fdt = mem;
	char* exc = mem + 1024;

	char* tab[128];
	if (!ReadProcessMemory(process, dispatch_table, tab, sizeof(tab), nullptr))
	{
		VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		return false;
	}

	unsigned char excode[] = { 131,61,82,0,0,0,0,117,66,72,131,236,72,76,137,76,36,56,76,137,68,36,48,72,137,84,36,40,72,137,76,36,32,72,184,254,254,254,254,254,254,254,254,255,208,72,139,76,36,32,72,139,84,36,40,76,139,68,36,48,76,139,76,36,56,72,131,196,72,255,5,14,0,0,0,255,37,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0 };
	*reinterpret_cast<LPVOID*>(excode + 0x23) = address;
	*reinterpret_cast<LPVOID*>(excode + 0x51) = tab[2];
	tab[2] = exc;

	if (!WriteProcessMemory(process, fdt, tab, sizeof(tab), nullptr) ||
		!WriteProcessMemory(process, exc, excode, sizeof(excode), nullptr) ||
		!WriteProcessMemory(process, dispatch_table_ptr, &fdt, 8, nullptr))
	{
		VirtualFreeEx(process, mem, 0, MEM_RELEASE);
		return false;
	}

	//SendNotifyMessageA(HWND_BROADCAST, WM_NULL, 0, 0);
	EnumWindows(EnumWindowFunc, 0);

	remote_exec_final = CreateThread(nullptr, 0, RemoteExecFinal, mem, 0, nullptr);

	return true;
}

bool InstallVEH()
{
	HANDLE process = *ef.OpenedProcessHandle;
	char* base = static_cast<char*>(VirtualAllocEx(process, nullptr, sizeof(shellcode), MEM_COMMIT, PAGE_EXECUTE_READWRITE));
	if (base)
	{
		if (WriteProcessMemory(process, base, shellcode, sizeof(shellcode), nullptr))
		{
			if (RemoteExec(process, base))
			{
				fm = base + 0x3018;
				ConfigName = base + 0x3250;
				EventsName = base + 0x3020;
				InitializeVEH = base + 0x1410;
				UnloadVEH = base + 0x1000;
				RegisterSymbol("vehdebug-x86_64.dll", base);
				RegisterSymbol("vehdebug-x86_64.InitializeVEH", InitializeVEH);
				RegisterSymbol("vehdebug-x86_64.UnloadVEH", UnloadVEH);
				return true;
			}
		}
		VirtualFreeEx(process, base, 0, MEM_RELEASE);
	}
	return false;
}

HANDLE WINAPI HOOKFN(CreateFileMappingA)(
	_In_     HANDLE hFile,
	_In_opt_ LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
	_In_     DWORD flProtect,
	_In_     DWORD dwMaximumSizeHigh,
	_In_     DWORD dwMaximumSizeLow,
	_In_opt_ LPCSTR lpName)
{
	HANDLE res = ORIGINAL(CreateFileMappingA)(hFile, lpFileMappingAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow, lpName);
	if (lpName && *reinterpret_cast<const WORD*>(lpName) == '{"')  // "{GUID}"
	{
		if (dwMaximumSizeLow >= 8192 && dwMaximumSizeLow <= 10240) // sizeof(TVEHDebugSharedMem)
		{
			strcpy(config_name, lpName);
			file_mapping = res;
			debug_active_step = 1;
		}
	}
	return res;
}

HANDLE WINAPI HOOKFN(CreateEventA)(
	_In_opt_ LPSECURITY_ATTRIBUTES lpEventAttributes,
	_In_ BOOL bManualReset,
	_In_ BOOL bInitialState,
	_In_opt_ LPCSTR lpName)
{

	switch (debug_active_step)
	{
	case 1:
		// HasDebugEvent
		lpName = events_name[0];
		break;
	case 2:
		// HasHandledDebugEvent
		lpName = events_name[1];
		break;
	}

	HANDLE res = ORIGINAL(CreateEventA)(lpEventAttributes, bManualReset, bInitialState, lpName);

	switch (debug_active_step)
	{
	case 1:
		has_debug_event = res;
		debug_active_step = 2;
		break;
	case 2:
		has_handled_debug_event = res;
		debug_active_step = 0;
		break;
	}

	return res;
}

BOOL WINAPI HOOKFN(DuplicateHandle)(
	_In_ HANDLE hSourceProcessHandle,
	_In_ HANDLE hSourceHandle,
	_In_ HANDLE hTargetProcessHandle,
	_Outptr_ LPHANDLE lpTargetHandle,
	_In_ DWORD dwDesiredAccess,
	_In_ BOOL bInheritHandle,
	_In_ DWORD dwOptions)
{
	if (hSourceProcessHandle == GetCurrentProcess() &&
		hTargetProcessHandle == *ef.OpenedProcessHandle)
	{
		if (hSourceHandle == has_debug_event ||
			hSourceHandle == has_handled_debug_event ||
			hSourceHandle == file_mapping)
		{
			return TRUE;
		}
	}
	return ORIGINAL(DuplicateHandle)(hSourceProcessHandle, hSourceHandle, hTargetProcessHandle, lpTargetHandle, dwDesiredAccess, bInheritHandle, dwOptions);
}

void HOOKFN(InjectDll)(const char* dllname, const char* function_to_call)
{
	if (strstr(dllname, "vehdebug-x86_64.dll"))
	{
		InstallVEH();
		return;
	}
	ORIGINAL(InjectDll)(dllname, function_to_call);
}

bool HOOKFN(AutoAssemble)(TStrings* strings, bool popup_messages)
{
	HANDLE process = *ef.OpenedProcessHandle;
	if (strings->Has(".InitializeVEH"))
	{
		HANDLE null_handle = 0;
		if (WriteProcessMemory(process, fm, &null_handle, sizeof(null_handle), nullptr) &&
			WriteProcessMemory(process, ConfigName, config_name, sizeof(config_name), nullptr) &&
			WriteProcessMemory(process, EventsName, events_name, sizeof(events_name), nullptr))
		{
			return RemoteExec(process, InitializeVEH);
		}
		return false;
	}
	else if (strings->Has(".UnloadVEH"))
	{
		return RemoteExec(process, UnloadVEH);
	}
	return ORIGINAL(AutoAssemble)(strings, popup_messages);
}

void __stdcall MainMenuClick()
{
	veh_debug_enable = !veh_debug_enable;
	if (veh_debug_enable)
	{
		MH_EnableHook(MH_ALL_HOOKS);
		DoString("getMainForm().Menu.Items[8].getItem(0).Checked = true");
	}
	else
	{
		MH_DisableHook(MH_ALL_HOOKS);
		DoString("getMainForm().Menu.Items[8].getItem(0).Checked = false");
	}
}

BOOL __stdcall CEPlugin_GetVersion(PPluginVersion pv, int size)
{
	pv->version = CESDK_VERSION;
	pv->pluginname = const_cast<char*>("VEH Debug");
	return TRUE;
}

BOOL __stdcall CEPlugin_InitializePlugin(PExportedFunctions exported_functions, int plugin_id)
{
	ef = *exported_functions;
	if (ef.sizeofExportedFunctions != sizeof(ef))
		return FALSE;

	MAINMENUPLUGIN_INIT menu_init = { const_cast<char*>("VEH Debug"), MainMenuClick, nullptr };
	if (ef.RegisterFunction(plugin_id, ptMainMenu, &menu_init) == -1)
		return FALSE;

	MH_Initialize();
	MH_CreateHook(CreateFileMappingA, HOOKARGS(CreateFileMappingA));
	MH_CreateHook(CreateEventA, HOOKARGS(CreateEventA));
	MH_CreateHook(DuplicateHandle, HOOKARGS(DuplicateHandle));
	MH_CreateHook(FindCall(ef.InjectDLL, 3), HOOKARGS(InjectDll));
	MH_CreateHook(FindCall(ef.AutoAssemble, 3), HOOKARGS(AutoAssemble));

	return TRUE;
}

BOOL __stdcall CEPlugin_DisablePlugin()
{
	MH_Uninitialize();
	return TRUE;
}