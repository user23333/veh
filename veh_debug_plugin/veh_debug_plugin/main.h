#pragma once
#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include "cesdk/cepluginsdk.h"
#include "cesdk/lua.hpp"
#include "minhook/minhook.h"
#include "minhook/hde/hde64.h"

#pragma comment(lib, "ntdll.lib")

#define HOOKFN(name) name##Hook
#define ORIGFN(name) name##Orig

#define HOOKARGS(name) HOOKFN(name), &ORIGFN(name)
#define ORIGINAL(name) reinterpret_cast<decltype(HOOKFN(name))*>(ORIGFN(name))

class VTFInvoke
{
public:
	template<typename T, typename... Args>
	inline T Invoke(int index, Args... args)
	{
		return reinterpret_cast<T(__thiscall*)(void*, Args...)>((*reinterpret_cast<void***>(this))[index])(this, args...);
	}
};

class TStrings : VTFInvoke
{
public:
	inline void GetString(const char** ptr, int index)
	{
		return Invoke<void>(30, ptr, index);
	}

	inline int GetCount()
	{
		return Invoke<int>(32);
	}

	inline bool Has(const char* str)
	{
		int count = GetCount();
		for (int i = 0; i < count; i++)
		{
			const char* ptr = nullptr;
			GetString(&ptr, i);
			if (strstr(ptr, str))
			{
				return true;
			}
		}
		return false;
	}
};

inline void* FindCall(const void* code, int num /*1,2,3,...*/, int size = 4096)
{
	char* ptr = static_cast<char*>(const_cast<void*>(code));
	int i = 0, j = 0;
	while (i < size)
	{
		hde64s hs;
		hde64_disasm(ptr + i, &hs);
		if (hs.opcode == 0xE8 && ++j == num)
		{
			return ptr + i + hs.len + static_cast<int>(hs.imm.imm32);
		}
		if (!hs.len) break;
		i += hs.len;
	}
	return nullptr;
}