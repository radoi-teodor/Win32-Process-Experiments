#pragma once

typedef BOOL (WINAPI* EnumProcessesFunctionPointer)(
	DWORD* lpidProcess,
	DWORD   cb,
	LPDWORD lpcbNeeded
);