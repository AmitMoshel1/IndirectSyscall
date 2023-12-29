#pragma once
#include <Windows.h>
#include <winternl.h>

HMODULE ParsePEB(char XORFuncName);	// Parsing the PEB to extract ntdll's base address inside current process
FARPROC GetFuncAddress(HMODULE entry, const char* FuncName); // Get the function's address 

char * GetSyscallNumberHooked(FARPROC FuncAddress1, FARPROC FuncAddress2); //After getting the function's address, determine whether the function is hooked (by searching for the presence of a JMP opcode inside the function's block), then extracting the syscall number.
PVOID GetSyscallAddress(FARPROC address);
