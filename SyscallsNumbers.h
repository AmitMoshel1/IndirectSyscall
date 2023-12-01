#pragma once
#include <Windows.h>
#include <winternl.h>

#define KEY "DEADBEEF"

char XOR(char* Name);	//XORing function names and DLLs
HMODULE ParsePEB(char XORFuncName);	// Parsing the PEB to extract ntdll's base address inside current process
FARPROC GetFuncAddress(HMODULE entry, const char* FuncName); // Get the function's address 
int GetSyscallNumber(HMODULE handle, FARPROC FuncAddress); //After getting the function's address, determinig whether the function is hooked (by searching for the presence of a JMP opcode inside the function's block), then extracting the syscall number.

