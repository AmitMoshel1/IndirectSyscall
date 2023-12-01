#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include "SyscallsNumbers.h"
#include <string.h>

char XOR(char Name)
{
	return Name ^ (char)KEY;
}

HMODULE ParsePEB(char XORDllName) {
    PPEB PEBPtr = (PPEB)__readgsqword(0x60);
    const wchar_t* name;

    PPEB_LDR_DATA HeadModuleList = (PPEB_LDR_DATA)PEBPtr->Ldr;
    PLIST_ENTRY entry = &HeadModuleList->InMemoryOrderModuleList;

    HMODULE NtdllBase = NULL;
    DWORD baseaddress = ((uintptr_t)PEBPtr + 0x10);

    while (entry->Flink != &HeadModuleList->InMemoryOrderModuleList) {
        PLDR_DATA_TABLE_ENTRY table_entries = (PLDR_DATA_TABLE_ENTRY)entry->Flink;
        name = table_entries->FullDllName.Buffer;
        if (_wcsicmp(name, (wchar_t *)XOR(XORDllName)) == 0) {
            HMODULE NtdllBase = (HMODULE)table_entries->DllBase;
            return NtdllBase;
        }
        entry = entry->Flink;
    }
    return NULL;
}

FARPROC GetFuncAddress(HMODULE handle, const char* APIFunction)
{
    PVOID moduleBase = (PVOID)handle;

    PIMAGE_DOS_HEADER pDosHeaders = (PIMAGE_DOS_HEADER)moduleBase;
    PIMAGE_NT_HEADERS64 pNtHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)moduleBase + pDosHeaders->e_lfanew);

    PIMAGE_OPTIONAL_HEADER pOptionalHeaders = &pNtHeaders->OptionalHeader;

    PIMAGE_DATA_DIRECTORY pExportDirectory = (PIMAGE_DATA_DIRECTORY)&pOptionalHeaders->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ExportAddressTable = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)handle + pExportDirectory->VirtualAddress);

    PDWORD FuncAddresses = (PDWORD)((BYTE*)handle + ExportAddressTable->AddressOfFunctions);
    PDWORD NameAddresses = (PDWORD)((BYTE*)handle + ExportAddressTable->AddressOfNames);

    DWORD NumberOfFunctions = ExportAddressTable->NumberOfFunctions;

    char* FuncName;
    for (DWORD i = 0; i < NumberOfFunctions; i++)
    {
        //printf("Function Name: %s\n", pOptionalHeaders->ImageBase + NameAddresses[i]);
        //printf("Function Address: 0x%p\n", (FARPROC)(&pOptionalHeaders->ImageBase + FuncAddresses[i]));
        FuncName = reinterpret_cast<char*>(pOptionalHeaders->ImageBase + NameAddresses[i]);
        if (strcmp(FuncName, APIFunction) == 0)
        {
            return (FARPROC)(pOptionalHeaders->ImageBase + FuncAddresses[i]);
        }
    }    
    return NULL;
}

//FARPROC GetFuncAddress(HMODULE Handle, char* XORFuncName) 
//{
    /*
    Parsing the EAT of the DLL and iterating over the exported function's addresses
    for each function iterating inside the EAT, XORING it and comparing it to the value
    of the function we want to execute through indirect syscall, then returning the address
    of that function.
    */
    //return NULL;
//}


int GetSyscallNumber(HMODULE handle, FARPROC BaseAddress)
{
    /*
    After getting the function's address, determinig whether the function is hooked
    (by searching for the presence of a JMP opcode inside the function's block),
    then extracting the syscall number.
    */
	return 0;
}


