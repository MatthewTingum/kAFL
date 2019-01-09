/*

Copyright (C) 2017 Sergej Schumilo, et al.

This file is part of kAFL Fuzzer (kAFL).

QEMU-PT is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 2 of the License, or
(at your option) any later version.

QEMU-PT is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with QEMU-PT.  If not, see <http://www.gnu.org/licenses/>.

*/

#include <windows.h>
#include <psapi.h>
#include <tchar.h>
#include <stdio.h>
#include <winternl.h>
#include "../../kafl_user.h"

#define ARRAY_SIZE 1024

// If this fails, try increasing INFO_SIZE in kafl_user.h

BOOL SetPrivilege( HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) { 

	TOKEN_PRIVILEGES tp = { 0 }; 
	// Initialize everything to zero 
	LUID luid; 
	DWORD cb=sizeof(TOKEN_PRIVILEGES); 

	if(!LookupPrivilegeValue( NULL, Privilege, &luid )){
		return FALSE; 
	}

	tp.PrivilegeCount = 1; 
	tp.Privileges[0].Luid = luid; 

	if(bEnablePrivilege) { 
		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED; 
	} else { 
		tp.Privileges[0].Attributes = 0; 
	} 

	AdjustTokenPrivileges( hToken, FALSE, &tp, cb, NULL, NULL ); 

	if (GetLastError() != ERROR_SUCCESS){
		return FALSE; 
	}

	return TRUE;

}


int main( void ){

	char* info_buffer = (char*)VirtualAlloc(0, INFO_SIZE, MEM_COMMIT, PAGE_READWRITE);
	memset(info_buffer, 0xff, INFO_SIZE);
	memset(info_buffer, 0x00, INFO_SIZE);
	int pos = 0;

	HANDLE hToken;

	if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)){
		if (GetLastError() == ERROR_NO_TOKEN){

			if (!ImpersonateSelf(SecurityImpersonation)){
            			goto fail;
			}

			if(!OpenThreadToken(GetCurrentThread(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, FALSE, &hToken)){
            			goto fail;
            		}
		} else {
			goto fail;;
		}
	}

	// Enable the Chad SeDebugPrivilege
	if(!SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
		//DisplayError("SetPrivilege");

		// close token handle
		CloseHandle(hToken);

		// indicate failure
		goto fail;
	}	

	DWORD aProcesses[1024]; 
	DWORD cbNeeded; 
	DWORD cProcesses;

	// Get the list of process identifiers.
	if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) )
		return 1;

	// Calculate how many process identifiers were returned.
	cProcesses = cbNeeded / sizeof(DWORD);
	pos += sprintf(info_buffer + pos, "kAFL Windows x86-64 Kernel Addresses (%d Processes)\n\n", cProcesses);


	for (int i = 0; i < cProcesses; i++ )
	{
		HMODULE hMods[1024];
		HANDLE hProcess;
		DWORD cbNeededMods;

		// Print the process identifier.
		pos += sprintf(info_buffer + pos, "Process ID: %d\n", aProcesses[i]);

		// Get a handle to the process.

		hProcess = OpenProcess( PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i] );
		
		if (hProcess != NULL) {
			
			// Get a list of all the modules in this process.

			if( EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeededMods)) {

				for (int j = 0; j < (cbNeededMods / sizeof(HMODULE)); j++ ) {

					TCHAR szModName[MAX_PATH];

					// Get the full path to the module's file.
					if ( GetModuleFileNameEx( hProcess, hMods[j], szModName, sizeof(szModName) / sizeof(TCHAR))) {

						MODULEINFO moduleInfo = { 0 };
				
						if (GetModuleInformation(hProcess, hMods[j], &moduleInfo, cbNeededMods)) {

							pos += sprintf(info_buffer + pos, "\t%s (0x%p) - (0x%p)\n", szModName, hMods[j], hMods[j] + moduleInfo.SizeOfImage);

						}

					}
				}
			}
    
			// Release the handle to the process.
			CloseHandle( hProcess );

		}

	}


fail:
	kAFL_hypercall(HYPERCALL_KAFL_INFO, (UINT64)info_buffer);
	//printf("%s\n", (UINT64)info_buffer);
	return 0;

}


