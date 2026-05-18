#include <stdio.h>
#include <windows.h>
#include <tlhelp32.h>

// Checks which modules have been loaded into memory by a specific process and locates the export tables
void SeeExport(HANDLE proc, BYTE* baseadress, FILE* output_file){
    IMAGE_DOS_HEADER dos;
    IMAGE_NT_HEADERS nt;

    // Read the structures of the executable directly from process memory (RPM)
    ReadProcessMemory(proc, baseadress, &dos, sizeof(dos), NULL);
    ReadProcessMemory(proc, baseadress + dos.e_lfanew, &nt, sizeof(nt), NULL);

    IMAGE_DATA_DIRECTORY exportdatadir = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

    if (exportdatadir.Size == 0){
        fprintf(output_file, "This DLL does not export functions.\n");
        printf("This DLL does not export functions.\n");
        return;
    }

    IMAGE_EXPORT_DIRECTORY exportdir;
    ReadProcessMemory(proc, baseadress + exportdatadir.VirtualAddress, &exportdir, sizeof(exportdir), NULL);
    
    DWORD* nomes = (DWORD*)malloc(exportdir.NumberOfNames * sizeof(DWORD));
    ReadProcessMemory(proc, baseadress + exportdir.AddressOfNames, nomes, exportdir.NumberOfNames * sizeof(DWORD), NULL);

    for (DWORD i = 0; i < exportdir.NumberOfNames; i++){
        char funcname[256] = {0};
        ReadProcessMemory(proc, baseadress + nomes[i], funcname, sizeof(funcname), NULL);
        
        fprintf(output_file, "\t/--Func Name:   %s\n", funcname);
        printf("\t/--Func Name:   %s\n", funcname);
    }
    
    free(nomes); 
}

void ListarDLL(DWORD pid, FILE* output_file){
    // Retrieves the DLLs mapped by the process using toolhelp32    
    HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    HANDLE hp = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);

    if (hsnap == INVALID_HANDLE_VALUE){
        return;
    }

    if (hp == NULL){
        return;
    }

    MODULEENTRY32 me;
    me.dwSize = sizeof(MODULEENTRY32);

    if (Module32First(hsnap, &me)){
        fprintf(output_file, "Resolving DLLs for PID: %u \n", pid);
        printf("Resolving DLLs for PID: %u \n", pid);

        do {
            fprintf(output_file, "Name:   %s |    Path:   %s |", me.szModule , me.szExePath);
            fprintf(output_file, "DLL Address:     %p\n", me.modBaseAddr);
            
            printf("Name:   %s |    Path:   %s |", me.szModule , me.szExePath);
            printf("DLL Address:     %p\n", me.modBaseAddr); 
            
            SeeExport(hp, me.modBaseAddr, output_file);

        } while (Module32Next(hsnap, &me));
    }
    CloseHandle(hsnap);
    CloseHandle(hp); 
}

void HUnt(const char* targetProcess, FILE* output_file){

    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Snapshot of all running processes on the OS
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap){
        return;
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32)){
        CloseHandle(hProcessSnap);
        return;
    }

    do {
        // Find the process passed via an argument
        if(stricmp(pe32.szExeFile, targetProcess) == 0){
            fprintf(output_file, "Hello [%s]\n", targetProcess);
            printf("Hello [%s]\n", targetProcess);
            
            ListarDLL(pe32.th32ProcessID, output_file);
            CloseHandle(hProcessSnap);
            return;
        }
    } while (Process32Next(hProcessSnap, &pe32));

    fprintf(output_file, "Process %s was not found at this time.\n", targetProcess);
    printf("Process %s was not found at this time.\n", targetProcess);
    CloseHandle(hProcessSnap);
}


int main (int argc, char *argv[]){
    if (argc != 2) {
        printf("Usage: %s <process_name.exe>\n", argv[0]);
        return 1;
    }

    // Opens or creates the TXT report file
    FILE* output_file = fopen("process_hunt_report.txt", "w");
    if (output_file == NULL) {
        printf("Error creating TXT report file.\n");
        return 1;
    }

    HUnt(argv[1], output_file);

    fclose(output_file);
    printf("\n[+] Analysis complete! Results saved to 'process_hunt_report.txt'\n");
    return 0;
}
