#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <cstdint>
#include <string>

namespace wndhide
{
    inline uintptr_t get_module_base(uint32_t process_id, const wchar_t* module_name)
    {
        uintptr_t base_address = 0;
        const HANDLE snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
        if (snapshot_handle != INVALID_HANDLE_VALUE)
        {
            MODULEENTRY32 module_entry;
            module_entry.dwSize = sizeof(module_entry);
            if (Module32First(snapshot_handle, &module_entry))
            {
                do
                {
                    if (!_wcsicmp(module_entry.szModule, module_name))
                    {
                        base_address = reinterpret_cast<uintptr_t>(module_entry.modBaseAddr);
                        break;
                    }
                } while (Module32Next(snapshot_handle, &module_entry));
            }
        }
        CloseHandle(snapshot_handle);
        return base_address;
    }

    inline uintptr_t get_module_export(HANDLE process_handle, uintptr_t module_base, const char* export_name)
    {
        SIZE_T dummy_read_size;
        IMAGE_DOS_HEADER dos_header = { 0 };
        IMAGE_NT_HEADERS64 nt_headers = { 0 };

        if (!ReadProcessMemory(process_handle, reinterpret_cast<void*>(module_base), &dos_header, sizeof(dos_header), &dummy_read_size) || dos_header.e_magic != IMAGE_DOS_SIGNATURE ||
            !ReadProcessMemory(process_handle, reinterpret_cast<void*>(module_base + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), &dummy_read_size) || nt_headers.Signature != IMAGE_NT_SIGNATURE)
            return 0;

        const auto export_base = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        const auto export_base_size = nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

        if (!export_base || !export_base_size)
            return 0;

        const auto export_data = static_cast<PIMAGE_EXPORT_DIRECTORY>(VirtualAlloc(nullptr, export_base_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!export_data)
            return 0;

        if (!ReadProcessMemory(process_handle, reinterpret_cast<void*>(module_base + export_base), export_data, export_base_size, &dummy_read_size))
        {
            VirtualFree(export_data, 0, MEM_RELEASE);
            return 0;
        }

        const auto delta = reinterpret_cast<uint64_t>(export_data) - export_base;

        const auto name_table = reinterpret_cast<uint32_t*>(export_data->AddressOfNames + delta);
        const auto ordinal_table = reinterpret_cast<uint16_t*>(export_data->AddressOfNameOrdinals + delta);
        const auto function_table = reinterpret_cast<uint32_t*>(export_data->AddressOfFunctions + delta);

        for (auto i = 0u; i < export_data->NumberOfNames; ++i)
        {
            const std::string current_function_name = std::string(reinterpret_cast<char*>(name_table[i] + delta));

            if (!_stricmp(current_function_name.c_str(), export_name))
            {
                const auto function_ordinal = ordinal_table[i];
                if (function_table[function_ordinal] <= 0x1000)
                    return 0;

                const auto function_address = module_base + function_table[function_ordinal];

                if (function_address >= module_base + export_base && function_address <= module_base + export_base + export_base_size)
                {
                    // Forwarded export
                    VirtualFree(export_data, 0, MEM_RELEASE);
                    return 0;
                }

                VirtualFree(export_data, 0, MEM_RELEASE);
                return function_address;
            }
        }

        VirtualFree(export_data, 0, MEM_RELEASE);
        return 0;
    }

    inline bool hide_window(uint32_t process_id, HWND window_id, bool hide = true)
    {
        const HANDLE process_handle = OpenProcess(PROCESS_ALL_ACCESS, false, process_id);
        if (!process_handle || process_handle == INVALID_HANDLE_VALUE)
            return false;

        const uintptr_t user32_base = get_module_base(process_id, L"user32.dll");
        if (!user32_base)
            return false;

        const uintptr_t function_pointer = get_module_export(process_handle, user32_base, "SetWindowDisplayAffinity");
        if (!function_pointer)
            return false;

        unsigned char shellcode_buffer[] = "\x48\x89\x4C\x24\x08\x48\x89\x54\x24\x10\x4C\x89\x44\x24\x18\x4C\x89\x4C\x24"
            "\x20\x48\x83\xEC\x38\x48\xB9\xED\xFE\xAD\xDE\xED\xFE\x00\x00\x48\xC7\xC2\xAD"
            "\xDE\x00\x00\x48\xB8\xAD\xDE\xED\xFE\xAD\xDE\x00\x00\xFF\xD0\x48\x83\xC4\x38"
            "\x48\x8B\x4C\x24\x08\x48\x8B\x54\x24\x10\x4C\x8B\x44\x24\x18\x4C\x8B\x4C\x24"
            "\x20\xC3";

        const uint32_t mask = hide ? 0x00000011 : 0x00000000; // CWDA_EXCLUDEFROMCAPTURE : CWDA_NONE

        *reinterpret_cast<uintptr_t*>(shellcode_buffer + 26) = reinterpret_cast<uintptr_t>(window_id); // window hwnd
        *reinterpret_cast<uint32_t*>(shellcode_buffer + 37) = mask; // flags
        *reinterpret_cast<uintptr_t*>(shellcode_buffer + 43) = function_pointer; // function ptr

        void* allocated_base = VirtualAllocEx(process_handle, 0x0, sizeof(shellcode_buffer), MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        if (!allocated_base)
            return false;

        SIZE_T dummy_size;
        if (!WriteProcessMemory(process_handle, allocated_base, shellcode_buffer, sizeof(shellcode_buffer), &dummy_size))
            return false;

        HANDLE thread_handle = CreateRemoteThread(process_handle, nullptr, 0, static_cast<LPTHREAD_START_ROUTINE>(allocated_base), nullptr, 0, nullptr);
        if (!thread_handle || thread_handle == INVALID_HANDLE_VALUE)
            return false;

        // wait for shellcode to execute
        Sleep(1000);

        memset(shellcode_buffer, 0, sizeof(shellcode_buffer));
        if (!WriteProcessMemory(process_handle, allocated_base, shellcode_buffer, sizeof(shellcode_buffer), &dummy_size))
            return false;

        return true;
    }
}