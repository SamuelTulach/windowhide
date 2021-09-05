#include <iostream>
#include "wndhide.h"

int main()
{
    HWND test_window = FindWindowA("ProcessHacker", nullptr);
    DWORD pid = 0;
    GetWindowThreadProcessId(test_window, &pid);
    printf("pid: %u hwnd: 0x%p\n", pid, test_window);
    if (!pid)
    {
        getchar();
        return 1;
    }

    bool status = wndhide::hide_window(pid, test_window);
    printf("status: %u\n", static_cast<unsigned>(status));

    getchar();
    return 0;
}