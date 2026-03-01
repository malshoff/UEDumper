// ReSharper disable CppNonInlineFunctionDefinitionInHeaderFile
#pragma once

//add any other includes here your driver might use
#include <Windows.h>
#include <tlhelp32.h>

/*
 * KMDF Driver Backend for UEDumper
 *
 * Reads memory from the target process via a kernel driver using shared memory.
 * The driver exposes KMDF_OP_READ through a named section "Global\\KmdfSvc".
 *
 * Protocol:
 *   1. Write ReadAddress, ReadTotalSize, TargetPID, OpType=KMDF_OP_READ
 *   2. Set CmdState = KMDF_CMD_READY (interlocked)
 *   3. Poll until CmdState == KMDF_CMD_DONE
 *   4. Read result from DllData buffer
 */

// ---------------------------------------------------------------------------
// KMDF protocol definitions (must match shared/protocol.h in driver project)
// ---------------------------------------------------------------------------
#define KMDF_SHM_NAME_UM    "Global\\KmdfSvc"
#define KMDF_SHM_SIZE       0x1000000   // 16 MB
#define KMDF_MAX_DLL_SIZE   0xFF0000
#define KMDF_MAGIC          0x4B4D4446  // "KMDF"

#define KMDF_CMD_NONE       0
#define KMDF_CMD_READY      1
#define KMDF_CMD_DONE       2

#define KMDF_OP_READ        3

#define KMDF_OK             0

#pragma pack(push, 1)
typedef struct _KMDF_SHARED_DATA {
    unsigned int        Magic;
    volatile long       CmdState;
    int                 OpType;
    int                 TargetPID;
    int                 DllSize;
    int                 Result;
    int                 Progress;
    unsigned long long  MappedBase;
    char                StatusMsg[256];
    unsigned long long  DumpTotalSize;
    unsigned long long  DumpOffset;
    int                 DumpChunkSize;
    char                DumpModuleName[64];
    unsigned long long  ReadAddress;
    unsigned long long  ReadTotalSize;
    unsigned char       DllData[1];
} KMDF_SHARED_DATA, *PKMDF_SHARED_DATA;
#pragma pack(pop)

// ---------------------------------------------------------------------------
// Global state
// ---------------------------------------------------------------------------
static HANDLE          g_hMapping = nullptr;
static PKMDF_SHARED_DATA g_shm = nullptr;
static int             g_targetPID = 0;

// Fallback: also keep a process handle for operations like getBaseAddress
// that use Toolhelp snapshots (these work from usermode without the driver)
HANDLE procHandle = nullptr;

// ---------------------------------------------------------------------------
// Wait for the driver to finish processing a command
// ---------------------------------------------------------------------------
static bool WaitForDriverCommand(int timeoutMs = 5000)
{
    for (int i = 0; i < timeoutMs; i++)
    {
        if (InterlockedCompareExchange(&g_shm->CmdState, KMDF_CMD_DONE, KMDF_CMD_DONE) == KMDF_CMD_DONE)
            return true;
        Sleep(1);
    }
    return false;
}

// ---------------------------------------------------------------------------
// Connect to the KMDF driver shared memory
// ---------------------------------------------------------------------------
inline void init()
{
    g_hMapping = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, KMDF_SHM_NAME_UM);
    if (!g_hMapping)
    {
        printf("[KMDF] Failed to open shared memory. Is the driver loaded?\n");
        return;
    }

    g_shm = (PKMDF_SHARED_DATA)MapViewOfFile(g_hMapping, FILE_MAP_ALL_ACCESS, 0, 0, KMDF_SHM_SIZE);
    if (!g_shm)
    {
        printf("[KMDF] MapViewOfFile failed: %lu\n", GetLastError());
        CloseHandle(g_hMapping);
        g_hMapping = nullptr;
        return;
    }

    if (g_shm->Magic != KMDF_MAGIC)
    {
        printf("[KMDF] Invalid magic: 0x%X (expected 0x%X)\n", g_shm->Magic, KMDF_MAGIC);
        UnmapViewOfFile(g_shm);
        CloseHandle(g_hMapping);
        g_shm = nullptr;
        g_hMapping = nullptr;
        return;
    }

    printf("[KMDF] Connected to driver via shared memory\n");
}

uint64_t _getBaseAddress(const wchar_t* processName, int& pid);

void attachToProcess(const int& pid);

/**
 * \brief use this function to initialize the target process
 * \param processName process name as input
 * \param baseAddress base address of the process gets returned
 * \param processID process id of the process gets returned
 */
inline void loadData(std::string& processName, uint64_t& baseAddress, int& processID)
{
    const auto name = std::wstring(processName.begin(), processName.end());

    baseAddress = _getBaseAddress(name.c_str(), processID);

    attachToProcess(processID);
}

/**
 * \brief read function — reads via KMDF kernel driver shared memory
 * \param address memory address to read from (in target process VA space)
 * \param buffer memory address to write to (local buffer)
 * \param size size of memory to read
 */
inline void _read(const void* address, void* buffer, const DWORD64 size)
{
    if (!g_shm || !address || !buffer || size == 0)
    {
        memset(buffer, 0, size);
        return;
    }

    const auto addr = reinterpret_cast<unsigned long long>(address);
    unsigned long long offset = 0;

    while (offset < size)
    {
        unsigned long long chunk = size - offset;
        if (chunk > KMDF_MAX_DLL_SIZE)
            chunk = KMDF_MAX_DLL_SIZE;

        g_shm->TargetPID     = g_targetPID;
        g_shm->OpType        = KMDF_OP_READ;
        g_shm->ReadAddress   = addr + offset;
        g_shm->ReadTotalSize = chunk;
        g_shm->DumpOffset    = 0;
        g_shm->Result        = -1;
        InterlockedExchange(&g_shm->CmdState, KMDF_CMD_READY);

        if (!WaitForDriverCommand(10000) || g_shm->Result != KMDF_OK || g_shm->DumpChunkSize <= 0)
        {
            // Read failed — zero fill the rest
            memset(static_cast<uint8_t*>(buffer) + offset, 0, size - offset);
            return;
        }

        int chunkRead = g_shm->DumpChunkSize;
        if (static_cast<unsigned long long>(chunkRead) > chunk)
            chunkRead = static_cast<int>(chunk);

        memcpy(static_cast<uint8_t*>(buffer) + offset, g_shm->DllData, chunkRead);
        offset += chunkRead;
    }
}


/**
 * \brief write function — not supported via kernel driver (UEDumper rarely writes)
 * \param address memory address to write to
 * \param buffer memory address to write from
 * \param size size of memory to write
 */
inline void _write(void* address, const void* buffer, const DWORD64 size)
{
    // Write not implemented for kernel driver — UEDumper is read-only for SDK generation
    // If live editor write support is needed, add KMDF_OP_WRITE to the driver protocol
}


/**
 * \brief gets the process base address using Toolhelp32 (works from usermode)
 * \param processName the name of the process
 * \param pid returns the process id
 * \return process base address
 */
uint64_t _getBaseAddress(const wchar_t* processName, int& pid)
{
    uint64_t baseAddress = 0;

    if (!pid)
    {
        // Get a handle to the process
        const HANDLE hProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hProcess == INVALID_HANDLE_VALUE) {
            return false;
        }

        // Iterate through the list of processes to find the one with the given filename
        PROCESSENTRY32 pe32 = { sizeof(PROCESSENTRY32) };
        if (!Process32First(hProcess, &pe32)) {
            CloseHandle(hProcess);
            return false;
        }
        while (Process32Next(hProcess, &pe32)) {
            if (wcscmp(pe32.szExeFile, processName) == 0) {
                pid = pe32.th32ProcessID;
                break;
            }
        }

        CloseHandle(hProcess);
    }

    // Get the base address of the process in memory
    if (pid != 0) {
        const HANDLE hModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (hModule != INVALID_HANDLE_VALUE) {
            MODULEENTRY32 me32 = { sizeof(MODULEENTRY32) };
            if (Module32First(hModule, &me32)) {
                baseAddress = reinterpret_cast<DWORD64>(me32.modBaseAddr);
            }
            CloseHandle(hModule);
        }
    }

    // Clean up and return

    return baseAddress;
}

/**
 * \brief stores the target PID for kernel driver reads
 * \param pid process id of the target process
 */
void attachToProcess(const int& pid)
{
    g_targetPID = pid;
    // Also open a handle for any code that still uses procHandle directly
    procHandle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
}