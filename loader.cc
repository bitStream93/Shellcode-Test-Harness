#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <string>
#include <vector>
#include <windows.h>
#include <winternl.h>

using namespace std;

struct Config {
	string payloadPath = "payload.bin";
	string targetDll = "mscoree.dll";
	bool   modeScan = false;
} g_Config;

static BYTE  g_OrigDbgBytes[14];
static void* g_DbgAddr = nullptr;

void PrintHexDump(const void* data, const size_t size) {
	if (!data || size == 0) return;
	const auto* p = static_cast<const unsigned char *> (data);

	for (size_t i = 0; i < size; i += 16) {
		printf ("    0x%p: ", (void *)(p + i));
		for (size_t j = 0; j < 16; ++j) {
			if (i + j < size) printf ("%02x ", p[i + j]);
			else printf ("   ");
		}
		printf (" ");
		for (size_t j = 0; j < 16; ++j) {
			if (i + j < size) {
				unsigned char c = p[i + j];
				printf ("%c", (c >= 32 && c <= 126) ? c : '.');
			}
		}
		printf ("\n");
	}
}

LONG WINAPI ShellcodeExceptionHandler(const PEXCEPTION_POINTERS ex) {
	printf ("\n\033[31m[!] CRASH AT 0x%p (Code: 0x%08X)\033[0m\n",
	        ex->ExceptionRecord->ExceptionAddress,
	        static_cast<unsigned int> (ex->ExceptionRecord->ExceptionCode));

	PCONTEXT ctx = ex->ContextRecord;
#ifdef _WIN64
	printf ("RIP: %p | RAX: %p | RSP: %p\n", reinterpret_cast<void *> (ctx->Rip), reinterpret_cast<void *> (ctx->Rax),
	        reinterpret_cast<void *> (ctx->Rsp));
#else
	printf ("EIP: %p | EAX: %p | ESP: %p\n", (void *)ctx->Eip, (void *)ctx->Eax, (void *)ctx->Esp);
#endif

	printf ("\n[!] Stack Dump (RSP):\n");
	PrintHexDump (reinterpret_cast<void *> (ctx->Rsp), 64);

	printf ("\n[!] Code Dump (RIP):\n");
	PrintHexDump (reinterpret_cast<void *> (ctx->Rip), 32);

	TerminateProcess (GetCurrentProcess(), 1);
	return EXCEPTION_CONTINUE_SEARCH;
}

ULONG NTAPI hooked_DbgPrint(const PCCH Format, ...) {
	va_list args;
	va_start (args, Format);
	char buffer[1024];
	vsnprintf (buffer, sizeof(buffer), Format, args);
	va_end (args);

	if (strstr (buffer, "HEXDUMP:") != nullptr) {
		const char* startPtr = strstr (buffer, "HEXDUMP:") + 8;
		char*       endPtr = nullptr;

		const auto addr = (uintptr_t)strtoull (startPtr, &endPtr, 16);
		if (endPtr && *endPtr == ':') {
			if (const auto size = static_cast<size_t> (strtoul (endPtr + 1, nullptr, 10)); size > 0) {
				printf ("\033[33m[HEX DUMP at 0x%p (%zu bytes)]\033[0m\n", reinterpret_cast<void *> (addr), size);
				PrintHexDump (reinterpret_cast<void *> (addr), size);
				return 0;
			}
		}
	}

	printf ("\033[36m[DEBUG]\033[0m %s", buffer);
	if (buffer[strlen (buffer) - 1] != '\n') printf ("\n");
	return 0;
}
void ToggleDbgHook(const bool enable) {
	DWORD old;
	if (!g_DbgAddr) g_DbgAddr = reinterpret_cast<void *> (GetProcAddress (GetModuleHandleA ("ntdll.dll"), "DbgPrint"));
	if (!g_DbgAddr) return;

	VirtualProtect (g_DbgAddr, 14, PAGE_EXECUTE_READWRITE, &old);
	if (enable) {
		memcpy (g_OrigDbgBytes, g_DbgAddr, 14);
		BYTE       patch[14] = { 0x48, 0xB8 };
		const auto addr = reinterpret_cast<uintptr_t> (hooked_DbgPrint);
		memcpy (patch + 2, &addr, 8);
		memcpy (patch + 10, "\xFF\xE0", 2);
		memcpy (g_DbgAddr, patch, 14);
	} else { memcpy (g_DbgAddr, g_OrigDbgBytes, 14); }
	VirtualProtect (g_DbgAddr, 14, old, &old);
	FlushInstructionCache (GetCurrentProcess(), g_DbgAddr, 14);
}

void RunScanner(size_t payloadSize) {
	char sysDir[MAX_PATH];
	GetSystemDirectoryA (sysDir, MAX_PATH);
	const string     path = string (sysDir) + "\\*.dll";
	WIN32_FIND_DATAA data;
	const HANDLE     hFind = FindFirstFileA (path.c_str(), &data);
	if (hFind == INVALID_HANDLE_VALUE) return;
	printf ("\n%-30s | %-10s | %-15s\n", "DLL Name", "Text Size", "Status");
	printf ("------------------------------------------------------------\n");
	do {
		string        fullPath = string (sysDir) + "\\" + data.cFileName;
		const HMODULE hMod = LoadLibraryExA (fullPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
		if (!hMod) continue;
		const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER> (hMod);
		auto       nt = reinterpret_cast<PIMAGE_NT_HEADERS> (reinterpret_cast<BYTE *> (hMod) + dos->e_lfanew);
		const auto sec = IMAGE_FIRST_SECTION (nt);
		size_t     textSize = 0;
		for (auto i = 0; i < nt->FileHeader.NumberOfSections; i++) {
			if (strncmp (reinterpret_cast<char *> (sec[i].Name), ".text", 5) == 0) {
				textSize = sec[i].Misc.VirtualSize;
				break;
			}
		}
		auto is_compatible = true;
		if (nt->OptionalHeader.AddressOfEntryPoint == 0) { is_compatible = false; } else if (payloadSize > 0 && textSize
			< payloadSize) { is_compatible = false; } else if (nt->OptionalHeader.DllCharacteristics &
			IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY) { is_compatible = false; }
		if (is_compatible) printf ("%-30s | %-10zu | %-15s\n", data.cFileName, textSize, "Compatible");
		FreeLibrary (hMod);
	} while (FindNextFileA (hFind, &data));
	FindClose (hFind);
}

void RunLoader() {
	ifstream file (g_Config.payloadPath, ios::binary | ios::ate);
	if (!file) {
		printf ("[-] Failed to open bin.\n");
		return;
	}
	const streamsize size = file.tellg();
	vector<uint8_t>  sc (static_cast<size_t> (size));
	file.seekg (0);
	file.read (reinterpret_cast<char *> (sc.data()), size);
	const HMODULE hMod = LoadLibraryExA (g_Config.targetDll.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
	if (!hMod) {
		printf ("[-] Failed to map %s\n", g_Config.targetDll.c_str());
		return;
	}
	const auto dos = reinterpret_cast<PIMAGE_DOS_HEADER> (hMod);
	const auto nt = reinterpret_cast<PIMAGE_NT_HEADERS> (reinterpret_cast<BYTE *> (hMod) + dos->e_lfanew);
	void*      ep = reinterpret_cast<BYTE *> (hMod) + nt->OptionalHeader.AddressOfEntryPoint;
	DWORD      old;
	VirtualProtect (ep, sc.size(), PAGE_EXECUTE_READWRITE, &old);
	memcpy (ep, sc.data(), sc.size());
	AddVectoredExceptionHandler (1, ShellcodeExceptionHandler);
	ToggleDbgHook (true);
	printf ("[!] Executing at %p...\n---\n", ep);
	reinterpret_cast<void(*)()> (ep)();
}

int main(int argc, char** argv) {
	for (auto i = 1; i < argc; i++) {
		if (string arg = argv[i]; arg == "--bin") g_Config.payloadPath = argv[++i];
		else if (arg == "--dll") g_Config.targetDll = argv[++i];
		else if (arg == "--scan") g_Config.modeScan = true;
	}
	if (g_Config.modeScan) {
		size_t sz = 0;
		if (!g_Config.payloadPath.empty()) {
			if (ifstream f (g_Config.payloadPath, ios::binary | ios::ate); f) sz = static_cast<size_t> (f.tellg());
		}
		RunScanner (sz);
	} else if (!g_Config.payloadPath.empty()) { RunLoader(); } else {
		printf ("Usage: loader.exe --bin <payload.bin> [--dll <target.dll>] [--scan]\n");
	}
	return 0;
}
