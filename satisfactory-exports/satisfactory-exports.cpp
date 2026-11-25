#pragma comment(lib, "psapi.lib")
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <string>
#include <vector>

static HANDLE g_proc;
#define RPM(addr, buf, size) (ReadProcessMemory(g_proc, (LPCVOID)(addr), (buf), (size), nullptr))

static std::string s_nm(const char* m) {
	if (m[0] != '?' || m[1] == '?') return m;//ignore mangled msvc slop
	std::vector<std::string> p;
	for (const char* q = m + 1, *e; *q && (e = strchr(q, '@')); q = e + 1) {
		p.emplace_back(q, e - q);
		if (e[1] == '@' || !e[1]) break;//stop at @@ or eos
	}
	std::string out;
	for (size_t i = p.size(); i--;) out += p[i] + (i ? "::" : "");//reverse order
	return out.empty() ? m : out;
}

void d_ex(uintptr_t base, const std::vector<std::string>& filters) {
	IMAGE_DOS_HEADER dos;
	IMAGE_NT_HEADERS64 nt;
	if (!RPM(base, &dos, sizeof dos) || !RPM(base + dos.e_lfanew, &nt, sizeof nt)) return;
	auto dd = nt.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
	if (!dd.VirtualAddress || !dd.Size) return;//no exports
	std::vector<BYTE> b(dd.Size);
	if (!RPM(base + dd.VirtualAddress, b.data(), b.size())) return;
	auto at = [&](DWORD rva, size_t len) -> BYTE* {//null if out of export section
		DWORD off = rva - dd.VirtualAddress;
		return (rva >= dd.VirtualAddress && off + len <= b.size()) ? b.data() + off : nullptr;
		};
	auto ed = (IMAGE_EXPORT_DIRECTORY*)b.data();
	auto names = (DWORD*)at(ed->AddressOfNames, ed->NumberOfNames * 4);//name rvas
	auto ords = (WORD*)at(ed->AddressOfNameOrdinals, ed->NumberOfNames * 2);//name to func index
	auto funcs = (DWORD*)at(ed->AddressOfFunctions, ed->NumberOfFunctions * 4);//func rvas
	if (!names || !ords || !funcs) return;
	for (DWORD i = 0; i < ed->NumberOfNames; ++i) {
		auto mangled = (const char*)at(names[i], 1);
		if (!mangled) continue;
		DWORD rva = funcs[ords[i]];
		if (rva >= dd.VirtualAddress && rva < dd.VirtualAddress + dd.Size) continue;//forward export
		bool match = filters.empty();//dump all if no filter
		for (auto& f : filters) if (strstr(mangled, f.c_str())) { match = true; break; }
		if (match) printf("%s -> 0x%08X (RVA)\n", s_nm(mangled).c_str(), rva);
	}
}

int main(int argc, char** argv) {//ignore 'uses 33332 bytes of stack space' warning
	if (argc < 2) return puts("bad args"), 1; //usage -> pid [filter ...]
	g_proc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, strtoul(argv[1], nullptr, 10));
	HMODULE modul[4096];//warning caused by this
	DWORD needed;
	if (!g_proc || !EnumProcessModulesEx(g_proc, modul, sizeof modul, &needed, LIST_MODULES_64BIT)) return puts("failed openproc"), 1;
	std::vector<std::string> filters(argv + 2, argv + argc);
	for (DWORD i = 0; i < min(needed, sizeof modul) / sizeof(HMODULE); ++i) {
		wchar_t path[MAX_PATH];
		if (GetModuleFileNameExW(g_proc, modul[i], path, MAX_PATH) && wcsstr(path, L"-Win64-Shipping.dll")) d_ex((uintptr_t)modul[i], filters);
	}
}