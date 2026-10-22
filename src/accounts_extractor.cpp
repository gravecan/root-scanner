#include "accounts_extractor.hpp"
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <regex>
#include <set>
#include <cstdlib>

namespace RootScanner {

std::vector<MinecraftAccount> AccountsExtractor::ExtractMinecraftAccounts() {
    std::vector<MinecraftAccount> accounts;
    std::set<std::string> seenNames;

    const char* appdata = std::getenv("APPDATA");
    if (appdata) {
        std::filesystem::path mcAccounts = std::filesystem::path(appdata) / ".minecraft" / "launcher_accounts.json";
        if (std::filesystem::exists(mcAccounts)) {
            std::ifstream f(mcAccounts);
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

            std::regex nameRegex(R"del("name"\s*:\s*"([^"]+)")del");
            std::sregex_iterator it(content.begin(), content.end(), nameRegex);
            std::sregex_iterator end;
            while (it != end) {
                std::string name = (*it)[1].str();
                if (seenNames.find(name) == seenNames.end()) {
                    seenNames.insert(name);
                    accounts.push_back({ name, "minecraft_memory" });
                }
                ++it;
            }
        }
    }

    const char* userprofile = std::getenv("USERPROFILE");
    if (userprofile) {
        std::filesystem::path lunarAccounts = std::filesystem::path(userprofile) / ".lunarclient" / "settings" / "game" / "accounts.json";
        if (std::filesystem::exists(lunarAccounts)) {
            std::ifstream f(lunarAccounts);
            std::string content((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());

            std::regex nameRegex(R"del("username"\s*:\s*"([^"]+)")del");
            std::sregex_iterator it(content.begin(), content.end(), nameRegex);
            std::sregex_iterator end;
            while (it != end) {
                std::string name = (*it)[1].str();
                if (seenNames.find(name) == seenNames.end()) {
                    seenNames.insert(name);
                    accounts.push_back({ name, "lunar_cache" });
                }
                ++it;
            }
        }
    }

    return accounts;
}

std::vector<DiscordAccount> AccountsExtractor::ExtractDiscordAccounts() {
    std::vector<DiscordAccount> accounts;
    std::set<std::string> seenIds;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnap == INVALID_HANDLE_VALUE) return accounts;

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);

    if (Process32FirstW(hSnap, &pe32)) {
        do {
            if (_wcsicmp(pe32.szExeFile, L"Discord.exe") == 0) {
                HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
                if (hProc) {
                    uint8_t* address = nullptr;
                    MEMORY_BASIC_INFORMATION mbi;

                    while (VirtualQueryEx(hProc, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
                        if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_READONLY | PAGE_READWRITE)) && !(mbi.Protect & PAGE_GUARD)) {
                            SIZE_T toRead = std::min<SIZE_T>(mbi.RegionSize, 512 * 1024);
                            std::vector<char> buf(toRead);
                            SIZE_T bytesRead = 0;

                            if (ReadProcessMemory(hProc, mbi.BaseAddress, buf.data(), toRead, &bytesRead) && bytesRead > 0) {
                                std::string pageData(buf.data(), bytesRead);
                                std::regex userRegex(R"del("id"\s*:\s*"([0-9]{17,20})"\s*,\s*"username"\s*:\s*"([a-zA-Z0-9_\.]{2,32})")del");
                                std::sregex_iterator it(pageData.begin(), pageData.end(), userRegex);
                                std::sregex_iterator end;

                                while (it != end) {
                                    std::string id = (*it)[1].str();
                                    std::string name = (*it)[2].str();
                                    if (seenIds.find(id) == seenIds.end()) {
                                        seenIds.insert(id);
                                        accounts.push_back({ id, name, "discord_cache" });
                                    }
                                    ++it;
                                }
                            }
                        }
                        address += mbi.RegionSize;
                        if (accounts.size() >= 20 || (uintptr_t)address >= 0x7FFFFFFFFFFF) break;
                    }
                    CloseHandle(hProc);
                    if (!accounts.empty()) break;
                }
            }
        } while (Process32NextW(hSnap, &pe32));
    }
    CloseHandle(hSnap);
    return accounts;
}

} // namespace RootScanner
