#include "registry_forensics.hpp"
#include <iostream>
#include <filesystem>
#include <algorithm>

namespace RootScanner {

std::string RegistryForensics::DecodeRot13(const std::string& input) {
    std::string out = input;
    for (char& c : out) {
        if (c >= 'a' && c <= 'z') {
            c = 'a' + (c - 'a' + 13) % 26;
        } else if (c >= 'A' && c <= 'Z') {
            c = 'A' + (c - 'A' + 13) % 26;
        }
    }
    return out;
}

void RegistryForensics::ScanBamEntries(std::vector<Finding>& outFindings) {
    HKEY hBamKey;
    const wchar_t* bamBasePath = L"SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, bamBasePath, 0, KEY_READ, &hBamKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t subKeyName[256];
        DWORD subKeyLen = 256;

        while (RegEnumKeyExW(hBamKey, index++, subKeyName, &subKeyLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            HKEY hUserBam;
            if (RegOpenKeyExW(hBamKey, subKeyName, 0, KEY_READ, &hUserBam) == ERROR_SUCCESS) {
                DWORD valIdx = 0;
                wchar_t valName[1024];
                DWORD valNameLen = 1024;
                DWORD valType = 0;
                uint8_t valData[256];
                DWORD valDataLen = sizeof(valData);

                while (RegEnumValueW(hUserBam, valIdx++, valName, &valNameLen, nullptr, &valType, valData, &valDataLen) == ERROR_SUCCESS) {
                    std::wstring fullPath = valName;
                    std::string lowerPath;
                    for (wchar_t wc : fullPath) lowerPath.push_back(static_cast<char>(::towlower(wc)));

                    // Check for cheat keywords
                    bool isCheat = (lowerPath.find("vape") != std::string::npos ||
                                    lowerPath.find("drip") != std::string::npos ||
                                    lowerPath.find("doomsday") != std::string::npos ||
                                    lowerPath.find("slinky") != std::string::npos ||
                                    lowerPath.find("autoclicker") != std::string::npos ||
                                    lowerPath.find("nativeinjector") != std::string::npos);

                    if (isCheat) {
                        Finding f;
                        f.category = FindingCategory::Detect;
                        f.message = "BAM Execution Artifact: " + lowerPath;
                        f.explanation = "Background Activity Moderator recorded execution of cheat executable in SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings.";
                        f.next_step = "Cross-reference binary last-run timestamp with match start time.";
                        outFindings.push_back(f);
                    }

                    // Check if file was executed from Temp/Downloads and subsequently deleted
                    if (lowerPath.find("\\temp\\") != std::string::npos ||
                        lowerPath.find("\\downloads\\") != std::string::npos ||
                        lowerPath.find("\\appdata\\local\\temp") != std::string::npos) {
                        // Extract standard dos path if begins with \Device\HarddiskVolumeX
                        std::wstring checkPath = fullPath;
                        if (checkPath.find(L"\\Device\\HarddiskVolume") == 0) {
                            size_t thirdSlash = checkPath.find(L'\\', 22);
                            if (thirdSlash != std::wstring::npos) {
                                checkPath = L"C:" + checkPath.substr(thirdSlash);
                            }
                        }
                        if (!std::filesystem::exists(checkPath)) {
                            Finding f;
                            f.category = FindingCategory::Warning;
                            f.message = "Application execution logged in Windows BAM, but file has been subsequently deleted";
                            f.explanation = "Windows BAM registry record confirms execution of binary '" + lowerPath + "' which is currently missing from disk. Indicates self-destruct or deliberate cleanup.";
                            f.next_step = "Inspect USN Change Journal for deletion record and file metadata.";
                            outFindings.push_back(f);
                        }
                    }

                    valNameLen = 1024;
                    valDataLen = sizeof(valData);
                }
                RegCloseKey(hUserBam);
            }
            subKeyLen = 256;
        }
        RegCloseKey(hBamKey);
    }
}

void RegistryForensics::ScanRunMruEntries(std::vector<Finding>& outFindings) {
    HKEY hKey;
    const wchar_t* runMruPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU";
    if (RegOpenKeyExW(HKEY_CURRENT_USER, runMruPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t valName[256];
        DWORD valNameLen = 256;
        DWORD valType = 0;
        wchar_t valData[1024];
        DWORD valDataLen = sizeof(valData);

        while (RegEnumValueW(hKey, index++, valName, &valNameLen, nullptr, &valType, reinterpret_cast<LPBYTE>(valData), &valDataLen) == ERROR_SUCCESS) {
            if (valType == REG_SZ) {
                std::wstring cmd = valData;
                std::string lowerCmd;
                for (wchar_t wc : cmd) lowerCmd.push_back(static_cast<char>(::towlower(wc)));

                if (lowerCmd.find("jcmd") != std::string::npos) {
                    Finding f;
                    f.category = FindingCategory::Detect;
                    f.message = "Win+R RunMRU Forensics: LOLBin JVMTI Agent Injection (jcmd)";
                    f.explanation = "Windows Run dialog (Win + R) history records JDK jcmd dynamic JVMTI agent loading into Java process: '" + lowerCmd + "'";
                    f.next_step = "Check Java agent DLL path and inspect process loaded modules.";
                    outFindings.push_back(f);
                } else if (lowerCmd.find("mavinject") != std::string::npos) {
                    Finding f;
                    f.category = FindingCategory::Detect;
                    f.message = "Win+R RunMRU Forensics: LOLBin Remote Injection (mavinject)";
                    f.explanation = "Windows Run dialog (Win + R) history records invocation of mavinject remote thread injection: '" + lowerCmd + "'";
                    f.next_step = "Inspect injected module path and process thread list.";
                    outFindings.push_back(f);
                } else if (lowerCmd.find("pcalua") != std::string::npos) {
                    Finding f;
                    f.category = FindingCategory::Warning;
                    f.message = "Win+R RunMRU Forensics: LOLBin Compatibility Assistant Execution (pcalua)";
                    f.explanation = "Windows Run dialog (Win + R) history records Program Compatibility Assistant execution proxy: '" + lowerCmd + "'";
                    f.next_step = "Verify forwarded execution target binary.";
                    outFindings.push_back(f);
                } else if (lowerCmd.find("certutil") != std::string::npos && lowerCmd.find("-decode") != std::string::npos) {
                    Finding f;
                    f.category = FindingCategory::Detect;
                    f.message = "Win+R RunMRU Forensics: Encoded Payload Decoding (certutil -decode)";
                    f.explanation = "Windows Run dialog (Win + R) history records certutil decoding an obfuscated/disguised payload from disk: '" + lowerCmd + "'";
                    f.next_step = "Inspect output decoded payload file in temp folder.";
                    outFindings.push_back(f);
                }
            }
            valNameLen = 256;
            valDataLen = sizeof(valData);
        }
        RegCloseKey(hKey);
    }
}

void RegistryForensics::ScanUsbSerialCom(std::vector<Finding>& outFindings) {
    HKEY hKey;
    const wchar_t* serialCommPath = L"HARDWARE\\DEVICEMAP\\SERIALCOMM";
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, serialCommPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t valName[256];
        DWORD valNameLen = 256;
        DWORD valType = 0;
        wchar_t valData[256];
        DWORD valDataLen = sizeof(valData);

        while (RegEnumValueW(hKey, index++, valName, &valNameLen, nullptr, &valType, reinterpret_cast<LPBYTE>(valData), &valDataLen) == ERROR_SUCCESS) {
            std::wstring device = valName;
            std::wstring port = valData;
            std::string sPort(port.begin(), port.end());
            std::string sDevice(device.begin(), device.end());

            Finding f;
            f.category = FindingCategory::Warning;
            f.message = "Active USB Serial COM board attached (" + sPort + ")";
            f.explanation = "Active USB Serial COM port detected (" + sPort + " -> " + sDevice + "). Often used for external Arduino/Teensy hardware mouse macros or aim assist.";
            f.next_step = "Check Device Manager under Ports (COM & LPT) and inspect connected microcontroller firmware.";
            outFindings.push_back(f);

            valNameLen = 256;
            valDataLen = sizeof(valData);
        }
        RegCloseKey(hKey);
    }
}

void RegistryForensics::ScanUserAssist(std::vector<Finding>& outFindings) {
    HKEY hKey;
    const wchar_t* userAssistPath = L"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist\\{CEBFF5CD-ACE2-4F4B-9170-DDC926C0B475}\\Count";
    if (RegOpenKeyExW(HKEY_CURRENT_USER, userAssistPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        DWORD index = 0;
        wchar_t valName[1024];
        DWORD valNameLen = 1024;
        DWORD valType = 0;
        uint8_t valData[256];
        DWORD valDataLen = sizeof(valData);

        while (RegEnumValueW(hKey, index++, valName, &valNameLen, nullptr, &valType, valData, &valDataLen) == ERROR_SUCCESS) {
            std::string encoded;
            for (DWORD i = 0; i < valNameLen; ++i) encoded.push_back(static_cast<char>(valName[i]));
            std::string decoded = DecodeRot13(encoded);
            std::string lowerDecoded = decoded;
            std::transform(lowerDecoded.begin(), lowerDecoded.end(), lowerDecoded.begin(), ::tolower);

            if (lowerDecoded.find("vape") != std::string::npos ||
                lowerDecoded.find("drip") != std::string::npos ||
                lowerDecoded.find("cheat") != std::string::npos ||
                lowerDecoded.find("clicker") != std::string::npos) {
                Finding f;
                f.category = FindingCategory::Detect;
                f.message = "UserAssist GUI Launch: " + decoded;
                f.explanation = "Explorer UserAssist history recorded GUI execution of cheat application in Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist.";
                f.next_step = "Check user session logon times and Prefetch files.";
                outFindings.push_back(f);
            }

            valNameLen = 1024;
            valDataLen = sizeof(valData);
        }
        RegCloseKey(hKey);
    }
}

void RegistryForensics::CheckServiceTampering(std::vector<Finding>& outFindings) {
    HKEY hVhdmp;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\vhdmp", 0, KEY_READ, &hVhdmp) == ERROR_SUCCESS) {
        DWORD startVal = 0;
        DWORD startSize = sizeof(startVal);
        if (RegQueryValueExW(hVhdmp, L"Start", nullptr, nullptr, reinterpret_cast<LPBYTE>(&startVal), &startSize) == ERROR_SUCCESS) {
            if (startVal == 4) {
                Finding f;
                f.category = FindingCategory::Bypass;
                f.message = "Virtual Disk Driver Disabled (vhdmp)";
                f.explanation = "Virtual Disk driver service (vhdmp) has been disabled (Start=4) to prevent VHD artifact logging. Bypass Method (Service manipulation).";
                f.next_step = "Inspect mounted drive history and service configuration timestamps.";
                outFindings.push_back(f);
            }
        }
        RegCloseKey(hVhdmp);
    }

    SC_HANDLE hSCM = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (hSCM) {
        SC_HANDLE hDPS = OpenServiceW(hSCM, L"DPS", SERVICE_QUERY_STATUS);
        if (hDPS) {
            SERVICE_STATUS_PROCESS ssp = { 0 };
            DWORD bytesNeeded = 0;
            if (QueryServiceStatusEx(hDPS, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &bytesNeeded)) {
                if (ssp.dwCurrentState == SERVICE_RUNNING) {
                    wchar_t sysDir[MAX_PATH];
                    GetSystemDirectoryW(sysDir, MAX_PATH);
                    std::wstring srudbPath = std::wstring(sysDir) + L"\\sru\\SRUDB.dat";
                    if (!std::filesystem::exists(srudbPath)) {
                        Finding f;
                        f.category = FindingCategory::Bypass;
                        f.message = "System Resource Usage Monitor Wiped (SRUDB.dat Missing)";
                        f.explanation = "System Resource Usage Monitor database (SRUDB.dat) is missing or deleted while DPS service is active. Bypass Method (Data Usage Clear).";
                        f.next_step = "Check event log for DPS stop/restart events and volume shadow copies.";
                        outFindings.push_back(f);
                    }
                }
            }
            CloseServiceHandle(hDPS);
        }
        CloseServiceHandle(hSCM);
    }
}

} // namespace RootScanner
