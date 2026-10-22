#include "journal_forensics.hpp"
#include <iostream>
#include <sstream>
#include <algorithm>

namespace RootScanner {

void JournalForensics::ScanAllFixedDrives(std::vector<Finding>& outFindings) {
    DWORD drives = GetLogicalDrives();
    for (int i = 0; i < 26; ++i) {
        if (drives & (1 << i)) {
            wchar_t driveLetter = L'A' + i;
            std::wstring rootPath = std::wstring(1, driveLetter) + L":\\";
            if (GetDriveTypeW(rootPath.c_str()) == DRIVE_FIXED) {
                ScanVolumeUsnJournal(driveLetter, outFindings);
            }
        }
    }
}

void JournalForensics::ScanVolumeUsnJournal(wchar_t driveLetter, std::vector<Finding>& outFindings) {
    std::wstring volPath = L"\\\\.\\" + std::wstring(1, driveLetter) + L":";
    HANDLE hVol = CreateFileW(volPath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                              nullptr, OPEN_EXISTING, 0, nullptr);
    if (hVol == INVALID_HANDLE_VALUE) {
        return;
    }

    USN_JOURNAL_DATA journalData = { 0 };
    if (QueryJournalState(hVol, journalData, outFindings)) {
        ReadDeletedFiles(hVol, journalData, outFindings);
    }

    CloseHandle(hVol);
}

bool JournalForensics::QueryJournalState(HANDLE hVol, USN_JOURNAL_DATA& journalData, std::vector<Finding>& outFindings) {
    DWORD bytesReturned = 0;
    BOOL ok = DeviceIoControl(hVol, FSCTL_QUERY_USN_JOURNAL, nullptr, 0,
                              &journalData, sizeof(journalData), &bytesReturned, nullptr);
    if (!ok) {
        DWORD err = GetLastError();
        if (err == 1179 || err == 1178) {
            Finding f;
            f.category = FindingCategory::Bypass;
            f.message = "USN Change Journal Deleted or Disabled (System Tampering)";
            f.explanation = "The NTFS USN Change Journal is disabled, in deletion progress, or was recently wiped. Used to wipe file execution and deletion traces.";
            f.next_step = "Check fsutil command execution in command line history and PowerShell logs.";
            outFindings.push_back(f);
        }
        return false;
    }
    return true;
}

void JournalForensics::ReadDeletedFiles(HANDLE hVol, const USN_JOURNAL_DATA& journalData, std::vector<Finding>& outFindings) {
    READ_USN_JOURNAL_DATA readData = { 0 };
    readData.StartUsn = (journalData.NextUsn > 0x1000000) ? (journalData.NextUsn - 0x1000000) : 0;
    readData.ReasonMask = USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME;
    readData.ReturnOnlyOnClose = FALSE;
    readData.Timeout = 0;
    readData.BytesToWaitFor = 0;
    readData.UsnJournalID = journalData.UsnJournalID;

    const DWORD bufSize = 64 * 1024;
    std::vector<uint8_t> buffer(bufSize);
    DWORD bytesReturned = 0;

    const std::vector<std::string> suspiciousCheatNames = {
        "vape", "drip", "doomsday", "koid", "slinky", "breeze", "haru", "reach",
        "autoclicker", "killaura", "aimassist", "injector", "pemapper", "cheat"
    };

    while (DeviceIoControl(hVol, FSCTL_READ_USN_JOURNAL, &readData, sizeof(readData),
                           buffer.data(), bufSize, &bytesReturned, nullptr) && bytesReturned > sizeof(USN)) {
        USN nextUsn = *reinterpret_cast<USN*>(buffer.data());
        uint8_t* pCurrent = buffer.data() + sizeof(USN);
        uint8_t* pEnd = buffer.data() + bytesReturned;

        while (pCurrent < pEnd) {
            auto record = reinterpret_cast<PUSN_RECORD>(pCurrent);
            if (record->RecordLength == 0) break;

            if (record->Reason & (USN_REASON_FILE_DELETE | USN_REASON_RENAME_OLD_NAME)) {
                std::wstring fileName(reinterpret_cast<wchar_t*>(pCurrent + record->FileNameOffset),
                                      record->FileNameLength / sizeof(wchar_t));
                std::string lowerFile;
                for (wchar_t wc : fileName) lowerFile.push_back(static_cast<char>(::towlower(wc)));

                for (const auto& cheatToken : suspiciousCheatNames) {
                    if (lowerFile.find(cheatToken) != std::string::npos) {
                        Finding f;
                        f.category = FindingCategory::Detect;
                        f.message = "Deleted Cheat File in USN Journal: " + lowerFile;
                        f.explanation = "USN Change Journal recorded deletion/rename matching cheat keyword '" + cheatToken + "': " + lowerFile;
                        f.next_step = "Check Recycle Bin and MFT records for file recovery.";
                        outFindings.push_back(f);
                        break;
                    }
                }
            }

            pCurrent += record->RecordLength;
        }

        if (readData.StartUsn == nextUsn) break;
        readData.StartUsn = nextUsn;
    }
}

} // namespace RootScanner
