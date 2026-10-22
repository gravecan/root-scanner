#pragma once

#include "root_scanner.hpp"
#include <vector>
#include <string>

namespace RootScanner {

class JournalForensics {
public:
    static void ScanVolumeUsnJournal(wchar_t driveLetter, std::vector<Finding>& outFindings);
    static void ScanAllFixedDrives(std::vector<Finding>& outFindings);

private:
    static bool QueryJournalState(HANDLE hVol, USN_JOURNAL_DATA& journalData, std::vector<Finding>& outFindings);
    static void ReadDeletedFiles(HANDLE hVol, const USN_JOURNAL_DATA& journalData, std::vector<Finding>& outFindings);
};

} // namespace RootScanner
