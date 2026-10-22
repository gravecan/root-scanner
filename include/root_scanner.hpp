#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstdint>

namespace RootScanner {

    enum class FindingCategory {
        Detect,     // Confirmed cheat signature / byte pattern
        System,     // System integrity / tamper indicator
        Bypass,     // Screenshare bypass attempts (SRUDB, USN wiping)
        Warning,    // Suspicious permissions, flags, or configuration
        Suspicious  // Unusual memory allocations / classloader anomalies
    };

    struct Finding {
        FindingCategory category;
        std::string message;      // Display title (e.g. "PAGE_GUARD Memory Evasion Detected")
        std::string explanation;  // Forensic explanation
        std::string next_step;    // Recommended reviewer next step
    };

    struct MinecraftAccount {
        std::string name;
        std::string source;       // "minecraft_memory", "lunar_cache"
    };

    struct DiscordAccount {
        std::string id;
        std::string name;
        std::string source;       // "discord_cache"
    };

    struct LogEntry {
        std::string title;
        std::string description;
        std::string status;       // "Clean", "Complete", "Warning"
    };

    struct ScanReportData {
        bool preview = false;
        std::vector<Finding> findings;
        std::vector<MinecraftAccount> minecraft_accounts;
        std::vector<DiscordAccount> discord_accounts;
        std::vector<LogEntry> logs;
    };

    struct ProcessTarget {
        DWORD pid;
        std::wstring process_name;
        HANDLE handle;
        bool is_64bit;
    };

} // namespace RootScanner
