#pragma once

#include "root_scanner.hpp"
#include <vector>

namespace RootScanner {

class AccountsExtractor {
public:
    static std::vector<MinecraftAccount> ExtractMinecraftAccounts();
    static std::vector<DiscordAccount> ExtractDiscordAccounts();
};

} // namespace RootScanner
