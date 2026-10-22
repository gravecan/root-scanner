#pragma once

#include "root_scanner.hpp"
#include <vector>
#include <string>

namespace RootScanner {

class BytecodeAnalyzer {
public:
    static void AnalyzeClassFile(const std::vector<uint8_t>& classBytes, std::vector<Finding>& outFindings);
    static void ScanModDirectory(const std::wstring& dirPath, std::vector<Finding>& outFindings);
    static void ScanJarArchive(const std::wstring& jarPath, std::vector<Finding>& outFindings);
    static std::string DeobfuscateDoubleStruckUnicode(const std::string& input);
    static std::string DeobfuscateDelimitedString(const std::string& input);

private:
    struct ConstantPoolEntry {
        uint8_t tag;
        std::string str_val;
        uint16_t ref1;
        uint16_t ref2;
    };

    static bool ParseConstantPool(const std::vector<uint8_t>& data, size_t& offset, 
                                  std::vector<ConstantPoolEntry>& cp);
    static void CheckMixinHooks(const std::vector<ConstantPoolEntry>& cp, std::vector<Finding>& outFindings);
    static void CheckGhostClientSignatures(const std::vector<ConstantPoolEntry>& cp, std::vector<Finding>& outFindings);
    static void CheckVoraClassLoader(const std::vector<ConstantPoolEntry>& cp, std::vector<Finding>& outFindings);
};

} // namespace RootScanner
