#include "bytecode_analyzer.hpp"
#include <iostream>
#include <algorithm>
#include <filesystem>
#include <fstream>

namespace RootScanner {

std::string BytecodeAnalyzer::DeobfuscateDoubleStruckUnicode(const std::string& input) {
    std::string result;
    for (size_t i = 0; i < input.size();) {
        if (i + 4 <= input.size() &&
            static_cast<uint8_t>(input[i]) == 0xF0 &&
            static_cast<uint8_t>(input[i+1]) == 0x9D) {
            uint8_t b3 = static_cast<uint8_t>(input[i+2]);
            uint8_t b4 = static_cast<uint8_t>(input[i+3]);

            if (b3 == 0x94 && b4 >= 0xB8) {
                result.push_back('A' + (b4 - 0xB8));
                i += 4;
                continue;
            } else if (b3 == 0x95 && b4 <= 0xAB) {
                result.push_back('a' + (b4 - 0x92));
                i += 4;
                continue;
            }
        }
        result.push_back(input[i]);
        i++;
    }
    return result;
}

std::string BytecodeAnalyzer::DeobfuscateDelimitedString(const std::string& input) {
    std::string clean;
    for (char c : input) {
        if (c != '.' && c != '_' && c != ' ' && c != '\0' && c != '-') {
            clean.push_back(c);
        }
    }
    return clean;
}

bool BytecodeAnalyzer::ParseConstantPool(const std::vector<uint8_t>& data, size_t& offset, 
                                        std::vector<ConstantPoolEntry>& cp) {
    if (data.size() < 10) return false;
    uint32_t magic = (data[0] << 24) | (data[1] << 16) | (data[2] << 8) | data[3];
    if (magic != 0xCAFEBABE) return false;

    uint16_t cpCount = (data[8] << 8) | data[9];
    cp.resize(cpCount);
    offset = 10;

    for (uint16_t i = 1; i < cpCount; ++i) {
        if (offset >= data.size()) return false;
        uint8_t tag = data[offset++];
        cp[i].tag = tag;

        switch (tag) {
            case 1: {
                if (offset + 2 > data.size()) return false;
                uint16_t len = (data[offset] << 8) | data[offset+1];
                offset += 2;
                if (offset + len > data.size()) return false;
                cp[i].str_val = std::string(reinterpret_cast<const char*>(&data[offset]), len);
                offset += len;
                break;
            }
            case 7:
            case 8:
            case 16:
                if (offset + 2 > data.size()) return false;
                cp[i].ref1 = (data[offset] << 8) | data[offset+1];
                offset += 2;
                break;
            case 9:
            case 10:
            case 11:
            case 12:
            case 18:
                if (offset + 4 > data.size()) return false;
                cp[i].ref1 = (data[offset] << 8) | data[offset+1];
                cp[i].ref2 = (data[offset+2] << 8) | data[offset+3];
                offset += 4;
                break;
            case 3:
            case 4:
                offset += 4;
                break;
            case 5:
            case 6:
                offset += 8;
                i++;
                break;
            case 15:
                offset += 3;
                break;
            default:
                return false;
        }
    }
    return true;
}

void BytecodeAnalyzer::CheckMixinHooks(const std::vector<ConstantPoolEntry>& cp, std::vector<Finding>& outFindings) {
    bool hasMixin = false;
    bool hasCombatTarget = false;

    for (const auto& entry : cp) {
        if (entry.tag == 1) {
            if (entry.str_val.find("Lorg/spongepowered/asm/mixin/Mixin;") != std::string::npos ||
                entry.str_val.find("Lorg/spongepowered/asm/mixin/injection/Inject;") != std::string::npos) {
                hasMixin = true;
            }
            if (entry.str_val.find("attackEntity") != std::string::npos ||
                entry.str_val.find("onUpdateWalkingPlayer") != std::string::npos ||
                entry.str_val.find("reach") != std::string::npos) {
                hasCombatTarget = true;
            }
        }
    }

    if (hasMixin && hasCombatTarget) {
        Finding f;
        f.category = FindingCategory::Detect;
        f.message = "Suspicious Combat Attack Mixin Injection";
        f.explanation = "Mod injects mixins into combat-critical player methods (attackEntity/reach). Suspicious combat attack mixin injection detected in class constant pool.";
        f.next_step = "Decompile targeted mod class and examine injection handler logic.";
        outFindings.push_back(f);
    }
}

static const std::vector<std::string> g_modSignatures = {
    "-XX:+EnableDynamicAgentLoading",
    "-XX:-EnableDynamicAgentLoading",
    "-agentlib:jdwp",
    "-agentpath:",
    "-javaagent:",
    "-xx:+enabledynamicagentloading",
    ".mixins.json",
    "/agent/cH+",
    "/drip",
    "/slinky",
    "/vape",
    "Agent_OnAttach",
    "Agent_OnLoad",
    "AimAssist",
    "AimAssistHandler",
    "AutoClicker",
    "Bloom Client Embedded Runtime",
    "Bloom cheat client device authentication file detected:",
    "Detected mod ghost client: ReachAdjust / Combat backdoor",
    "Detected reach/hitbox expander logic",
    "ElypPvP artifact server / injector chain",
    "ElypPvP artifact server / injector process",
    "ElypPvP source/injector tree marker",
    "GameRendererGhostHandMixin",
    "JNIC",
    "JNIC native method obfuscator markers detected at",
    "JVMTI dynamic agent injected into javaw.exe:",
    "Java agent capability in manifest",
    "Java startup-agent reference recovered from",
    "Java_jnic_",
    "Jnic Obfuscator Functions",
    "LOLBin JVM Injection: jcmd dynamic JVMTI agent loading",
    "LagReach",
    "MinecraftClientDoAttackFriendsMixin",
    "MinecraftClientDoAttackMixin",
    "ReachAdjust",
    "Suspicious combat attack mixin injection",
    "Wtap",
    "\\bloom\\runtime",
    "_jnic",
    "agent-class",
    "agent_load",
    "agentmain",
    "aimAssistEnabled",
    "aimassist",
    "aimassisthandler",
    "anticclient",
    "autoclicker",
    "cancelvelocity",
    "cheat/fastplace",
    "cheat/velocity",
    "com/drip",
    "com/vape",
    "com/vora/agent/",
    "com/vora/agent/Boot",
    "com/vora/agent/Bridge",
    "com/vora/agent/TraceScrubber",
    "com/vora/agent/c",
    "com/vora/agent/d",
    "com/vora/agent/script/ScriptClassLoader",
    "customreach",
    "desirable-cc.mixins.json",
    "doomsday",
    "doomsdayH+",
    "drip",
    "drip.lite",
    "drip/",
    "drip/client",
    "drip_",
    "dripclient",
    "driplite",
    "elypvpinjector",
    "fastplace",
    "fastplacemodule",
    "features/velocity",
    "getExtendedReach",
    "getReachDistance",
    "grimvelocity",
    "javainjector",
    "javainjector/",
    "javainjector/Injector",
    "javainjector/PeMapper",
    "jnic-obfuscator",
    "jnic.obf",
    "jvmti.agent_load",
    "killaura",
    "loadAgent",
    "loadagent",
    "management_agent.dll",
    "managementagent",
    "mixin",
    "mixin.json",
    "module/movement/velocity",
    "modules/fastplace",
    "modules/velocity",
    "nativeinjector",
    "nativeinjector.cs",
    "packetfly",
    "pemapper",
    "pub.vape",
    "pub/vape",
    "reach",
    "reachAdjust",
    "reachDistance",
    "reachadjust",
    "reachdistance",
    "reachmodule",
    "reducevelocity",
    "slinky",
    "slinkyclient",
    "timerboost",
    "vape",
    "vape/",
    "vape/client",
    "vape_loader",
    "vapeclient",
    "velocity",
    "velocityhack",
    "velocitymodule",
    "velocityspoof",
    "vora.agent.build",
    "vora.agent.jar",
    "wtapmodule",
    "zerovelocity"
};

void BytecodeAnalyzer::CheckGhostClientSignatures(const std::vector<ConstantPoolEntry>& cp, std::vector<Finding>& outFindings) {
    for (const auto& entry : cp) {
        if (entry.tag == 1) {
            std::string s = entry.str_val;
            std::string deobf = DeobfuscateDoubleStruckUnicode(s);
            std::string clean = DeobfuscateDelimitedString(deobf);
            std::string lowerClean = clean;
            std::transform(lowerClean.begin(), lowerClean.end(), lowerClean.begin(), ::tolower);

            for (const auto& sig : g_modSignatures) {
                std::string lowerSig = sig;
                std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::tolower);
                if (lowerClean.find(lowerSig) != std::string::npos) {
                    Finding f;
                    f.category = FindingCategory::Detect;
                    f.message = "Detected Mod Ghost Signature: " + sig;
                    f.explanation = "Mod scope: constant pool in inspected mod archive matches verified signature '" + sig + "'.";
                    f.next_step = "Check mod provenance and cross-reference with player inventory.";
                    outFindings.push_back(f);
                    break;
                }
            }
        }
    }
}

void BytecodeAnalyzer::CheckVoraClassLoader(const std::vector<ConstantPoolEntry>& cp, std::vector<Finding>& outFindings) {
    bool hasClassLoader = false;
    bool hasDefineClass = false;
    bool hasVora = false;

    for (const auto& entry : cp) {
        if (entry.tag == 1) {
            if (entry.str_val.find("java/lang/ClassLoader") != std::string::npos) hasClassLoader = true;
            if (entry.str_val.find("defineClass") != std::string::npos) hasDefineClass = true;
            if (entry.str_val.find("vora") != std::string::npos || entry.str_val.find("Vora") != std::string::npos) hasVora = true;
        }
    }

    if (hasClassLoader && hasDefineClass && hasVora) {
        Finding f;
        f.category = FindingCategory::Detect;
        f.message = "Vora Dynamic Script ClassLoader";
        f.explanation = "Declared Vora script class loader, direct ClassLoader superclass, typed findClass and reachable Map.get/defineClass calls.";
        f.next_step = "Inspect in-memory dynamically generated bytecode payloads.";
        outFindings.push_back(f);
    }
}

void BytecodeAnalyzer::AnalyzeClassFile(const std::vector<uint8_t>& classBytes, std::vector<Finding>& outFindings) {
    size_t offset = 0;
    std::vector<ConstantPoolEntry> cp;
    if (ParseConstantPool(classBytes, offset, cp)) {
        CheckMixinHooks(cp, outFindings);
        CheckGhostClientSignatures(cp, outFindings);
        CheckVoraClassLoader(cp, outFindings);
    }
}

void BytecodeAnalyzer::ScanJarArchive(const std::wstring& jarPath, std::vector<Finding>& outFindings) {
    std::ifstream file(std::filesystem::path(jarPath), std::ios::binary);
    if (!file) return;

    // Read up to 8 MB of the archive
    file.seekg(0, std::ios::end);
    size_t fileSize = static_cast<size_t>(file.tellg());
    size_t readSize = std::min<size_t>(fileSize, 8ULL * 1024 * 1024);
    file.seekg(0, std::ios::beg);

    std::vector<uint8_t> buffer(readSize);
    file.read(reinterpret_cast<char*>(buffer.data()), readSize);

    std::string rawData(reinterpret_cast<const char*>(buffer.data()), buffer.size());
    std::string lowerData = rawData;
    std::transform(lowerData.begin(), lowerData.end(), lowerData.begin(), ::tolower);

    // 1. Check for Java Agent capability in MANIFEST.MF
    if (rawData.find("Agent-Class:") != std::string::npos ||
        rawData.find("Premain-Class:") != std::string::npos ||
        rawData.find("Can-Redefine-Classes: true") != std::string::npos ||
        rawData.find("Can-Retransform-Classes: true") != std::string::npos) {
        Finding f;
        f.category = FindingCategory::Warning;
        f.message = "Java Agent Capability in Manifest: " + std::filesystem::path(jarPath).filename().string();
        f.explanation = "Java agent capability declared in archive manifest (Agent-Class / Can-Retransform-Classes). Allows dynamic bytecode instrumentation.";
        f.next_step = "Verify whether this archive was supplied as a startup Java agent.";
        outFindings.push_back(f);
    }

    // 2. Check for Mixin configurations
    if (rawData.find(".mixins.json") != std::string::npos || rawData.find("desirable-cc.mixins.json") != std::string::npos) {
        Finding f;
        f.category = FindingCategory::Warning;
        f.message = "Mixin Configuration in Mod: " + std::filesystem::path(jarPath).filename().string();
        f.explanation = "Archive contains Mixin configuration mappings targeting internal Minecraft classes.";
        f.next_step = "Inspect declared mixin package and combat injection targets.";
        outFindings.push_back(f);
    }

    // 3. Scan for any embedded .class file headers (0xCAFEBABE)
    for (size_t i = 0; i + 4 <= buffer.size(); ++i) {
        if (buffer[i] == 0xCA && buffer[i+1] == 0xFE && buffer[i+2] == 0xBA && buffer[i+3] == 0xBE) {
            size_t classLen = std::min<size_t>(buffer.size() - i, 64 * 1024);
            std::vector<uint8_t> classBytes(buffer.begin() + i, buffer.begin() + i + classLen);
            AnalyzeClassFile(classBytes, outFindings);
            i += 128; // Advance past current header
        }
    }

    // 4. Scan against verified signatures catalog
    for (const auto& sig : g_modSignatures) {
        std::string lowerSig = sig;
        std::transform(lowerSig.begin(), lowerSig.end(), lowerSig.begin(), ::tolower);
        if (lowerData.find(lowerSig) != std::string::npos) {
            Finding f;
            f.category = FindingCategory::Detect;
            f.message = "Mod String Match: " + sig;
            f.explanation = "The mod archive '" + std::filesystem::path(jarPath).filename().string() + "' contains verified cheat signature string '" + sig + "'.";
            f.next_step = "Quarantine archive and review decompiled bytecode.";
            outFindings.push_back(f);
        }
    }
}

void BytecodeAnalyzer::ScanModDirectory(const std::wstring& dirPath, std::vector<Finding>& outFindings) {
    try {
        if (!std::filesystem::exists(dirPath)) return;
        for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
            if (entry.is_regular_file()) {
                std::wstring ext = entry.path().extension().wstring();
                std::transform(ext.begin(), ext.end(), ext.begin(), ::towlower);

                if (ext == L".jar" || ext == L".zip" || ext == L".litemod") {
                    ScanJarArchive(entry.path().wstring(), outFindings);
                } else if (ext == L".class") {
                    std::ifstream file(entry.path(), std::ios::binary);
                    if (file) {
                        std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                        AnalyzeClassFile(bytes, outFindings);
                    }
                }
            }
        }
    } catch (...) {}
}

} // namespace RootScanner
