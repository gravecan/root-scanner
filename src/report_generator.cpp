#include "report_generator.hpp"
#include <fstream>
#include <sstream>

namespace RootScanner {

std::string ReportGenerator::CategoryToString(FindingCategory cat) {
    switch (cat) {
        case FindingCategory::Detect: return "detect";
        case FindingCategory::System: return "system";
        case FindingCategory::Bypass: return "bypass";
        case FindingCategory::Warning: return "warning";
        case FindingCategory::Suspicious: return "suspicious";
    }
    return "warning";
}

std::string ReportGenerator::EscapeJson(const std::string& str) {
    std::ostringstream ss;
    for (char c : str) {
        switch (c) {
            case '"': ss << "\\\""; break;
            case '\\': ss << "\\\\"; break;
            case '\b': ss << "\\b"; break;
            case '\f': ss << "\\f"; break;
            case '\n': ss << "\\n"; break;
            case '\r': ss << "\\r"; break;
            case '\t': ss << "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < ' ') {
                    ss << "\\u00" << std::hex << (int)c;
                } else {
                    ss << c;
                }
        }
    }
    return ss.str();
}

std::string ReportGenerator::SerializeToJson(const ScanReportData& data) {
    std::ostringstream json;
    json << "{\n";
    json << "  \"preview\": " << (data.preview ? "true" : "false") << ",\n";
    json << "  \"findings\": [\n";

    for (size_t i = 0; i < data.findings.size(); ++i) {
        const auto& f = data.findings[i];
        json << "    {\n";
        json << "      \"category\": \"" << CategoryToString(f.category) << "\",\n";
        json << "      \"message\": \"" << EscapeJson(f.message) << "\",\n";
        json << "      \"explanation\": \"" << EscapeJson(f.explanation) << "\",\n";
        json << "      \"next_step\": \"" << EscapeJson(f.next_step) << "\"\n";
        json << "    }" << (i + 1 < data.findings.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    json << "  \"minecraft_accounts\": [\n";
    for (size_t i = 0; i < data.minecraft_accounts.size(); ++i) {
        const auto& acc = data.minecraft_accounts[i];
        json << "    {\n";
        json << "      \"name\": \"" << EscapeJson(acc.name) << "\",\n";
        json << "      \"source\": \"" << EscapeJson(acc.source) << "\"\n";
        json << "    }" << (i + 1 < data.minecraft_accounts.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    json << "  \"discord_accounts\": [\n";
    for (size_t i = 0; i < data.discord_accounts.size(); ++i) {
        const auto& d = data.discord_accounts[i];
        json << "    {\n";
        json << "      \"id\": \"" << EscapeJson(d.id) << "\",\n";
        json << "      \"name\": \"" << EscapeJson(d.name) << "\",\n";
        json << "      \"source\": \"" << EscapeJson(d.source) << "\"\n";
        json << "    }" << (i + 1 < data.discord_accounts.size() ? "," : "") << "\n";
    }
    json << "  ],\n";

    json << "  \"logs\": [\n";
    for (size_t i = 0; i < data.logs.size(); ++i) {
        const auto& log = data.logs[i];
        json << "    {\n";
        json << "      \"title\": \"" << EscapeJson(log.title) << "\",\n";
        json << "      \"description\": \"" << EscapeJson(log.description) << "\",\n";
        json << "      \"status\": \"" << EscapeJson(log.status) << "\"\n";
        json << "    }" << (i + 1 < data.logs.size() ? "," : "") << "\n";
    }
    json << "  ]\n";
    json << "}";

    return json.str();
}

bool ReportGenerator::GenerateHtmlReport(const std::string& templateHtml, const ScanReportData& data, const std::string& outputPath) {
    std::string jsonPayload = SerializeToJson(data);

    std::string finalHtml = templateHtml;
    size_t placeholderPos = finalHtml.find("@@DATA@@");
    if (placeholderPos != std::string::npos) {
        finalHtml.replace(placeholderPos, 8, jsonPayload);
    }

    std::ofstream out(outputPath);
    if (!out.is_open()) return false;
    out << finalHtml;
    return true;
}

} // namespace RootScanner
