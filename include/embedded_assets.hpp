#pragma once

#include <string>
#include <cstdint>
#include <cstddef>

extern "C" {
    extern const char _binary_ui_index_html_start[];
    extern const char _binary_ui_index_html_end[];

    extern const char _binary_ui_prebaked_report_html_start[];
    extern const char _binary_ui_prebaked_report_html_end[];

    extern const char _binary_WebView2Loader_dll_start[];
    extern const char _binary_WebView2Loader_dll_end[];

    extern const char _binary_dumped_resources_10_302_1033_bin_start[];
    extern const char _binary_dumped_resources_10_302_1033_bin_end[];
}

namespace RootScanner {

    inline std::string GetEmbeddedWindowHtml() {
        return std::string(_binary_ui_index_html_start, _binary_ui_index_html_end - _binary_ui_index_html_start);
    }

    inline std::string GetEmbeddedReportTemplate() {
        return std::string(_binary_ui_prebaked_report_html_start, _binary_ui_prebaked_report_html_end - _binary_ui_prebaked_report_html_start);
    }

    inline const uint8_t* GetEmbeddedWebView2Loader(size_t& outSize) {
        outSize = _binary_WebView2Loader_dll_end - _binary_WebView2Loader_dll_start;
        return reinterpret_cast<const uint8_t*>(_binary_WebView2Loader_dll_start);
    }

} // namespace RootScanner
