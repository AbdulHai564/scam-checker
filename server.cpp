#include <httplib.h>
#include <ada.h>
#include <utf8proc.h>

#include <charconv>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>
#include <regex>
#include <stdexcept>
#include <string>
#include <string_view>

#include "assets.h"
#include "detector.h"

namespace {

using namespace std::literals;
using scam::Level;

constexpr std::size_t messageLimit = 20000;
constexpr std::size_t websiteLimit = 4096;
constexpr auto invalidWebsite = "Enter a complete website address, such as https://example.com."sv;

enum class Mode { message, website };

struct Website {
    std::string hostname;
    scam::Assessment assessment;
};

struct View {
    std::string_view title;
    std::string_view advice;
    std::string_view style;
    unsigned flags{};
    std::string hostname;
};

std::string escapeHtml(std::string_view value) {
    std::string escaped;
    for (const char ch : value) {
        switch (ch) {
            case '&': escaped += "&amp;"; break;
            case '<': escaped += "&lt;"; break;
            case '>': escaped += "&gt;"; break;
            case '"': escaped += "&quot;"; break;
            case '\'': escaped += "&#39;"; break;
            default: escaped += ch; break;
        }
    }
    return escaped;
}

std::string normalizeMessage(std::string_view text) {
    utf8proc_uint8_t* data = nullptr;
    const auto size = utf8proc_map(reinterpret_cast<const utf8proc_uint8_t*>(text.data()),
        static_cast<utf8proc_ssize_t>(text.size()), &data,
        static_cast<utf8proc_option_t>(UTF8PROC_STABLE | UTF8PROC_COMPAT | UTF8PROC_COMPOSE));
    std::unique_ptr<utf8proc_uint8_t, decltype(&std::free)> buffer(data, &std::free);
    if (size < 0) throw std::invalid_argument("Use valid UTF-8 text.");

    std::string normalized;
    bool gap = false;
    for (utf8proc_ssize_t i = 0; i < size;) {
        utf8proc_int32_t codepoint = 0;
        const auto length = utf8proc_iterate(data + i, size - i, &codepoint);
        const auto category = utf8proc_category(codepoint);
        if (codepoint <= 0x20 || codepoint == 0xfeff ||
            category == UTF8PROC_CATEGORY_ZS || category == UTF8PROC_CATEGORY_ZL || category == UTF8PROC_CATEGORY_ZP) {
            gap = !normalized.empty();
        } else {
            if (gap) normalized += ' ';
            gap = false;
            if (codepoint == 0x2018 || codepoint == 0x2019) normalized += '\'';
            else normalized.append(reinterpret_cast<const char*>(data + i), static_cast<std::size_t>(length));
        }
        i += length;
    }
    return normalized;
}

std::optional<Website> checkAddress(std::string_view address) {
    constexpr auto space = " \t\n\r\v\f"sv;
    const auto first = address.find_first_not_of(space);
    if (first == std::string_view::npos) return std::nullopt;
    address = address.substr(first, address.find_last_not_of(space) - first + 1);
    if (address.size() > websiteLimit || address.find_first_of(" \t\n\r\v\f\\") != std::string_view::npos ||
        address.find('\0') != std::string_view::npos) return std::nullopt;

    static const std::regex scheme(R"(^[a-z][a-z\d+.-]*://)", std::regex::icase);
    const auto candidate = std::regex_search(address.begin(), address.end(), scheme)
        ? std::string(address) : "https://" + std::string(address);
    const auto url = ada::parse(candidate);
    if (!url || (url->get_protocol() != "https:" && url->get_protocol() != "http:")) return std::nullopt;

    std::string host(url->get_hostname());
    if (host.ends_with('.')) host.pop_back();
    static const std::regex hostname(R"([a-z\d](?:[a-z\d-]{0,61}[a-z\d])?(?:\.[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?)+)");
    if (host.size() > 253 || (!host.starts_with('[') && !std::regex_match(host, hostname))) return std::nullopt;
    const bool userInfo = !url->get_username().empty() || !url->get_password().empty();
    return Website{host, scam::checkWebsite(host, userInfo, url->get_protocol() == "http:")};
}

scam::Assessment checkMessageLinks(const std::string& message) {
    static const std::regex prefix(R"(https?://|\bwww\.)", std::regex::icase);
    unsigned linkFlags = 0;
    unsigned highRiskLinkFlags = 0;
    std::string_view remaining = message;
    std::match_results<std::string_view::const_iterator> match;
    while (std::regex_search(remaining.begin(), remaining.end(), match, prefix)) {
        remaining.remove_prefix(static_cast<std::size_t>(match.position()));
        auto end = remaining.find_first_of(" <>\"'", static_cast<std::size_t>(match.length()));
        if (end == std::string_view::npos) end = remaining.size();
        auto address = remaining.substr(0, end);
        remaining.remove_prefix(end);
        auto last = address.find_last_not_of("),.!?;}");
        if (last == std::string_view::npos) continue;
        address = address.substr(0, last + 1);
        if (address.find('[') == std::string_view::npos) {
            while (address.ends_with(']')) address.remove_suffix(1);
        }
        if (const auto website = checkAddress(address)) {
            linkFlags |= website->assessment.flags;
            if (website->assessment.level == Level::high) highRiskLinkFlags |= website->assessment.flags;
        }
    }
    return scam::checkMessage(message, linkFlags, highRiskLinkFlags);
}

View assess(Mode mode, std::string_view input) {
    scam::Assessment result;
    std::string host;
    if (mode == Mode::website) {
        if (input.size() > websiteLimit) throw std::invalid_argument(invalidWebsite.data());
        auto website = checkAddress(input);
        if (!website) throw std::invalid_argument(invalidWebsite.data());
        result = website->assessment;
        host = std::move(website->hostname);
    } else {
        if (input.size() > messageLimit) throw std::invalid_argument("Paste a shorter message (up to 20,000 UTF-8 bytes).");
        const auto text = normalizeMessage(input);
        if (text.empty()) throw std::invalid_argument("Paste a message to check it.");
        if (text.size() > messageLimit) throw std::invalid_argument("Paste a shorter message so it fits after normalization.");
        result = checkMessageLinks(text);
    }

    if (result.level == Level::high) {
        return {"Strong scam warning signs", "Avoid acting on this. Contact the claimed sender using details you already trust.",
            "high", result.flags, std::move(host)};
    }
    if (result.level == Level::caution) {
        return {"Use caution", "Verify the sender or domain independently before clicking, paying, or sharing personal information.",
            "caution", result.flags, std::move(host)};
    }
    if (mode == Mode::website) {
        return {"Couldn’t verify this website", "Verify the domain independently before entering information or making payments.",
            "low", 0, std::move(host)};
    }
    return {"Couldn’t determine from this message", "Verify the sender through a contact method you already trust before sending money or sharing private information.", "low", 0, {}};
}

std::string renderResult(const View& view) {
    std::string html = "<section class=\"result\" id=\"result\" aria-labelledby=\"result-title\" data-level=\"";
    html += view.style;
    html += "\"><h2 id=\"result-title\"><span class=\"result-symbol\" aria-hidden=\"true\">";
    html += view.style == "low" ? "?" : "!";
    html += "</span>" + escapeHtml(view.title) + "</h2>";
    if (!view.hostname.empty()) {
        html += "<p class=\"checked-host\">Hostname checked <code>" + escapeHtml(view.hostname) + "</code></p>";
    }
    if (view.flags != 0) {
        html += "<ul>";
        for (unsigned i = 0; i < 16; ++i) {
            if (view.flags & (1u << i)) html += "<li>" + escapeHtml(scam::warningReason(i)) + "</li>";
        }
        html += "</ul>";
    }
    return html + "<p>" + escapeHtml(view.advice) + "</p></section>";
}

std::string renderPage(Mode mode, std::string_view input, const View* result, bool local) {
    const bool website = mode == Mode::website;
    const auto escaped = escapeHtml(input);
    const auto field = website
        ? "<label for=\"input\">Website address</label><input id=\"input\" name=\"input\" type=\"text\" inputmode=\"url\" placeholder=\"https://example.com\" spellcheck=\"false\" autocomplete=\"off\" autocapitalize=\"none\" required maxlength=\"4096\" value=\"" + escaped + "\">"
        : "<label for=\"input\">Message text</label><textarea id=\"input\" name=\"input\" placeholder=\"Paste a text, email, or chat message here…\" spellcheck=\"false\" required maxlength=\"20000\">\n" + escaped + "</textarea>";
    const auto resultHtml = result ? renderResult(*result) : std::string{};
    const std::pair<std::string_view, std::string_view> values[] = {
        {"message-current", website ? "" : "aria-current=\"page\""},
        {"website-current", website ? "aria-current=\"page\"" : ""},
        {"action", website ? "/website" : "/message"},
        {"field", field}, {"result", resultHtml},
        {"submit", website ? "Check website" : "Check message"},
        {"privacy", local ? "Checks run on this computer. Pasted links are never opened."
                          : "Checks run on the C++ server. The app does not store submissions or open pasted links."},
    };

    std::string html;
    std::string_view source = scam::web::page;
    while (!source.empty()) {
        const auto start = source.find("{{");
        if (start == std::string_view::npos) {
            html += source;
            break;
        }
        html += source.substr(0, start);
        const auto end = source.find("}}", start + 2);
        if (end == std::string_view::npos) throw std::logic_error("Unclosed template token");
        const auto name = source.substr(start + 2, end - start - 2);
        for (const auto& [key, value] : values) {
            if (key == name) {
                html += value;
                break;
            }
        }
        source.remove_prefix(end + 2);
    }
    return html;
}

void sendPage(httplib::Response& response, Mode mode, std::string_view input, bool runCheck, bool local) {
    const View* result = nullptr;
    View view;
    if (runCheck) {
        try {
            view = assess(mode, input);
        } catch (const std::invalid_argument& error) {
            response.status = 422;
            if (mode == Mode::website ? input.size() > websiteLimit : input.size() > messageLimit) input = {};
            const std::string_view advice(error.what());
            view = {"Check your input", advice, "error", 0, {}};
            response.set_content(renderPage(mode, input, &view, local), "text/html; charset=utf-8");
            return;
        } catch (const std::regex_error&) {
            response.status = 422;
            view = {"Couldn’t finish this check", "Try a shorter excerpt or a simpler website address.", "error", 0, {}};
        }
        result = &view;
    }
    response.set_content(renderPage(mode, input, result, local), "text/html; charset=utf-8");
}

class CheckerServer {
public:
    bool run(const std::string& bind, int port) {
        const bool local = bind == "127.0.0.1" || bind == "::1" || bind == "localhost";
        server_.set_payload_max_length(256 * 1024);
        server_.set_default_headers({
            {"Cache-Control", "no-store"},
            {"Content-Security-Policy", "default-src 'none'; style-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'"},
            {"Referrer-Policy", "no-referrer"},
            {"X-Content-Type-Options", "nosniff"},
        });
        server_.Get("/styles.css", [](const auto&, auto& response) {
            response.set_content(scam::web::stylesheet, "text/css; charset=utf-8");
        });
        server_.Get("/health", [](const auto&, auto& response) {
            response.set_content("OK", "text/plain");
        });
        server_.Get("/", [local](const auto&, auto& response) {
            sendPage(response, Mode::message, "", false, local);
        });
        addMode("/message", Mode::message, "We missed you. Reschedule delivery at https://parcel.example.", local);
        addMode("/website", Mode::website, "https://aamazon.example", local);
        std::cout << "Scam Checker listening on port " << port << std::endl;
        return server_.listen(bind, port);
    }

private:
    httplib::Server server_;

    void addMode(const std::string& path, Mode mode, std::string_view example, bool local) {
        server_.Get(path, [mode, local](const auto&, auto& response) {
            sendPage(response, mode, "", false, local);
        });
        server_.Get(path + "/example", [mode, example, local](const auto&, auto& response) {
            sendPage(response, mode, example, true, local);
        });
        server_.Post(path, [mode, local](const auto& request, auto& response) {
            sendPage(response, mode, request.get_param_value("input"), true, local);
        });
    }
};

}

int main() {
    const auto* portSetting = std::getenv("PORT");
    const auto* bindSetting = std::getenv("SCAM_BIND");
    int port = 8080;
    if (portSetting) {
        const std::string_view value(portSetting);
        const auto [end, error] = std::from_chars(value.data(), value.data() + value.size(), port);
        if (error != std::errc{} || end != value.data() + value.size() || port < 1 || port > 65535) {
            std::cerr << "PORT must be between 1 and 65535.\n";
            return 1;
        }
    }
    if (!CheckerServer{}.run(bindSetting ? bindSetting : "127.0.0.1", port)) {
        std::cerr << "Could not listen. Check that the address and port are available.\n";
        return 1;
    }
}
