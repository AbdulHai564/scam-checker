#include <algorithm>
#include <array>
#include <regex>
#include <string_view>

namespace scam {

enum Signal : unsigned {
    CredentialsInUrl, Unencrypted, IpAddress, Internationalized, Subdomains, AccountDomain,
    Urgency, AccountThreat, PrivateCode, PaymentMethod, Prize, Fee
};

constexpr std::array reasons{
    "The address contains user information before the actual host. This can disguise where the link goes.",
    "The address uses HTTP, which does not encrypt traffic.",
    "The link points to an IP address instead of a named website.",
    "The domain uses internationalized characters. Check for letters that resemble those in a domain you trust.",
    "The domain has several levels of subdomains. Check who the address actually belongs to.",
    "The hostname contains words commonly used in account or verification links. Check it against the official website.",
    "The message uses urgency or a deadline to pressure you into acting.",
    "The message threatens loss of access to an account or service.",
    "The message asks for a password, private code, or recovery phrase.",
    "The message requests payment through a method commonly used in scams.",
    "The message claims you won a prize or asks you to claim one.",
    "The message promises unusual returns or mentions a fee to release money or a prize."
};

class RiskAssessment {
public:
    void add(Signal signal, unsigned weight) {
        weights_[signal] = std::max(weights_[signal], weight);
    }

    unsigned packedResult() const {
        unsigned flags = 0;
        unsigned score = 0;
        for (unsigned i = 0; i < weights_.size(); ++i) {
            if (weights_[i] != 0) flags |= 1u << i;
            score += weights_[i];
        }
        const unsigned level = score >= 5 ? 2 : score > 0 ? 1 : 0;
        return flags | (level << 16);
    }

private:
    std::array<unsigned, reasons.size()> weights_{};
};

class WebsiteDetector {
public:
    RiskAssessment check(std::string_view host, bool hasUserInfo, bool usesHttp) const {
        RiskAssessment result;
        if (hasUserInfo) result.add(CredentialsInUrl, 5);
        if (usesHttp) result.add(Unencrypted, 1);
        const bool isIp = host.starts_with("[") ||
            host.find_first_not_of("0123456789.") == std::string_view::npos;
        if (isIp) result.add(IpAddress, 2);
        if (host.starts_with("xn--") || host.find(".xn--") != std::string_view::npos) {
            result.add(Internationalized, 2);
        }
        if (!isIp && std::count(host.begin(), host.end(), '.') >= 4) result.add(Subdomains, 1);
        static const std::regex accountWord(R"((^|[.-])(login|verify|secure|account|wallet|support)[.-])");
        if (std::regex_search(host.begin(), host.end(), accountWord)) result.add(AccountDomain, 1);
        return result;
    }
};

class MessageDetector {
public:
    RiskAssessment check(std::string_view message, unsigned linkFlags, unsigned highRiskLinkFlags) const {
        RiskAssessment result;
        for (const auto& rule : rules_) {
            if (std::regex_search(message.begin(), message.end(), rule.pattern)) {
                result.add(rule.signal, rule.weight);
            }
        }

        for (unsigned i = CredentialsInUrl; i <= AccountDomain; ++i) {
            const unsigned flag = 1u << i;
            if (linkFlags & flag) result.add(static_cast<Signal>(i), highRiskLinkFlags & flag ? 5 : 1);
        }
        return result;
    }

private:
    struct Rule {
        std::regex pattern;
        Signal signal;
        unsigned weight;
    };

    static inline const auto insensitive = std::regex::icase;
    static inline const std::array<Rule, 6> rules_{{
        {std::regex(R"(\b(?:urgent(?:ly)?|act now|immediately|final warning|last chance|within \d+ hours?)\b)", insensitive), Urgency, 1},
        {std::regex(R"(\b(?:account|service|access)\b.{0,55}\b(?:suspend(?:ed)?|locked|clos(?:ed|ure)|terminat(?:ed|ion))\b)", insensitive), AccountThreat, 2},
        {std::regex(R"(\b(?:send|share|provide|enter|confirm|reply with|tell us|give us)\b.{0,55}\b(?:password|pin|otp|one[- ]time (?:code|password)|verification code|seed phrase|recovery phrase)\b)", insensitive), PrivateCode, 5},
        {std::regex(R"(\b(?:pay|send|buy|purchase|transfer)\b.{0,70}\b(?:gift cards?|wire transfer|bitcoin|crypto(?:currency)?)\b)", insensitive), PaymentMethod, 3},
        {std::regex(R"(\b(?:you(?:'ve| have) won|you won|claim (?:your|a) prize|lottery winner)\b)", insensitive), Prize, 2},
        {std::regex(R"(\b(?:upfront fee|processing fee|release fee|guaranteed returns?|double your money)\b)", insensitive), Fee, 2},
    }};
};

}

// The browser decodes the low 16 bits as warning flags and the upper bits as the risk level.
extern "C" {
    unsigned check_website(const char* host, int hasUserInfo, int usesHttp) {
        return scam::WebsiteDetector{}.check(host, hasUserInfo != 0, usesHttp != 0).packedResult();
    }

    unsigned check_message(const char* message, unsigned linkFlags, unsigned highRiskLinkFlags) {
        return scam::MessageDetector{}.check(message, linkFlags, highRiskLinkFlags).packedResult();
    }

    const char* warning_reason(unsigned index) {
        return index < scam::reasons.size() ? scam::reasons[index] : nullptr;
    }
}
