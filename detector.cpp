#include <algorithm>
#include <array>
#include <cmath>
#include <iterator>
#include <limits>
#include <regex>
#include <set>
#include <string>
#include <string_view>

#include "detector.h"
#include "message_model.h"

namespace scam {

enum Signal : unsigned {
    CredentialsInUrl, Unencrypted, IpAddress, Internationalized, Subdomains, AccountDomain, BrandLookalike,
    BrandDisguise, ShortenedLink, EncodedHostname, NonstandardPort, ExternalRedirect,
    Urgency, AccountThreat, PrivateCode, PaymentMethod, Prize, Fee, RoyalHelpRequest,
    FamilyPaymentRequest, FinancialDetailsRequest, SuspiciousWording
};

constexpr std::array reasons{
    "The address contains user information before the actual host. This can disguise where the link goes.",
    "The address uses HTTP, which does not encrypt traffic.",
    "The link points to an IP address instead of a named website.",
    "The domain uses internationalized characters. Check for letters that resemble those in a domain you trust.",
    "The domain has several levels of subdomains. Check who the address actually belongs to.",
    "The hostname contains words commonly used in account or verification links. Check it against the official website.",
    "The domain name looks like a misspelling of a well-known brand. Open the brand’s official site from a trusted bookmark or type its address yourself.",
    "The hostname contains a familiar brand domain followed by a different domain. Read the full hostname before trusting the link.",
    "This link uses a shortener. Its final destination is hidden.",
    "The hostname uses encoded characters that can make the destination harder to read.",
    "The address uses a nonstandard port for its protocol.",
    "The address contains a possible redirect to a different hostname.",
    "The message uses urgency or a deadline to pressure you into acting.",
    "The message threatens loss of access to an account or service.",
    "The message asks for a password, private code, or recovery phrase.",
    "The message requests payment through a method commonly used in scams.",
    "The message claims you won a prize or asks you to claim one.",
    "The message promises unusual returns or mentions a fee to release money or a prize.",
    "The sender claims to be royalty and asks for help. This is a common opening in scams that later ask for money or personal information.",
    "Someone claiming to be family is using a new number and asking for money. Call them on a number you already know.",
    "The sender asks for bank or card details. Check who they are and why they need the information before sharing it.",
    "The wording resembles messages in a labeled text scam collection. Verify the request through a contact method you already trust."
};
static_assert(reasons.size() <= std::numeric_limits<unsigned>::digits, "Warning flags must fit in the result.");

class RiskAssessment {
public:
    void add(Signal signal, unsigned weight) {
        weights_[signal] = std::max(weights_[signal], weight);
    }

    Assessment assess() const {
        unsigned flags = 0;
        unsigned score = 0;
        for (unsigned i = 0; i < weights_.size(); ++i) {
            if (weights_[i] != 0) flags |= 1u << i;
            if (i != SuspiciousWording) score += weights_[i];
        }
        const auto level = score >= 5 ? Level::high : flags != 0 ? Level::caution : Level::uncertain;
        return {flags, level};
    }

private:
    std::array<unsigned, reasons.size()> weights_{};
};

class WebsiteDetector {
public:
    RiskAssessment check(WebsiteAddress address) const {
        RiskAssessment result;
        const auto host = address.host;
        if (address.hasUserInfo) result.add(CredentialsInUrl, 5);
        if (address.usesHttp) result.add(Unencrypted, 1);
        if (address.encodedHost) result.add(EncodedHostname, 2);
        if (address.nonstandardPort) result.add(NonstandardPort, 1);
        if (address.possibleRedirect) result.add(ExternalRedirect, 2);
        const bool isIp = host.starts_with("[") ||
            host.find_first_not_of("0123456789.") == std::string_view::npos;
        if (isIp) result.add(IpAddress, 2);
        if (host.starts_with("xn--") || host.find(".xn--") != std::string_view::npos) {
            result.add(Internationalized, 2);
        }
        if (!isIp && std::count(host.begin(), host.end(), '.') >= 4) result.add(Subdomains, 1);
        static const std::regex accountWord(R"((^|[.-])(login|verify|secure|account|wallet|support)[.-])");
        if (std::regex_search(host.begin(), host.end(), accountWord)) result.add(AccountDomain, 1);
        if (!isIp && resemblesBrand(host)) result.add(BrandLookalike, 3);
        if (containsDisguisedBrand(host)) result.add(BrandDisguise, 5);
        if (isShortener(host)) result.add(ShortenedLink, 2);
        return result;
    }

private:
    static bool containsDisguisedBrand(std::string_view host) {
        constexpr std::array domains{"amazon.com", "amazon.co.uk", "google.com", "microsoft.com", "netflix.com", "paypal.com"};
        for (const std::string_view brand : domains) {
            if (host == brand || (host.ends_with(brand) && host[host.size() - brand.size() - 1] == '.')) {
                continue;
            }
            for (auto start = host.find(brand); start != std::string_view::npos; start = host.find(brand, start + 1)) {
                const auto end = start + brand.size();
                if ((start == 0 || host[start - 1] == '.') && end < host.size() && host[end] == '.') return true;
            }
        }
        return false;
    }

    static bool isShortener(std::string_view host) {
        constexpr std::array domains{"bit.ly", "cutt.ly", "is.gd", "lnkd.in", "ow.ly", "rb.gy", "rebrand.ly", "t.co", "tinyurl.com"};
        if (host.starts_with("www.")) host.remove_prefix(4);
        return std::find(domains.begin(), domains.end(), host) != domains.end();
    }

    static bool resemblesBrand(std::string_view host) {
        constexpr std::array<std::string_view, 5> brands{"amazon", "google", "microsoft", "netflix", "paypal"};
        const auto suffix = host.rfind('.');
        if (suffix == std::string_view::npos) return false;

        auto name = host.substr(0, suffix);
        auto separator = name.rfind('.');
        // Recognize common country-code suffixes such as co.uk and com.au.
        if (host.size() - suffix == 3 && separator != std::string_view::npos) {
            const auto suffixLabel = name.substr(separator + 1);
            if (suffixLabel == "co" || suffixLabel == "com" || suffixLabel == "net" || suffixLabel == "org") {
                name = name.substr(0, separator);
                separator = name.rfind('.');
            }
        }
        if (separator != std::string_view::npos) name.remove_prefix(separator + 1);

        return std::any_of(brands.begin(), brands.end(), [name](std::string_view brand) {
            return isSingleTypo(name, brand);
        });
    }

    static bool isSingleTypo(std::string_view name, std::string_view brand) {
        if (name.size() < brand.size()) std::swap(name, brand);
        if (name.size() > brand.size() + 1) return false;

        const auto mismatch = std::mismatch(brand.begin(), brand.end(), name.begin());
        const auto prefixLength = static_cast<std::size_t>(mismatch.first - brand.begin());
        name.remove_prefix(prefixLength);
        brand.remove_prefix(prefixLength);
        if (name.empty()) return false;
        if (name.size() > brand.size()) return name.substr(1) == brand;
        if (name.substr(1) == brand.substr(1)) return true;
        return name.size() >= 2 && name[0] == brand[1] && name[1] == brand[0] &&
            name.substr(2) == brand.substr(2);
    }
};

class MessageClassifier {
public:
    bool resemblesScam(std::string_view message) const {
        std::string normalized(message);
        for (auto& ch : normalized) {
            if (ch >= 'A' && ch <= 'Z') ch += 'a' - 'A';
        }

        static const std::regex token(R"(https?://\S+|\bwww\.\S+|[a-z]+|[0-9]+)");
        std::string previous;
        std::set<std::size_t> known;
        for (auto it = std::sregex_iterator(normalized.begin(), normalized.end(), token);
             it != std::sregex_iterator(); ++it) {
            auto word = it->str();
            if (word.starts_with("http://") || word.starts_with("https://") || word.starts_with("www.")) {
                word = "_link";
            } else if (word[0] >= '0' && word[0] <= '9') {
                word = "_number";
            } else if (word.size() > 24) {
                continue;
            }
            addFeature(known, word);
            if (!previous.empty()) addFeature(known, previous + ' ' + word);
            previous = std::move(word);
        }

        if (known.size() < 4) return false;
        double total = 0;
        for (const auto index : known) total += model::weights[index].weight;
        return model::bias + total / std::sqrt(static_cast<double>(known.size())) >= model::threshold;
    }

private:
    static void addFeature(std::set<std::size_t>& known, std::string_view term) {
        const auto end = std::end(model::weights);
        const auto match = std::lower_bound(std::begin(model::weights), end, term,
            [](const auto& entry, std::string_view text) { return entry.text < text; });
        if (match != end && match->text == term) {
            known.insert(static_cast<std::size_t>(match - std::begin(model::weights)));
        }
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

        for (unsigned i = CredentialsInUrl; i <= ExternalRedirect; ++i) {
            const unsigned flag = 1u << i;
            if (linkFlags & flag) result.add(static_cast<Signal>(i), highRiskLinkFlags & flag ? 5 : 1);
        }
        if (resemblesFamilyPaymentRequest(message)) result.add(FamilyPaymentRequest, 3);
        if (classifier_.resemblesScam(message)) result.add(SuspiciousWording, 1);
        return result;
    }

private:
    MessageClassifier classifier_;

    static bool resemblesFamilyPaymentRequest(std::string_view message) {
        static const std::regex family(R"(\b(?:mom|mum|dad|mummy|daddy|your son|your daughter)\b)", std::regex::icase);
        static const std::regex number(R"(\b(?:new|different|temporary) (?:phone |mobile )?number\b)", std::regex::icase);
        static const std::regex payment(R"(\b(?:could|can|would|will) you\b.{0,35}\b(?:pay|lend|transfer|(?:cover|send)\b.{0,24}\b(?:cash|money|funds|rent|the bill|payment))\b)", std::regex::icase);
        return std::regex_search(message.begin(), message.end(), family) &&
            std::regex_search(message.begin(), message.end(), number) &&
            std::regex_search(message.begin(), message.end(), payment);
    }
    struct Rule {
        std::regex pattern;
        Signal signal;
        unsigned weight;
    };

    static inline const auto insensitive = std::regex::icase;
    static inline const std::array<Rule, 8> rules_{{
        {std::regex(R"(\b(?:urgent(?:ly)?|act now|immediately|final warning|last chance|within \d+ hours?)\b)", insensitive), Urgency, 1},
        {std::regex(R"(\b(?:account|service|access)\b.{0,55}\b(?:suspend(?:ed)?|locked|clos(?:ed|ure)|terminat(?:ed|ion))\b)", insensitive), AccountThreat, 2},
        {std::regex(R"(\b(?:send|share|provide|enter|confirm|reply with|tell us|give us)\b.{0,55}\b(?:password|pin|otp|one[- ]time (?:code|password)|verification code|seed phrase|recovery phrase)\b)", insensitive), PrivateCode, 5},
        {std::regex(R"(\b(?:pay|send|buy|purchase|transfer)\b.{0,70}\b(?:gift cards?|wire transfer|bitcoin|crypto(?:currency)?)\b)", insensitive), PaymentMethod, 3},
        {std::regex(R"(\b(?:you(?:'ve| have) won|you won|claim (?:your|a) prize|lottery winner)\b)", insensitive), Prize, 2},
        {std::regex(R"(\b(?:upfront fee|processing fee|release fee|guaranteed returns?|double your money)\b)", insensitive), Fee, 2},
        {std::regex(R"(\b(?:i am|i'm|iam) (?:a |an |the )?(?:[a-z]+ ){0,2}(?:prince|princess|king|queen|royal heir)(?:[,;.!] *| +)(?:and )?(?:i )?(?:urgently )?(?:need (?:your )?(?:help|assistance)|am asking for (?:your )?help|ask for (?:your )?help)\b)", insensitive), RoyalHelpRequest, 3},
        {std::regex(R"((?:\b(?:can|could|may) (?:i|we) (?:please )?(?:have|get)|\b(?:can|could|would) you (?:please )?(?:send|share|provide|confirm)(?: me| us| with me| with us)?|(?:^|[.!?] )\s*(?:please )?(?:send|share|provide|confirm|enter)(?: me| us| with me| with us)?) (?:your|you|the) (?:bank (?:account )?(?:details|information|number)|(?:bank )?account and routing numbers?|(?:credit |debit )?card (?:details|number)|routing number|iban)\b)", insensitive), FinancialDetailsRequest, 3},
    }};
};

Assessment checkWebsite(WebsiteAddress address) {
    return WebsiteDetector{}.check(address).assess();
}

Assessment checkMessage(std::string_view message, unsigned linkFlags, unsigned highRiskLinkFlags) {
    return MessageDetector{}.check(message, linkFlags, highRiskLinkFlags).assess();
}

std::string_view warningReason(unsigned index) {
    return index < reasons.size() ? reasons[index] : "";
}

}
