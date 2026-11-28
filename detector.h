#pragma once

#include <string_view>

namespace scam {

enum class Level { uncertain, caution, high };

struct Assessment {
    unsigned flags{};
    Level level{Level::uncertain};
};

Assessment checkWebsite(std::string_view host, bool hasUserInfo, bool usesHttp);
Assessment checkMessage(std::string_view message, unsigned linkFlags, unsigned highRiskLinkFlags);
std::string_view warningReason(unsigned index);

}
