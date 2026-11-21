"use strict";

class RiskAssessment {
  constructor() {
    this.signals = new Map();
  }

  add(reason, weight) {
    this.signals.set(reason, weight);
  }

  get reasons() {
    return [...this.signals.keys()];
  }

  get level() {
    const score = [...this.signals.values()].reduce((total, weight) => total + weight, 0);
    if (score >= 5) return "high";
    if (score > 0) return "caution";
    return "low";
  }
}

class WebsiteDetector {
  check(value) {
    const address = value.trim();
    const invalidAddress = "Enter a complete website address, such as https://example.com.";
    if (!address || /[\s\\]/.test(address)) throw new Error(invalidAddress);

    const hasScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(address);
    let url;
    try {
      url = new URL(hasScheme ? address : `https://${address}`);
    } catch {
      throw new Error(invalidAddress);
    }

    if (!["https:", "http:"].includes(url.protocol)) throw new Error(invalidAddress);

    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    const isIpv6 = host.startsWith("[");
    const isIpv4 = /^\d+(?:\.\d+){3}$/.test(host);
    const labels = host.split(".");
    if (!isIpv6 && (labels.length < 2 || labels.some(label => !/^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/.test(label)))) {
      throw new Error(invalidAddress);
    }

    const assessment = new RiskAssessment();
    if (url.username || url.password) {
      assessment.add("The address contains user information before the actual host. This can disguise where the link goes.", 5);
    }
    if (url.protocol === "http:") {
      assessment.add("The address uses HTTP, which does not encrypt traffic.", 1);
    }
    if (isIpv4 || isIpv6) {
      assessment.add("The link points to an IP address instead of a named website.", 2);
    }
    if (labels.some(label => label.startsWith("xn--"))) {
      assessment.add("The domain uses internationalized characters. Check for letters that resemble those in a domain you trust.", 2);
    }
    if (!isIpv4 && labels.length >= 5) {
      assessment.add("The domain has several levels of subdomains. Check who the address actually belongs to.", 1);
    }
    if (/(?:^|[.-])(?:login|verify|secure|account|wallet|support)[.-]/i.test(host)) {
      assessment.add("The hostname contains words commonly used in account or verification links. Check it against the official website.", 1);
    }

    return { assessment, host };
  }
}

class MessageDetector {
  constructor(websiteDetector) {
    this.websiteDetector = websiteDetector;
  }

  static rules = [
    [/\b(?:urgent(?:ly)?|act now|immediately|final warning|last chance|within \d+ hours?)\b/i, "The message uses urgency or a deadline to pressure you into acting.", 1],
    [/\b(?:account|service|access)\b.{0,55}\b(?:suspend(?:ed)?|locked|clos(?:ed|ure)|terminat(?:ed|ion))\b/i, "The message threatens loss of access to an account or service.", 2],
    [/\b(?:send|share|provide|enter|confirm|reply with|tell us|give us)\b.{0,55}\b(?:password|pin|otp|one[- ]time (?:code|password)|verification code|seed phrase|recovery phrase)\b/i, "The message asks for a password, private code, or recovery phrase.", 5],
    [/\b(?:pay|send|buy|purchase|transfer)\b.{0,70}\b(?:gift cards?|wire transfer|bitcoin|crypto(?:currency)?)\b/i, "The message requests payment through a method commonly used in scams.", 3],
    [/\b(?:you(?:'ve| have) won|you won|claim (?:your|a) prize|lottery winner)\b/i, "The message claims you won a prize or asks you to claim one.", 2],
    [/\b(?:upfront fee|processing fee|release fee|guaranteed returns?|double your money)\b/i, "The message promises unusual returns or mentions a fee to release money or a prize.", 2],
  ];

  check(value) {
    const message = value.trim().normalize("NFKC").replace(/[‘’]/g, "'").replace(/\s+/g, " ");
    if (!message) throw new Error("Paste a message to check it.");

    const assessment = new RiskAssessment();
    for (const [pattern, reason, weight] of MessageDetector.rules) {
      if (pattern.test(message)) assessment.add(reason, weight);
    }

    for (const match of message.matchAll(/(?:https?:\/\/|\bwww\.)[^\s<>"']+/gi)) {
      const address = match[0].replace(/[),.!?;\]}]+$/, "");
      let link;
      try {
        link = this.websiteDetector.check(address);
      } catch {
        continue;
      }
      if (link.assessment.level === "low") continue;
      const weight = link.assessment.level === "high" ? 5 : 1;
      for (const reason of link.assessment.reasons) assessment.add(reason, weight);
    }

    return { assessment };
  }
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = { MessageDetector, WebsiteDetector };
}
