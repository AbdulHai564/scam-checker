"use strict";

class DetectorEngine {
  constructor(module) {
    this.module = module;
  }

  parseWebsite(value) {
    const address = value.trim();
    if (!address || /[\s\\]/.test(address)) return null;
    const hasScheme = /^[a-z][a-z\d+.-]*:\/\//i.test(address);
    let url;
    try {
      url = new URL(hasScheme ? address : "https://" + address);
    } catch {
      return null;
    }
    if (!["https:", "http:"].includes(url.protocol)) return null;

    const host = url.hostname.toLowerCase().replace(/\.$/, "");
    const labels = host.split(".");
    const validLabel = /^[a-z\d](?:[a-z\d-]{0,61}[a-z\d])?$/;
    if (!host.startsWith("[") && (labels.length < 2 || !labels.every(label => validLabel.test(label)))) {
      return null;
    }
    const packed = this.module.ccall("check_website", "number", ["string", "number", "number"],
      [host, Number(Boolean(url.username || url.password)), Number(url.protocol === "http:")]);
    return { host, packed };
  }

  website(value) {
    const link = this.parseWebsite(value);
    if (!link) throw new Error("Enter a complete website address, such as https://example.com.");
    return { host: link.host, assessment: this.decode(link.packed) };
  }

  message(value) {
    const message = value.trim().normalize("NFKC").replace(/[‘’]/g, "'").replace(/\s+/g, " ");
    if (!message) throw new Error("Paste a message to check it.");
    let linkFlags = 0;
    let highRiskLinkFlags = 0;
    for (const match of message.matchAll(/(?:https?:\/\/|\bwww\.)[^\s<>"']+/gi)) {
      const address = match[0].replace(/[),.!?;}]+$/, "");
      const link = this.parseWebsite(address.includes("[") ? address : address.replace(/\]+$/, ""));
      if (!link) continue;
      const flags = link.packed & 0xffff;
      linkFlags |= flags;
      if (link.packed >>> 16 === 2) highRiskLinkFlags |= flags;
    }
    const packed = this.module.ccall("check_message", "number", ["string", "number", "number"],
      [message.replace(/\0/g, " "), linkFlags, highRiskLinkFlags]);
    return { assessment: this.decode(packed) };
  }

  decode(packed) {
    const reasons = [];
    for (let index = 0; index < 16; index++) {
      if (packed & (1 << index)) {
        reasons.push(this.module.ccall("warning_reason", "string", ["number"], [index]));
      }
    }
    return { level: ["low", "caution", "high"][packed >>> 16], reasons };
  }
}
