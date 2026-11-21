"use strict";

class ScamCheckerApp {
  constructor() {
    this.tabs = [...document.querySelectorAll('[role="tab"]')];
    const websiteDetector = new WebsiteDetector();
    this.connectForm("message-panel", new MessageDetector(websiteDetector));
    this.connectForm("website-panel", websiteDetector);

    for (const tab of this.tabs) {
      tab.addEventListener("click", () => this.selectTab(tab));
      tab.addEventListener("keydown", event => this.navigateTabs(event, tab));
    }
  }

  selectTab(selectedTab) {
    for (const tab of this.tabs) {
      const selected = tab === selectedTab;
      tab.setAttribute("aria-selected", String(selected));
      tab.tabIndex = selected ? 0 : -1;
      document.getElementById(tab.getAttribute("aria-controls")).hidden = !selected;
    }
  }

  navigateTabs(event, currentTab) {
    const currentIndex = this.tabs.indexOf(currentTab);
    const lastIndex = this.tabs.length - 1;
    const nextIndex = {
      ArrowLeft: currentIndex === 0 ? lastIndex : currentIndex - 1,
      ArrowRight: currentIndex === lastIndex ? 0 : currentIndex + 1,
      Home: 0,
      End: lastIndex,
    }[event.key];
    if (!Number.isInteger(nextIndex)) return;
    event.preventDefault();
    const nextTab = this.tabs[nextIndex];
    this.selectTab(nextTab);
    nextTab.focus();
  }

  connectForm(panelId, detector) {
    const panel = document.getElementById(panelId);
    const form = panel.querySelector("form");
    const field = form.querySelector("textarea, input");
    const output = panel.querySelector(".result");

    field.addEventListener("input", () => {
      output.replaceChildren();
      delete output.dataset.level;
    });
    form.addEventListener("submit", event => {
      event.preventDefault();
      let result;
      try {
        result = detector.check(field.value);
      } catch (error) {
        this.render(output, "error", "Check your input", error.message);
        field.focus();
        return;
      }

      const { assessment, host } = result;
      const [title, advice] = {
        high: ["Strong scam warning signs", "Avoid acting on this. If it claims to be from an organization, contact that organization using details you already trust."],
        caution: ["Use caution", "Verify the sender or domain independently before clicking, paying, or sharing personal information."],
        low: ["No common warning signs found", "A scam can still pass this check. Verify the source before sharing information or making payments."],
      }[assessment.level];
      this.render(output, assessment.level, title, advice, assessment.reasons, host);
    });
  }

  render(output, level, title, advice, reasons = [], host) {
    const heading = document.createElement("h2");
    heading.textContent = title;
    const description = document.createElement("p");
    description.textContent = advice;
    const content = [heading];
    if (host) {
      const domain = document.createElement("p");
      domain.textContent = `Hostname checked: ${host}`;
      content.push(domain);
    }
    if (reasons.length) {
      const list = document.createElement("ul");
      for (const reason of reasons) {
        const item = document.createElement("li");
        item.textContent = reason;
        list.append(item);
      }
      content.push(list);
    }
    output.dataset.level = level;
    output.replaceChildren(...content, description);
  }
}

new ScamCheckerApp();
