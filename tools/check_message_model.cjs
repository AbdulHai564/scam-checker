const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const { join, resolve } = require("node:path");
const { runInNewContext } = require("node:vm");

const root = resolve(__dirname, "..");
const DetectorEngine = runInNewContext(
  readFileSync(join(root, "engine-client.js"), "utf8") + "\nDetectorEngine",
  { URL }
);

async function main() {
  const createEngine = require(join(root, "scam-engine.js"));
  const engine = new DetectorEngine(await createEngine());
  const check = (text) => engine.message(text).assessment;

  assert.match(check("We missed you. Reschedule delivery at https://parcel.example.").reasons.join(" "), /wording resembles/i);
  assert.match(check("Mum, my phone broke. This is my new number. Can you pay my rent today?").reasons.join(" "), /claiming to be family/i);
  assert.equal(check("Send us your verification code immediately.").level, "high");
  assert.equal(check("Dinner at seven? I can pick you up on the way.").level, "low");
  assert.equal(check("iam a nigerian prince and i need help").level, "caution");
  assert.equal(engine.website("aamazon.com").assessment.level, "caution");
  assert.equal(engine.website("amazon.com").assessment.level, "low");
  console.log("Message, risk-level, and website regression checks passed.");

  const [holdoutPath] = process.argv.slice(2);
  if (holdoutPath) {
    const totals = [0, 0];
    const warnings = [0, 0];
    for (const [text, label] of JSON.parse(readFileSync(holdoutPath, "utf8"))) {
      totals[label]++;
      if (check(text).level !== "low") warnings[label]++;
    }
    console.log("Held-out test", { totals, warnings });
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
