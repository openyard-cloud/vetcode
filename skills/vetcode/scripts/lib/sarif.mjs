// SARIF 2.1.0 for GitHub code scanning (upload with github/codeql-action/upload-sarif).
import crypto from "node:crypto";
import { VERSION } from "./index.mjs";

const LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", info: "note" };
const SCORE = { critical: "9.5", high: "8.0", medium: "5.0", low: "2.0", info: "0.0" };
const PRECISION = { high: "high", medium: "medium", low: "low" };

export function sarif(result) {
  const rules = new Map();
  for (const f of result.findings) if (!rules.has(f.rule)) rules.set(f.rule, f);
  const ids = [...rules.keys()];
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: {
        name: "vetcode", version: VERSION, informationUri: "https://github.com/openyard-cloud/vetcode",
        rules: ids.map(id => { const f = rules.get(id); return {
          id, name: id.replace(/(^|-)(\w)/g, (_, __, c) => c.toUpperCase()), shortDescription: { text: f.title },
          fullDescription: { text: f.why }, help: { text: `${f.why}\n\nFix: ${f.fix}`, markdown: `${f.why}\n\n**Fix:** ${f.fix}` },
          defaultConfiguration: { level: LEVEL[f.severity] },
          properties: { tags: ["security", f.category], "security-severity": SCORE[f.severity], precision: PRECISION[f.confidence] || "medium" },
        }; }),
      } },
      results: result.findings.filter(f => f.line > 0).map(f => ({
        ruleId: f.rule, ruleIndex: ids.indexOf(f.rule), level: LEVEL[f.severity],
        message: { text: `${f.title}: ${f.evidence}` },
        locations: [{ physicalLocation: { artifactLocation: { uri: f.file.split(" @ ")[0], uriBaseId: "%SRCROOT%" }, region: { startLine: f.line } } }],
        partialFingerprints: { primaryLocationLineHash: crypto.createHash("sha256").update(`${f.rule}|${f.file}|${f.evidence}`).digest("hex").slice(0, 32) },
        properties: { confidence: f.confidence, category: f.category },
      })),
    }],
  };
}
