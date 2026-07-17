import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";

const shortDisplayName = ["Mission", "Weave"].join("");
const shortMachineName = ["mission", "weave"].join("");

const vocabularyRules = [
  {
    label: "retired acronym",
    pattern: new RegExp(`\\b${["AW", "GP"].join("")}\\b`, "iu"),
  },
  {
    label: "retired expanded name",
    pattern: new RegExp(
      `\\b${["Agent", "Workgroup", "Protocol"].join("[\\s_-]+")}\\b`,
      "iu",
    ),
  },
  {
    label: "incomplete product name",
    pattern: new RegExp(`${shortDisplayName}(?!Protocol)`, "u"),
  },
  {
    label: "incomplete machine identifier",
    pattern: new RegExp(`${shortMachineName}(?!protocol)`, "u"),
  },
  {
    label: "retired decision-record shorthand",
    pattern: new RegExp(`\\b${["A", "DR"].join("")}s?\\b`, "iu"),
  },
  {
    label: "retired decision-record directory",
    pattern: new RegExp(["docs", ["a", "dr"].join("")].join("[/\\\\]+"), "iu"),
  },
  {
    label: "retired decision-record phrase",
    pattern: new RegExp(
      `\\b${["architecture", "decision", "record"].join("[\\s_-]+")}s?\\b`,
      "iu",
    ),
  },
];

const forbiddenTrackedPaths = [
  /^node_modules(?:\/|$)/u,
  /^(?:dist|\.astro)(?:\/|$)/u,
  /(?:^|\/)\.DS_Store$/u,
];

const trackedFiles = execFileSync("git", ["ls-files", "-z"])
  .toString("utf8")
  .split("\0")
  .filter(Boolean);

const failures = [];

function inspect(label, value) {
  String(value)
    .split(/\r?\n/u)
    .forEach((line, index) => {
      for (const rule of vocabularyRules) {
        if (rule.pattern.test(line)) {
          failures.push(`${label}:${index + 1}: ${rule.label}`);
        }
      }
    });
}

for (const file of trackedFiles) {
  if (forbiddenTrackedPaths.some((pattern) => pattern.test(file))) {
    failures.push(`path:${file}: generated or local-only content is tracked`);
  }

  inspect(`path:${file}`, file);
  const contents = readFileSync(file);
  if (!contents.includes(0)) {
    inspect(file, contents.toString("utf8"));
  }
}

if (failures.length > 0) {
  console.error("Repository policy violations:");
  for (const failure of failures) {
    console.error(`  ${failure}`);
  }
  process.exit(1);
}

console.log(
  `Repository policy passed for ${trackedFiles.length} tracked files.`,
);
