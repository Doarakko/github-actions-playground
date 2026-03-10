// @ts-check

/**
 * Parse Trivy JSON output and build Slack Block Kit payload.
 *
 * @param {object} params
 * @param {object} params.context
 * @param {object} params.core
 * @returns {string|undefined} JSON-stringified Slack payload, or undefined if no vulnerabilities
 */
module.exports = ({ context, core }) => {
  const severityOrder = ["CRITICAL", "HIGH", "MEDIUM", "LOW"];
  const trivyResultJson = process.env.TRIVY_RESULT_JSON || "{}";
  const filterStr = (process.env.SEVERITY_FILTER || "CRITICAL,HIGH")
    .toUpperCase()
    .split(",")
    .map((s) => s.trim());

  let trivyResult;
  try {
    trivyResult = JSON.parse(trivyResultJson);
  } catch (e) {
    core.setFailed(`Failed to parse Trivy JSON: ${e.message}`);
    return;
  }

  // --------------- Extract vulnerabilities ---------------
  const allVulns = [];
  const results = trivyResult.Results || [];
  for (const result of results) {
    const target = result.Target || "unknown";
    const vulns = result.Vulnerabilities || [];
    for (const v of vulns) {
      const sev = (v.Severity || "UNKNOWN").toUpperCase();
      if (!filterStr.includes(sev)) continue;
      allVulns.push({
        target,
        id: v.VulnerabilityID || "N/A",
        pkg: v.PkgName || "unknown",
        installedVersion: v.InstalledVersion || "",
        fixedVersion: v.FixedVersion || "",
        severity: sev,
        title: v.Title || v.Description || "No description",
        url: v.PrimaryURL || "",
      });
    }
  }

  if (allVulns.length === 0) {
    core.info("No vulnerabilities found for the specified severity filter.");
    return;
  }

  core.setOutput("has_vulns", "true");

  // --------------- Build Slack message ---------------
  const severityEmoji = {
    CRITICAL: "\u{1F534}",
    HIGH: "\u{1F7E0}",
    MEDIUM: "\u{1F7E1}",
    LOW: "\u{1F535}",
  };

  const repoUrl = `https://github.com/${context.repo.owner}/${context.repo.repo}`;
  const runUrl = `${context.serverUrl}/${context.repo.owner}/${context.repo.repo}/actions/runs/${context.runId}`;

  // Group by severity
  const grouped = {};
  for (const v of allVulns) {
    if (!grouped[v.severity]) grouped[v.severity] = [];
    grouped[v.severity].push(v);
  }

  const countSummary = severityOrder
    .filter((sev) => grouped[sev])
    .map(
      (sev) =>
        `${severityEmoji[sev] || "\u26AA"} ${sev}: ${grouped[sev].length}`,
    )
    .join("  |  ");

  const formatVuln = (v) => {
    const emoji = severityEmoji[v.severity] || "\u26AA";
    const urlLabel = v.url ? `<${v.url}|${v.id}>` : v.id;
    const fixed = v.fixedVersion ? ` → ${v.fixedVersion}` : "";
    const truncatedTitle =
      v.title.length > 80 ? `${v.title.substring(0, 77)}...` : v.title;
    return `${emoji} *[${v.severity}]* ${urlLabel} \`${v.pkg}@${v.installedVersion}${fixed}\` - ${truncatedTitle}`;
  };

  const mention = (process.env.MENTION || "").trim();

  const payload = {
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `\u{1F6E1}\uFE0F Trivy Security Scan (${allVulns.length})`,
        },
      },
      ...(mention
        ? [
            {
              type: "section",
              text: {
                type: "mrkdwn",
                text: mention,
              },
            },
          ]
        : []),
      {
        type: "section",
        text: {
          type: "mrkdwn",
          text: `*Repo:* <${repoUrl}|${context.repo.owner}/${context.repo.repo}>\n*Filter:* ${filterStr.join(",")}\n*Summary:* ${countSummary}\n*Action:* <${runUrl}|View Run>`,
        },
      },
      ...severityOrder
        .filter((sev) => grouped[sev])
        .flatMap((sev) => {
          const lines = grouped[sev].map(formatVuln);
          // Split into multiple section blocks to stay under Slack's 3000 char limit
          const chunks = [];
          let current = "";
          for (const line of lines) {
            const next = current ? `${current}\n${line}` : line;
            if (next.length > 2900 && current) {
              chunks.push(current);
              current = line;
            } else {
              current = next;
            }
          }
          if (current) chunks.push(current);
          return [
            { type: "divider" },
            ...chunks.map((chunk) => ({
              type: "section",
              text: { type: "mrkdwn", text: chunk },
            })),
          ];
        }),
    ],
  };

  return JSON.stringify(payload);
};
