// @ts-check

/**
 * Fetch Dependabot alerts, filter by severity/ignore list, and build Slack Block Kit payload.
 *
 * @param {object} params
 * @param {import("@octokit/rest").Octokit} params.github
 * @param {object} params.context
 * @param {object} params.core
 * @returns {Promise<string|undefined>} JSON-stringified Slack payload, or undefined if no alerts
 */
module.exports = async ({ github, context, core }) => {
  const severityOrder = ["critical", "high", "medium", "low"];
  const filterStr = (process.env.SEVERITY_FILTER || "all").toLowerCase();
  const allowedSeverities =
    filterStr === "all"
      ? severityOrder
      : filterStr.split(",").map((s) => s.trim().toLowerCase());

  // --------------- Load ignore list ---------------
  const ignoredAlerts = [];
  try {
    const ignoreData = JSON.parse(process.env.IGNORE_LIST_JSON || "{}");
    const entries = ignoreData.ignored_alerts || [];
    for (const entry of entries) {
      if (!entry.id || !entry.reason) {
        core.setFailed(
          `Ignore list entry requires both id and reason: ${JSON.stringify(entry)}`,
        );
        return;
      }
      ignoredAlerts.push(String(entry.id));
    }
  } catch (e) {
    core.setFailed(`Failed to parse ignore list JSON: ${e.message}`);
    return;
  }

  // --------------- Fetch alerts ---------------
  let alerts = [];
  try {
    const resp = await github.rest.dependabot.listAlertsForRepo({
      owner: context.repo.owner,
      repo: context.repo.repo,
      state: "open",
      per_page: 100,
    });
    alerts = resp.data;
  } catch (e) {
    core.setFailed(`Failed to fetch Dependabot alerts: ${e.message}`);
    return;
  }

  if (alerts.length === 0) {
    core.info("No open Dependabot alerts found.");
    return;
  }

  // --------------- Filter ---------------
  const filtered = alerts.filter((a) => {
    const severity =
      a.security_vulnerability?.severity?.toLowerCase() ||
      a.security_advisory?.severity?.toLowerCase() ||
      "unknown";

    if (!allowedSeverities.includes(severity)) return false;

    const ghsaId = a.security_advisory?.ghsa_id || "";
    if (ghsaId && ignoredAlerts.includes(ghsaId)) return false;
    const cveId = a.security_advisory?.cve_id || "";
    if (cveId && ignoredAlerts.includes(cveId)) return false;
    if (ignoredAlerts.includes(String(a.number))) return false;

    return true;
  });

  if (filtered.length === 0) {
    core.info(`No alerts found for severity filter (${filterStr}).`);
    return;
  }

  core.setOutput("has_alerts", "true");

  // --------------- Build Slack message ---------------
  const severityEmoji = {
    critical: "\u{1F534}",
    high: "\u{1F7E0}",
    medium: "\u{1F7E1}",
    low: "\u{1F535}",
  };

  const repoUrl = `https://github.com/${context.repo.owner}/${context.repo.repo}`;

  // Group alerts by severity
  const grouped = {};
  for (const a of filtered) {
    const sev =
      a.security_vulnerability?.severity?.toLowerCase() ||
      a.security_advisory?.severity?.toLowerCase() ||
      "unknown";
    if (!grouped[sev]) grouped[sev] = [];
    grouped[sev].push(a);
  }

  const formatAlert = (a) => {
    const sev =
      a.security_vulnerability?.severity?.toLowerCase() ||
      a.security_advisory?.severity?.toLowerCase() ||
      "unknown";
    const emoji = severityEmoji[sev] || "\u26AA";
    const pkg = a.security_vulnerability?.package?.name || "unknown";
    const cve = a.security_advisory?.cve_id || "";
    const summary = a.security_advisory?.summary || "No summary";
    const url = a.html_url;
    const cveLabel = cve ? ` (${cve})` : "";
    return `${emoji} *[${sev.toUpperCase()}]* <${url}|#${a.number}> \`${pkg}\`${cveLabel} - ${summary}`;
  };

  const countSummary = severityOrder
    .filter((sev) => grouped[sev])
    .map(
      (sev) =>
        `${severityEmoji[sev] || "\u26AA"} ${sev}: ${grouped[sev].length}`,
    )
    .join("  |  ");

  const mention = (process.env.MENTION || "").trim();

  const payload = {
    blocks: [
      {
        type: "header",
        text: {
          type: "plain_text",
          text: `\u{1F512} Dependabot Security Alerts (${filtered.length})`,
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
          text: `*Repo:* <${repoUrl}|${context.repo.owner}/${context.repo.repo}>\n*Filter:* ${filterStr}\n*Summary:* ${countSummary}`,
        },
      },
      ...severityOrder
        .filter((sev) => grouped[sev])
        .flatMap((sev) => {
          const lines = grouped[sev].map(formatAlert);
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
