/**
 * Lightwell catalog summary → Google Sheet (+ optional Drive HTML) + Web app
 *
 * Runs on Apps Script time-driven triggers (no Mac required).
 *
 * Setup: see google-apps-script/README.md
 * Script Properties (Project settings → Script properties):
 *   AUTH_MODE          = "offline" | "service_account"   (default offline)
 *   OFFLINE_TOKEN      = <refresh token from access.redhat.com/management/api>
 *   CLIENT_ID          = <Hybrid Console SA client id>     (if service_account)
 *   CLIENT_SECRET      = <Hybrid Console SA client secret>
 *   SPREADSHEET_ID     = <Google Sheet id>                 (required)
 *   SHEET_NAME         = CatalogSummary                    (optional)
 *   DRIVE_FOLDER_ID    = <Drive folder id for HTML>        (optional)
 *   WRITE_HTML         = true|false                        (default true if folder set)
 *   WEBAPP_KEY         = optional shared secret; if set, require ?key=... on doGet
 *   CHART_DAYS         = 30                                (optional; trend window)
 */

var SSO_TOKEN_URL =
  "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/token";
var API_BASE = "https://console.redhat.com/api/content-sources/v1.0";
var ECOSYSTEMS = ["maven", "python", "npm"];
var SECURITY_LEVELS = ["validated", "remediated"];
var SHEET_HEADERS = [
  "snapshot_at",
  "ecosystem",
  "security_level",
  "packages",
  "versions",
];
var DEFAULT_CHART_DAYS = 30;
var DEFAULT_HISTORY_PAGE_SIZE = 24;
/** Singapore Time (SGT, UTC+8, no DST). */
var TZ_SGT = "Asia/Singapore";
/** Title Case — first character of each word capitalized. */
var PAGE_TITLE = "Lightwell Catalog Summary (Daily Refresh)";
var SERIES_COLORS = {
  "maven|validated": "#34d399",
  "maven|remediated": "#2dd4bf",
  "python|validated": "#60a5fa",
  "python|remediated": "#93c5fd",
  "npm|validated": "#fb923c",
  "npm|remediated": "#fbbf24",
};

function titleCase_(text) {
  return String(text || "")
    .toLowerCase()
    .replace(/(^|[\s(/_-]+)([a-z])/g, function (_, sep, ch) {
      return sep + ch.toUpperCase();
    });
}

/**
 * Web app entrypoint (Deploy → Web app → execute as Me).
 *
 *   GET /exec                 → dashboard (Sheet only; no API call)
 *   GET /exec?action=status   → same as default
 *   GET /exec?action=run      → fetch snapshot, then dashboard
 *   GET /exec?key=SECRET      → required when Script Property WEBAPP_KEY is set
 */
function doGet(e) {
  e = e || { parameter: {} };
  var params = e.parameter || {};
  var props = PropertiesService.getScriptProperties();

  var requiredKey = props.getProperty("WEBAPP_KEY");
  if (requiredKey && params.key !== requiredKey) {
    return HtmlService.createHtmlOutput(
      errorPage_("Unauthorized", "Missing or invalid <code>key</code> query parameter.")
    ).setTitle("Unauthorized");
  }

  var action = (params.action || "status").toLowerCase();
  try {
    if (action === "run") {
      runCatalogSnapshot_();
    }
    var allRows = readAllSheetRows_(props);
    var chartDays = Number(props.getProperty("CHART_DAYS") || DEFAULT_CHART_DAYS);
    if (!isFinite(chartDays) || chartDays < 1) {
      chartDays = DEFAULT_CHART_DAYS;
    }
    return HtmlService.createHtmlOutput(
      buildCatalogPage_(allRows, {
        source: "Google Apps Script Web app",
        chartDays: chartDays,
        notice:
          action === "run"
            ? "Fresh snapshot written, then dashboard refreshed from the Sheet."
            : "",
      })
    )
      .setTitle(PAGE_TITLE)
      .addMetaTag("viewport", "width=device-width, initial-scale=1");
  } catch (err) {
    Logger.log(err);
    return HtmlService.createHtmlOutput(
      errorPage_(
        "Snapshot failed",
        "<pre>" + esc_(String(err && err.message ? err.message : err)) + "</pre>"
      )
    ).setTitle("Snapshot failed");
  }
}

function runCatalogSnapshot() {
  var result = runCatalogSnapshot_();
  Logger.log(
    "Wrote %s summary rows at %s",
    result.rows.length,
    result.snapshotAt
  );
}

function runCatalogSnapshot_() {
  var props = PropertiesService.getScriptProperties();
  var token = getAccessToken_(props);
  var rows = collectSummaryRows_(token);
  var meta = appendToSheet_(props, rows);
  maybeWriteHtml_(props);
  return {
    rows: rows,
    snapshotAt: rows[0] ? rows[0][0] : "",
    sheetName: meta.sheetName,
    spreadsheetUrl: meta.spreadsheetUrl,
  };
}

/** Install 08:00 and 15:00 Asia/Singapore daily triggers (idempotent). */
function installTriggers() {
  removeTriggers_();
  ScriptApp.newTrigger("runCatalogSnapshot")
    .timeBased()
    .atHour(8)
    .nearMinute(0)
    .everyDays(1)
    .inTimezone("Asia/Singapore")
    .create();
  ScriptApp.newTrigger("runCatalogSnapshot")
    .timeBased()
    .atHour(15)
    .nearMinute(0)
    .everyDays(1)
    .inTimezone("Asia/Singapore")
    .create();
  Logger.log("Installed 08:00 and 15:00 Asia/Singapore triggers for runCatalogSnapshot");
}

function removeTriggers() {
  removeTriggers_();
  Logger.log("Removed all project triggers");
}

function removeTriggers_() {
  ScriptApp.getProjectTriggers().forEach(function (t) {
    ScriptApp.deleteTrigger(t);
  });
}

function getAccessToken_(props) {
  var mode = (props.getProperty("AUTH_MODE") || "offline").toLowerCase();
  var payload;
  if (mode === "service_account") {
    var clientId = required_(props, "CLIENT_ID");
    var clientSecret = required_(props, "CLIENT_SECRET");
    payload = {
      grant_type: "client_credentials",
      client_id: clientId,
      client_secret: clientSecret,
      scope: "api.console",
    };
  } else {
    // User offline token (rh-ee-… with Repositories viewer)
    var offline = required_(props, "OFFLINE_TOKEN");
    payload = {
      grant_type: "refresh_token",
      client_id: "rhsm-api",
      refresh_token: offline,
    };
  }

  var res = UrlFetchApp.fetch(SSO_TOKEN_URL, {
    method: "post",
    contentType: "application/x-www-form-urlencoded",
    payload: payload,
    muteHttpExceptions: true,
  });
  var code = res.getResponseCode();
  var body = res.getContentText();
  if (code < 200 || code >= 300) {
    throw new Error("SSO token HTTP " + code + ": " + body.slice(0, 500));
  }
  var json = JSON.parse(body);
  if (!json.access_token) {
    throw new Error("SSO response missing access_token: " + body.slice(0, 500));
  }
  return json.access_token;
}

function formatStampSgt_(date) {
  return Utilities.formatDate(
    date,
    TZ_SGT,
    "yyyy-MM-dd'T'HH:mm:ss'+08:00'"
  );
}

/** Display format: MMM dd, yyyy HH:mm in SGT (e.g. Nov 25, 2026 19:15). */
function formatDisplayStamp_(stampOrDate) {
  var date;
  if (Object.prototype.toString.call(stampOrDate) === "[object Date]") {
    date = stampOrDate;
  } else {
    var t = Date.parse(String(stampOrDate || ""));
    if (!isFinite(t)) {
      return String(stampOrDate || "—");
    }
    date = new Date(t);
  }
  return Utilities.formatDate(date, TZ_SGT, "MMM dd, yyyy HH:mm");
}

/** Calendar day in SGT for chart bucketing (handles legacy UTC Z stamps). */
function stampToSgtDay_(stamp) {
  var t = Date.parse(String(stamp || ""));
  if (!isFinite(t)) {
    return String(stamp || "").slice(0, 10);
  }
  return Utilities.formatDate(new Date(t), TZ_SGT, "yyyy-MM-dd");
}

function formatChartDayLabel_(day) {
  var t = Date.parse(String(day) + "T12:00:00+08:00");
  if (!isFinite(t)) {
    return String(day || "");
  }
  return Utilities.formatDate(new Date(t), TZ_SGT, "MMM dd");
}

function collectSummaryRows_(token) {
  var snapshotAt = formatStampSgt_(new Date());
  var rows = [];
  ECOSYSTEMS.forEach(function (ecosystem) {
    SECURITY_LEVELS.forEach(function (level) {
      var packages = metaCount_(token, "/lightwell/packages", {
        ecosystem: ecosystem,
        security_level: level,
        limit: "1",
        offset: "0",
      });
      var versions = metaCount_(token, "/lightwell/package_versions", {
        ecosystem: ecosystem,
        security_level: level,
        limit: "1",
        offset: "0",
      });
      rows.push([snapshotAt, ecosystem, level, packages, versions]);
    });
  });
  return rows;
}

function metaCount_(token, path, params) {
  var qs = Object.keys(params)
    .map(function (k) {
      return encodeURIComponent(k) + "=" + encodeURIComponent(params[k]);
    })
    .join("&");
  var url = API_BASE + path + "?" + qs;
  var res = UrlFetchApp.fetch(url, {
    method: "get",
    headers: {
      Authorization: "Bearer " + token,
      Accept: "application/json",
    },
    muteHttpExceptions: true,
  });
  var code = res.getResponseCode();
  var body = res.getContentText();
  if (code < 200 || code >= 300) {
    throw new Error("API HTTP " + code + " for " + url + ": " + body.slice(0, 500));
  }
  var json = JSON.parse(body);
  if (!json.meta || typeof json.meta.count !== "number") {
    throw new Error("Missing meta.count for " + url + ": " + body.slice(0, 300));
  }
  return json.meta.count;
}

function appendToSheet_(props, rows) {
  var ssId = required_(props, "SPREADSHEET_ID");
  var sheetName = props.getProperty("SHEET_NAME") || "CatalogSummary";
  var ss = SpreadsheetApp.openById(ssId);
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet) {
    sheet = ss.insertSheet(sheetName);
  }
  if (sheet.getLastRow() === 0) {
    sheet.appendRow(SHEET_HEADERS);
  } else {
    var header = sheet.getRange(1, 1, 1, SHEET_HEADERS.length).getValues()[0];
    if (String(header[0]) !== SHEET_HEADERS[0]) {
      sheet.insertRowBefore(1);
      sheet.getRange(1, 1, 1, SHEET_HEADERS.length).setValues([SHEET_HEADERS]);
    }
  }
  var startRow = sheet.getLastRow() + 1;
  // getRange(row, column, numRows, numColumns)
  sheet
    .getRange(startRow, 1, rows.length, SHEET_HEADERS.length)
    .setValues(rows);
  return {
    sheetName: sheetName,
    spreadsheetUrl: ss.getUrl(),
  };
}

function readAllSheetRows_(props) {
  var ssId = required_(props, "SPREADSHEET_ID");
  var sheetName = props.getProperty("SHEET_NAME") || "CatalogSummary";
  var ss = SpreadsheetApp.openById(ssId);
  var sheet = ss.getSheetByName(sheetName);
  if (!sheet || sheet.getLastRow() < 2) {
    return [];
  }
  var values = sheet
    .getRange(2, 1, sheet.getLastRow() - 1, SHEET_HEADERS.length)
    .getValues();
  return values.map(function (r) {
    return [
      normalizeStamp_(r[0]),
      String(r[1] || ""),
      String(r[2] || ""),
      Number(r[3]) || 0,
      Number(r[4]) || 0,
    ];
  });
}

function normalizeStamp_(value) {
  if (Object.prototype.toString.call(value) === "[object Date]" && !isNaN(value)) {
    return formatStampSgt_(value);
  }
  return String(value || "");
}

function maybeWriteHtml_(props) {
  var folderId = props.getProperty("DRIVE_FOLDER_ID");
  if (!folderId) {
    return;
  }
  var writeHtml = (props.getProperty("WRITE_HTML") || "true").toLowerCase();
  if (writeHtml === "false" || writeHtml === "0") {
    return;
  }

  var allRows = readAllSheetRows_(props);
  var chartDays = Number(props.getProperty("CHART_DAYS") || DEFAULT_CHART_DAYS);
  if (!isFinite(chartDays) || chartDays < 1) {
    chartDays = DEFAULT_CHART_DAYS;
  }
  var htmlOut = buildCatalogPage_(allRows, {
    source: "Google Sheet · Apps Script",
    chartDays: chartDays,
  });
  var folder = DriveApp.getFolderById(folderId);
  var filename = "catalog-summary.html";
  var existing = folder.getFilesByName(filename);
  if (existing.hasNext()) {
    existing.next().setContent(htmlOut);
  } else {
    folder.createFile(filename, htmlOut, MimeType.HTML);
  }
}

/**
 * Full dashboard HTML (matches lightwell_catalog_daily.py layout + 30d chart).
 * options: { source, chartDays, notice }
 */
function buildCatalogPage_(allRows, options) {
  options = options || {};
  var chartDays = options.chartDays || DEFAULT_CHART_DAYS;
  var generated = formatDisplayStamp_(new Date());

  var latestAt = "";
  allRows.forEach(function (r) {
    if (String(r[0]) > latestAt) {
      latestAt = String(r[0]);
    }
  });
  var latestDisplay = latestAt ? formatDisplayStamp_(latestAt) : "—";

  var latestRows = allRows.filter(function (r) {
    return String(r[0]) === latestAt;
  });

  function num(n) {
    return Number(n).toLocaleString("en-US");
  }

  var totalPackages = 0;
  var totalVersions = 0;
  latestRows.forEach(function (r) {
    totalPackages += Number(r[3]) || 0;
    totalVersions += Number(r[4]) || 0;
  });

  var latestBody = latestRows
    .map(function (r) {
      var level = String(r[2] || "");
      var levelClass =
        level === "validated"
          ? "badge badge-validated"
          : level === "remediated"
            ? "badge badge-remediated"
            : "badge";
      return (
        "<tr><td><span class='eco'>" +
        esc_(titleCase_(r[1])) +
        "</span></td><td><span class='" +
        levelClass +
        "'>" +
        esc_(titleCase_(level)) +
        "</span></td><td class='num'>" +
        num(r[3]) +
        "</td><td class='num'>" +
        num(r[4]) +
        "</td></tr>"
      );
    })
    .join("");
  if (!latestBody) {
    latestBody = '<tr><td colspan="4">No Rows</td></tr>';
  }

  var historyCount = allRows.length;
  var historyBody = allRows
    .slice()
    .reverse()
    .map(function (r) {
      var stamp = String(r[0]);
      var cls = stamp === latestAt ? " class='latest'" : "";
      var level = String(r[2] || "");
      var levelClass =
        level === "validated"
          ? "badge badge-validated"
          : level === "remediated"
            ? "badge badge-remediated"
            : "badge";
      return (
        "<tr" +
        cls +
        "><td class='stamp'>" +
        esc_(formatDisplayStamp_(stamp)) +
        "</td><td>" +
        esc_(titleCase_(r[1])) +
        "</td><td><span class='" +
        levelClass +
        "'>" +
        esc_(titleCase_(level)) +
        "</span></td><td class='num'>" +
        num(r[3]) +
        "</td><td class='num'>" +
        num(r[4]) +
        "</td></tr>"
      );
    })
    .join("");
  if (!historyBody) {
    historyBody = '<tr class="empty"><td colspan="5">No Rows</td></tr>';
  }

  var chart = buildChartPayload_(allRows, chartDays);
  chart.labels = chart.labels.map(formatChartDayLabel_);
  var chartJson = JSON.stringify(chart).replace(/</g, "\\u003c");
  var notice = options.notice
    ? "<div class='notice' role='status'>" + esc_(options.notice) + "</div>"
    : "";
  var chartRange = chart.labels.length
    ? esc_(chart.labels[0]) +
      " → " +
      esc_(chart.labels[chart.labels.length - 1]) +
      " · " +
      chart.labels.length +
      " Snapshot" +
      (chart.labels.length === 1 ? "" : "s")
    : "No Snapshot Data In This Window Yet — Run A Few Days Of Triggers First.";
  var trendHeading =
    "Package Trend (Last " + chartDays + " Days)";

  return (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>" +
    "<meta name='color-scheme' content='dark'/>" +
    "<title>" +
    esc_(PAGE_TITLE) +
    "</title>" +
    "<link rel='preconnect' href='https://fonts.googleapis.com'/>" +
    "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin/>" +
    "<link href='https://fonts.googleapis.com/css2?family=Sora:wght@500;600;700&family=Manrope:wght@400;500;600;700&display=swap' rel='stylesheet'/>" +
    "<script src='https://cdn.jsdelivr.net/npm/chart.js@4.4.7/dist/chart.umd.min.js'></script>" +
    "<style>" +
    catalogCss_() +
    "</style></head><body>" +
    "<div class='glow glow-a' aria-hidden='true'></div>" +
    "<div class='glow glow-b' aria-hidden='true'></div>" +
    "<main class='fade-in'>" +
    "<header class='hero'>" +
    "<div class='hero-copy'>" +
    "<p class='eyebrow'>Lightwell Network · SGT</p>" +
    "<h1>" +
    esc_(PAGE_TITLE) +
    "</h1>" +
    "<p class='sub'>Package And Version Counts From Content-Sources <code>meta.count</code>. " +
    "Latest Snapshot <strong>" +
    esc_(latestDisplay) +
    "</strong></p>" +
    "</div>" +
    "<div class='hero-actions'>" +
    "<a class='btn btn-ghost' href='?action=status'>Refresh</a>" +
    "<a class='btn btn-primary' href='?action=run'>Run Snapshot</a>" +
    "</div>" +
    "</header>" +
    notice +
    "<div class='stats'>" +
    "<article class='stat'><p class='stat-label'>Total Packages</p><p class='stat-value'>" +
    num(totalPackages) +
    "</p></article>" +
    "<article class='stat'><p class='stat-label'>Total Versions</p><p class='stat-value'>" +
    num(totalVersions) +
    "</p></article>" +
    "<article class='stat'><p class='stat-label'>History Rows</p><p class='stat-value'>" +
    num(historyCount) +
    "</p></article>" +
    "<article class='stat'><p class='stat-label'>Trend Window</p><p class='stat-value'>" +
    chartDays +
    "d</p></article>" +
    "</div>" +
    "<section class='panel'>" +
    "<div class='section-head'>" +
    "<h2>" +
    esc_(trendHeading) +
    "</h2>" +
    "<p class='chart-sub'>" +
    chartRange +
    "</p>" +
    "</div>" +
    "<div class='chart-wrap'><canvas id='catalogChart'></canvas></div>" +
    "</section>" +
    "<section class='panel'>" +
    "<h2>Latest Snapshot</h2>" +
    "<div class='table-wrap'><table><thead><tr>" +
    "<th>Ecosystem</th><th>Security Level</th>" +
    "<th class='num'>Packages</th><th class='num'>Versions</th>" +
    "</tr></thead><tbody>" +
    latestBody +
    "</tbody></table></div></section>" +
    "<section class='panel'>" +
    "<div class='section-head'>" +
    "<h2>History</h2>" +
    (historyCount
      ? "<p class='chart-sub' id='historyCountLabel'>" +
        historyCount +
        " Row" +
        (historyCount === 1 ? "" : "s") +
        "</p>"
      : "") +
    "</div>" +
    "<div class='table-wrap'><table id='historyTable'><thead><tr>" +
    "<th>Snapshot (SGT)</th><th>Ecosystem</th><th>Security Level</th>" +
    "<th class='num'>Packages</th><th class='num'>Versions</th>" +
    "</tr></thead><tbody id='historyBody'>" +
    historyBody +
    "</tbody></table></div>" +
    historyPagerHtml_(DEFAULT_HISTORY_PAGE_SIZE) +
    "</section>" +
    "<footer><span>Generated " +
    esc_(generated) +
    "</span><span class='dot'>·</span><span>" +
    esc_(options.source || "Catalog") +
    "</span></footer>" +
    "<script>" +
    "const chartPayload = " +
    chartJson +
    ";" +
    "const ctx = document.getElementById('catalogChart');" +
    "if (ctx && chartPayload.labels.length && window.Chart) {" +
    "  Chart.defaults.color = '#9ca3af';" +
    "  Chart.defaults.borderColor = 'rgba(255,255,255,0.06)';" +
    "  new Chart(ctx, {" +
    "    type: 'line'," +
    "    data: {" +
    "      labels: chartPayload.labels," +
    "      datasets: chartPayload.datasets.map(function (ds) {" +
    "        return {" +
    "          label: ds.label," +
    "          data: ds.data," +
    "          borderColor: ds.color," +
    "          backgroundColor: ds.color," +
    "          tension: 0.35," +
    "          pointRadius: chartPayload.labels.length > 40 ? 0 : 3," +
    "          pointHoverRadius: 5," +
    "          borderWidth: 2.25," +
    "          spanGaps: true" +
    "        };" +
    "      })" +
    "    }," +
    "    options: {" +
    "      responsive: true," +
    "      maintainAspectRatio: false," +
    "      interaction: { mode: 'index', intersect: false }," +
    "      plugins: {" +
    "        legend: { position: 'bottom', labels: { boxWidth: 10, usePointStyle: true, color: '#9ca3af', padding: 16, font: { family: 'Manrope', size: 12 } } }," +
    "        tooltip: {" +
    "          backgroundColor: '#0a0a0a'," +
    "          titleColor: '#fafafa'," +
    "          bodyColor: '#d4d4d8'," +
    "          borderColor: '#27272a'," +
    "          borderWidth: 1," +
    "          padding: 12," +
    "          callbacks: { label: function (c) {" +
    "            var v = c.parsed.y; return c.dataset.label + ': ' + (v == null ? '—' : Number(v).toLocaleString('en-US'));" +
    "          }}" +
    "        }" +
    "      }," +
    "      scales: {" +
    "        x: { ticks: { maxRotation: 0, autoSkip: true, maxTicksLimit: 10, color: '#9ca3af' }, grid: { color: 'rgba(255,255,255,0.04)' } }," +
    "        y: { beginAtZero: true, ticks: { color: '#9ca3af', callback: function (v) { return Number(v).toLocaleString('en-US'); } }, grid: { color: 'rgba(255,255,255,0.04)' } }" +
    "      }" +
    "    }" +
    "  });" +
    "}" +
    historyPagerScript_(DEFAULT_HISTORY_PAGE_SIZE) +
    "</script>" +
    "</main></body></html>"
  );
}

function historyPagerHtml_(pageSize) {
  return (
    "<nav class='pager' id='historyPager' aria-label='History pagination' hidden>" +
    "<button type='button' id='histPrev'>Previous</button>" +
    "<span id='histPageLabel'></span>" +
    "<button type='button' id='histNext'>Next</button>" +
    "<label class='pager-size'>Rows " +
    "<select id='histPageSize'>" +
    [12, 24, 48, 96]
      .map(function (n) {
        return (
          "<option value='" +
          n +
          "'" +
          (n === pageSize ? " selected" : "") +
          ">" +
          n +
          "</option>"
        );
      })
      .join("") +
    "</select></label></nav>"
  );
}

function historyPagerScript_(pageSize) {
  return (
    "(function () {" +
    "  var body = document.getElementById('historyBody');" +
    "  var pager = document.getElementById('historyPager');" +
    "  if (!body || !pager) return;" +
    "  var rows = Array.prototype.slice.call(body.querySelectorAll('tr')).filter(function (tr) {" +
    "    return !tr.classList.contains('empty');" +
    "  });" +
    "  if (!rows.length) return;" +
    "  var page = 1;" +
    "  var pageSize = " +
    Number(pageSize) +
    ";" +
    "  var prev = document.getElementById('histPrev');" +
    "  var next = document.getElementById('histNext');" +
    "  var label = document.getElementById('histPageLabel');" +
    "  var sizeSel = document.getElementById('histPageSize');" +
    "  function render() {" +
    "    var pages = Math.max(1, Math.ceil(rows.length / pageSize));" +
    "    if (page > pages) page = pages;" +
    "    if (page < 1) page = 1;" +
    "    var start = (page - 1) * pageSize;" +
    "    var end = start + pageSize;" +
    "    rows.forEach(function (tr, i) { tr.hidden = i < start || i >= end; });" +
    "    var shown = Math.min(end, rows.length) - start;" +
    "    label.textContent = 'Page ' + page + ' of ' + pages +" +
    "      ' · ' + (start + 1) + '–' + (start + shown) + ' of ' + rows.length;" +
    "    prev.disabled = page <= 1;" +
    "    next.disabled = page >= pages;" +
    "    pager.hidden = false;" +
    "  }" +
    "  prev.addEventListener('click', function () { page -= 1; render(); });" +
    "  next.addEventListener('click', function () { page += 1; render(); });" +
    "  sizeSel.addEventListener('change', function () {" +
    "    pageSize = Number(sizeSel.value) || " +
    Number(pageSize) +
    ";" +
    "    page = 1;" +
    "    render();" +
    "  });" +
    "  render();" +
    "})();"
  );
}

function buildChartPayload_(allRows, chartDays) {
  var cutoffMs = Date.now() - chartDays * 24 * 60 * 60 * 1000;
  var byStamp = {};
  var stamps = [];

  allRows.forEach(function (r) {
    var stamp = String(r[0] || "");
    if (!stamp) {
      return;
    }
    var t = Date.parse(stamp);
    if (!isFinite(t) || t < cutoffMs) {
      return;
    }
    if (!byStamp[stamp]) {
      byStamp[stamp] = {};
      stamps.push(stamp);
    }
    byStamp[stamp][r[1] + "|" + r[2]] = Number(r[3]) || 0;
  });

  stamps.sort();
  // Prefer one point per SGT calendar day (keep last snapshot that day)
  var dayLast = {};
  var dayOrder = [];
  stamps.forEach(function (stamp) {
    var day = stampToSgtDay_(stamp);
    if (!day) {
      return;
    }
    if (!dayLast[day]) {
      dayOrder.push(day);
    }
    dayLast[day] = stamp;
  });

  var labels = dayOrder.slice();
  var datasets = [];
  ECOSYSTEMS.forEach(function (eco) {
    SECURITY_LEVELS.forEach(function (level) {
      var key = eco + "|" + level;
      datasets.push({
        label: eco + " · " + level,
        color: SERIES_COLORS[key] || "#57534e",
        data: labels.map(function (day) {
          var stamp = dayLast[day];
          var map = byStamp[stamp] || {};
          return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : null;
        }),
      });
    });
  });

  return { labels: labels, datasets: datasets };
}

function catalogCss_() {
  return (
    ":root{--bg:#000;--ink:#fafafa;--muted:#9ca3af;--accent:#4ade80;--accent-2:#38bdf8;--line:rgba(255,255,255,.08);--panel:rgba(16,16,18,.82);--panel-solid:#101012}" +
    "*{box-sizing:border-box}" +
    "body{margin:0;font-family:Manrope,ui-sans-serif,sans-serif;background:var(--bg);color:var(--ink);line-height:1.5;min-height:100vh;position:relative;overflow-x:hidden}" +
    ".glow{position:fixed;border-radius:999px;filter:blur(80px);pointer-events:none;z-index:0}" +
    ".glow-a{top:-8rem;left:-4rem;width:28rem;height:28rem;background:rgba(74,222,128,.16)}" +
    ".glow-b{top:10rem;right:-6rem;width:24rem;height:24rem;background:rgba(56,189,248,.12)}" +
    "main{position:relative;z-index:1;max-width:1080px;margin:0 auto;padding:2rem 1.25rem 4rem}" +
    ".fade-in{animation:rise .55s ease both}" +
    "@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}" +
    ".hero{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:1.25rem 1.5rem;margin-bottom:1.5rem;padding-bottom:1.35rem;border-bottom:1px solid var(--line)}" +
    ".hero-copy{flex:1 1 18rem;min-width:0}" +
    ".eyebrow{margin:0 0 .65rem;font-size:.7rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--accent)}" +
    "h1{font-family:Sora,ui-sans-serif,sans-serif;font-weight:700;font-size:clamp(1.65rem,3.2vw,2.4rem);margin:0 0 .65rem;letter-spacing:-.035em;line-height:1.12}" +
    ".sub{color:var(--muted);margin:0;max-width:40rem;font-size:.98rem}" +
    ".sub strong{color:var(--ink);font-weight:700}" +
    ".hero-actions{display:flex;flex-wrap:wrap;gap:.6rem}" +
    ".btn{display:inline-flex;align-items:center;justify-content:center;font:inherit;font-weight:600;font-size:.9rem;text-decoration:none;border-radius:999px;padding:.62rem 1.05rem;border:1px solid transparent;transition:transform .15s ease,background .15s ease,border-color .15s ease}" +
    ".btn:hover{transform:translateY(-1px);text-decoration:none}" +
    ".btn-primary{background:var(--accent);color:#052e16;border-color:transparent}" +
    ".btn-primary:hover{background:#86efac}" +
    ".btn-ghost{background:rgba(255,255,255,.03);color:var(--ink);border-color:var(--line)}" +
    ".btn-ghost:hover{border-color:rgba(255,255,255,.2);background:rgba(255,255,255,.06)}" +
    "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em;color:#e5e7eb;background:rgba(255,255,255,.04);border:1px solid var(--line);border-radius:6px;padding:.1rem .35rem}" +
    ".notice{background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.25);border-radius:14px;padding:.8rem 1rem;margin:0 0 1.15rem;color:#bbf7d0;font-size:.92rem}" +
    ".stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.75rem;margin-bottom:1.15rem}" +
    "@media (max-width:820px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}}" +
    ".stat{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:1rem 1.05rem;backdrop-filter:blur(10px)}" +
    ".stat-label{margin:0;color:var(--muted);font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}" +
    ".stat-value{margin:.35rem 0 0;font-family:Sora,ui-sans-serif,sans-serif;font-size:1.45rem;font-weight:700;letter-spacing:-.03em;font-variant-numeric:tabular-nums}" +
    ".panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:1.2rem 1.25rem 1.3rem;margin-bottom:1rem;backdrop-filter:blur(12px);box-shadow:0 20px 50px rgba(0,0,0,.35)}" +
    "h2{margin:0 0 .85rem;font-family:Sora,ui-sans-serif,sans-serif;font-size:1.02rem;font-weight:600;letter-spacing:-.02em;color:var(--ink)}" +
    ".section-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:.5rem .85rem;margin-bottom:.55rem}" +
    ".section-head h2{margin:0}" +
    ".section-head .chart-sub{margin:0}" +
    ".chart-sub{margin:-.2rem 0 .85rem;color:var(--muted);font-size:.88rem}" +
    ".chart-wrap{position:relative;height:min(380px,58vw);width:100%}" +
    ".table-wrap{overflow-x:auto;border-radius:12px;border:1px solid var(--line)}" +
    "table{width:100%;border-collapse:collapse;font-size:.93rem}" +
    "th,td{text-align:left;padding:.7rem .75rem;border-bottom:1px solid var(--line)}" +
    "thead th{background:rgba(255,255,255,.03);font-size:.7rem;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--muted);position:sticky;top:0}" +
    "tbody tr:last-child td{border-bottom:0}" +
    "td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}" +
    "td.stamp{white-space:nowrap;font-variant-numeric:tabular-nums;color:#e5e7eb}" +
    "tbody tr:hover td{background:rgba(255,255,255,.03)}" +
    "tr.latest td{background:rgba(74,222,128,.07)}" +
    ".eco{font-weight:600}" +
    ".badge{display:inline-flex;align-items:center;border-radius:999px;padding:.18rem .55rem;font-size:.78rem;font-weight:700;letter-spacing:.02em;border:1px solid transparent}" +
    ".badge-validated{color:#86efac;background:rgba(74,222,128,.1);border-color:rgba(74,222,128,.22)}" +
    ".badge-remediated{color:#7dd3fc;background:rgba(56,189,248,.1);border-color:rgba(56,189,248,.22)}" +
    ".pager{display:flex;flex-wrap:wrap;align-items:center;gap:.55rem .75rem;margin-top:1rem;color:var(--muted);font-size:.88rem}" +
    ".pager button{font:inherit;font-weight:600;color:var(--ink);background:rgba(255,255,255,.03);border:1px solid var(--line);border-radius:999px;padding:.42rem .9rem;cursor:pointer;transition:border-color .15s ease,background .15s ease}" +
    ".pager button:disabled{opacity:.35;cursor:default}" +
    ".pager button:not(:disabled):hover{border-color:rgba(255,255,255,.22);background:rgba(255,255,255,.06)}" +
    ".pager-size{margin-left:auto;display:inline-flex;align-items:center;gap:.35rem}" +
    ".pager-size select{font:inherit;border:1px solid var(--line);border-radius:999px;background:#0a0a0a;padding:.38rem .7rem;color:var(--ink)}" +
    "footer{display:flex;flex-wrap:wrap;align-items:center;gap:.45rem;color:var(--muted);font-size:.84rem;margin-top:1.1rem}" +
    "footer .dot{opacity:.5}" +
    "a{color:var(--accent);text-decoration:none}" +
    "a:hover{text-decoration:underline}"
  );
}

function errorPage_(title, messageHtml) {
  return (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>" +
    "<title>" +
    esc_(title) +
    "</title><style>" +
    catalogCss_() +
    "</style></head><body><main>" +
    "<h1>" +
    esc_(title) +
    "</h1>" +
    "<section>" +
    messageHtml +
    "</section>" +
    "<footer><a href='?action=status'>Back to dashboard</a></footer>" +
    "</main></body></html>"
  );
}

function esc_(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function required_(props, key) {
  var value = props.getProperty(key);
  if (!value) {
    throw new Error("Missing Script Property: " + key);
  }
  return value;
}
