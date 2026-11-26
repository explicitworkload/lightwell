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
 *   ACCESS_ADMIN       = owner email (set automatically from the account the script runs as)
 *   APPROVED_USERS     = JSON list of approved emails (managed on the Access page)
 *   CHART_DAYS         = 30                                (optional; trend window)
 *   LW_USER            = registry username (e.g. 1234567|name) for packages.redhat.com
 *   LW_TOKEN           = registry token (Basic Auth password) — registry proxy + OSV index
 *   OSV_INDEX_FILE_ID  = Drive file id for osv-severity-index.json (set by syncOsvIndex)
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

function ecosystemLabel_(eco) {
  var key = String(eco || "").toLowerCase();
  if (key === "maven") return "Java";
  return titleCase_(eco);
}

/**
 * Web app entrypoint (Deploy → Web app → execute as Me).
 *
 *   GET /exec                      → dashboard
 *   GET /exec?page=browser         → Catalog Browser
 *   GET /exec?page=recent          → Recent Releases (newest 300)
 *   GET /exec?page=cve             → CVE / RHLW Lookup
 *   GET /exec?page=match           → Dependency Match
 *   GET /exec?page=access          → approved-email list (owner only)
 *   GET /exec?page=registry&path=lightwell/…  → packages.redhat.com proxy (LW_USER / LW_TOKEN)
 *   GET /exec?action=run           → snapshot then dashboard
 *   GET /exec?key=SECRET           → when WEBAPP_KEY is set
 */
function doGet(e) {
  e = e || { parameter: {} };
  var params = e.parameter || {};
  var props = PropertiesService.getScriptProperties();
  var linkKey = params.key || "";

  var requiredKey = props.getProperty("WEBAPP_KEY");
  if (requiredKey && params.key !== requiredKey) {
    return htmlOutput_(
      errorPage_("Unauthorized", "Missing or invalid <code>key</code> query parameter.", linkKey),
      "Unauthorized"
    );
  }

  var gate;
  try {
    gate = requireApproved_();
  } catch (err) {
    return htmlOutput_(accessDeniedPage_(visitorEmail_()), "Access Denied");
  }

  var page = String(params.page || "dashboard").toLowerCase();
  if (page === "browser") {
    return serveHtmlPage_("Browser", linkKey, "Lightwell Catalog Browser", gate);
  }
  if (page === "recent") {
    return serveHtmlPage_("Recent", linkKey, "Lightwell Recent Releases", gate);
  }
  if (page === "cve") {
    return serveHtmlPage_("Cve", linkKey, "Lightwell CVE / RHLW Lookup", gate);
  }
  if (page === "match") {
    return serveHtmlPage_("Match", linkKey, "Lightwell Dependency Match", gate);
  }
  if (page === "access") {
    if (!gate.admin) {
      return htmlOutput_(
        errorPage_("Access", "<p>Only the owner can manage the approved list.</p>", linkKey),
        "Access"
      );
    }
    return serveHtmlPage_("Allowlist", linkKey, "Lightwell Access", gate);
  }
  if (page === "registry") {
    return serveRegistryProxy_(params, linkKey);
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
    return htmlOutput_(
      buildCatalogPage_(allRows, {
        source: "Google Apps Script Web app",
        chartDays: chartDays,
        webAppKey: linkKey,
        showAccess: gate.admin,
        notice:
          action === "run"
            ? "Fresh snapshot written, then dashboard refreshed from the Sheet."
            : "",
      }),
      PAGE_TITLE
    );
  } catch (err) {
    Logger.log(err);
    return htmlOutput_(
      errorPage_(
        "Snapshot Failed",
        "<pre>" + esc_(String(err && err.message ? err.message : err)) + "</pre>",
        linkKey
      ),
      "Snapshot Failed"
    );
  }
}

/** Include an HTML file from the Apps Script project (for templates). */
function include(filename) {
  requireApproved_();
  return HtmlService.createHtmlOutputFromFile(filename).getContent();
}

function serveHtmlPage_(filename, linkKey, title, gate) {
  requireApproved_();
  var tpl = HtmlService.createTemplateFromFile(filename);
  tpl.urlDashboard = webAppHref_({ key: linkKey });
  tpl.urlBrowser = webAppHref_({ page: "browser", key: linkKey });
  tpl.urlRecent = webAppHref_({ page: "recent", key: linkKey });
  tpl.urlCve = webAppHref_({ page: "cve", key: linkKey });
  tpl.urlMatch = webAppHref_({ page: "match", key: linkKey });
  tpl.webAppKey = linkKey || "";
  tpl.showAccess = !!(gate && gate.admin);
  tpl.urlAccess = webAppHref_({ page: "access", key: linkKey });
  var base = "";
  try {
    base = ScriptApp.getService().getUrl() || "";
  } catch (err) {
    base = "";
  }
  if (!base && tpl.urlBrowser) {
    base = String(tpl.urlBrowser).split("?")[0];
  }
  tpl.webAppBase = base;
  var out = tpl.evaluate();
  out.setTitle(title || PAGE_TITLE);
  out.addMetaTag("viewport", "width=device-width, initial-scale=1");
  out.setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
  return out;
}

/** HtmlService output with iframe-safe settings (avoids blank white pages on nav). */
function htmlOutput_(html, title) {
  return HtmlService.createHtmlOutput(html)
    .setTitle(title || PAGE_TITLE)
    .addMetaTag("viewport", "width=device-width, initial-scale=1")
    .setXFrameOptionsMode(HtmlService.XFrameOptionsMode.ALLOWALL);
}

/**
 * Absolute Web app URL.
 * opts: { action, page, key }  OR legacy webAppHref_(action, key)
 * Always use target="_top" on these links (Apps Script iframe).
 */
function webAppHref_(opts, maybeKey) {
  if (typeof opts === "string") {
    opts = { action: opts, key: maybeKey || "" };
  }
  opts = opts || {};
  var base = "";
  try {
    base = ScriptApp.getService().getUrl() || "";
  } catch (err) {
    base = "";
  }
  var q = [];
  if (opts.page) {
    q.push("page=" + encodeURIComponent(opts.page));
  }
  if (opts.action) {
    q.push("action=" + encodeURIComponent(opts.action));
  }
  if (opts.key) {
    q.push("key=" + encodeURIComponent(opts.key));
  }
  // Prefer path= over u= — nested https:// in query breaks Google's web-app router (Drive error page).
  if (opts.path) {
    q.push("path=" + encodeURIComponent(opts.path));
  } else if (opts.p) {
    q.push("path=" + encodeURIComponent(opts.p));
  }
  if (opts.u && !opts.path && !opts.p) {
    q.push("u=" + encodeURIComponent(opts.u));
  }
  var query = q.length ? "?" + q.join("&") : "";
  return (base || "") + query;
}

function runCatalogSnapshot() {
  requireApproved_();
  var result = runCatalogSnapshot_();
  Logger.log(
    "Wrote %s summary rows at %s",
    result.rows.length,
    result.snapshotAt
  );
}

function runCatalogSnapshot_() {
  requireApproved_();
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

/** Install daily triggers (idempotent). OSV index and snapshot at 08:00 and 15:00 SGT. */
function installTriggers() {
  requireApproved_();
  removeTriggers_();
  ScriptApp.newTrigger("syncOsvIndex")
    .timeBased()
    .atHour(8)
    .nearMinute(0)
    .everyDays(1)
    .inTimezone("Asia/Singapore")
    .create();
  ScriptApp.newTrigger("syncOsvIndex")
    .timeBased()
    .atHour(15)
    .nearMinute(0)
    .everyDays(1)
    .inTimezone("Asia/Singapore")
    .create();
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
  Logger.log("Installed SGT triggers: syncOsvIndex and runCatalogSnapshot at 08:00 and 15:00");
}

function removeTriggers() {
  requireApproved_();
  removeTriggers_();
  Logger.log("Removed all project triggers");
}

function removeTriggers_() {
  requireApproved_();
  ScriptApp.getProjectTriggers().forEach(function (t) {
    ScriptApp.deleteTrigger(t);
  });
}

function getAccessToken_(props) {
  requireApproved_();
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
  requireApproved_();
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
  requireApproved_();
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
  requireApproved_();
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
 * Full dashboard HTML.
 * options: { source, chartDays, notice, webAppKey }
 * Times/filters are applied in the browser (local timezone).
 */
function buildCatalogPage_(allRows, options) {
  requireApproved_();
  options = options || {};
  var chartDays = Number(options.chartDays || DEFAULT_CHART_DAYS);
  if (!isFinite(chartDays)) {
    chartDays = DEFAULT_CHART_DAYS;
  }
  chartDays = Math.max(7, Math.min(365, Math.round(chartDays)));
  var webAppKey = options.webAppKey || "";
  var hrefStatus = webAppHref_({ action: "status", key: webAppKey });
  var hrefRun = webAppHref_({ action: "run", key: webAppKey });
  var hrefBrowser = webAppHref_({ page: "browser", key: webAppKey });
  var hrefRecent = webAppHref_({ page: "recent", key: webAppKey });
  var hrefCve = webAppHref_({ page: "cve", key: webAppKey });
  var hrefMatch = webAppHref_({ page: "match", key: webAppKey });
  var hrefAccess = webAppHref_({ page: "access", key: webAppKey });
  var accessNav = options.showAccess
    ? "<a href='" + esc_(hrefAccess) + "' target='_top' rel='noopener'>Access</a>"
    : "";
  var generatedIso = formatStampSgt_(new Date());

  var latestAt = "";
  allRows.forEach(function (r) {
    if (String(r[0]) > latestAt) {
      latestAt = String(r[0]);
    }
  });

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
      var seriesKey = String(r[1] || "") + "|" + String(r[2] || "");
      return (
        "<tr data-series='" +
        esc_(seriesKey) +
        "'><td><span class='eco'>" +
        esc_(ecosystemLabel_(r[1])) +
        "</span></td><td><span class='" +
        levelClass +
        "'>" +
        esc_(titleCase_(level)) +
        "</span></td><td class='num'><span class='metric' data-metric='packages' data-value='" +
        (Number(r[3]) || 0) +
        "'>" +
        num(r[3]) +
        "</span></td><td class='num'><span class='metric' data-metric='versions' data-value='" +
        (Number(r[4]) || 0) +
        "'>" +
        num(r[4]) +
        "</span></td></tr>"
      );
    })
    .join("");
  if (!latestBody) {
    latestBody = '<tr><td colspan="4">No Rows</td></tr>';
  }

  var historyBody = allRows
    .slice()
    .reverse()
    .map(function (r) {
      var stamp = String(r[0]);
      var cls = stamp === latestAt ? " class='latest hist-row'" : " class='hist-row'";
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
        " data-iso='" +
        esc_(stamp) +
        "'><td class='stamp js-local-time' data-iso='" +
        esc_(stamp) +
        "'>" +
        esc_(stamp) +
        "</td><td>" +
        esc_(ecosystemLabel_(r[1])) +
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

  var catalogPayload = {
    rows: allRows.map(function (r) {
      return {
        t: String(r[0] || ""),
        ecosystem: String(r[1] || ""),
        level: String(r[2] || ""),
        packages: Number(r[3]) || 0,
        versions: Number(r[4]) || 0,
      };
    }),
    latestAt: latestAt,
    defaultDays: chartDays,
    pageSize: DEFAULT_HISTORY_PAGE_SIZE,
    series: ECOSYSTEMS.map(function (eco) {
      return SECURITY_LEVELS.map(function (level) {
        var key = eco + "|" + level;
        return {
          key: key,
          label: ecosystemLabel_(eco) + " · " + titleCase_(level),
          color: SERIES_COLORS[key] || "#a1a1aa",
        };
      });
    }).reduce(function (a, b) {
      return a.concat(b);
    }, []),
  };
  var catalogJson = JSON.stringify(catalogPayload).replace(/</g, "\\u003c");

  var notice = options.notice
    ? "<div class='notice' role='status'>" + esc_(options.notice) + "</div>"
    : "";

  var dayPresets = [7, 14, 30, 365];
  var segButtons = dayPresets
    .map(function (d) {
      return (
        "<button type='button' class='seg-btn" +
        (d === chartDays ? " is-active" : "") +
        "' data-days='" +
        d +
        "' aria-pressed='" +
        (d === chartDays ? "true" : "false") +
        "'>" +
        d +
        "D</button>"
      );
    })
    .join("");
  var defaultEco = "maven";
  var ecoButtons =
    "<button type='button' class='seg-btn' data-eco='' aria-pressed='false'>All</button>" +
    ECOSYSTEMS.map(function (eco) {
      var on = eco === defaultEco;
      return (
        "<button type='button' class='seg-btn" +
        (on ? " is-active" : "") +
        "' data-eco='" +
        esc_(eco) +
        "' aria-pressed='" +
        (on ? "true" : "false") +
        "'>" +
        esc_(ecosystemLabel_(eco)) +
        "</button>"
      );
    }).join("");

  return (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>" +
    "<meta name='color-scheme' content='dark'/>" +
    "<title>" +
    esc_(PAGE_TITLE) +
    "</title>" +
    "<link rel='icon' href='https://www.redhat.com/favicon.ico' type='image/x-icon'/>" +
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
    "<nav class='topnav' aria-label='Primary'>" +
    "<a class='is-active' href='" +
    esc_(hrefStatus) +
    "' target='_top' rel='noopener'>Dashboard</a>" +
    "<a href='" +
    esc_(hrefBrowser) +
    "' target='_top' rel='noopener'>Catalog Browser</a>" +
    "<a href='" +
    esc_(hrefRecent) +
    "' target='_top' rel='noopener'>Recent Releases</a>" +
    "<a href='" +
    esc_(hrefCve) +
    "' target='_top' rel='noopener'>CVE / RHLW Lookup</a>" +
    "<a href='" +
    esc_(hrefMatch) +
    "' target='_top' rel='noopener'>Dependency Match</a>" +
    accessNav +
    "</nav>" +
    "<header class='hero'>" +
    "<div class='hero-copy'>" +
    "<p class='eyebrow'>Lightwell Network · <span id='tzLabel'>Local Time</span></p>" +
    "<h1>" +
    esc_(PAGE_TITLE) +
    "</h1>" +
    "<p class='sub'>Package And Version Counts From Content-Sources <code>meta.count</code>.</p>" +
    "<p class='latest-line'>Latest Snapshot<br/><strong class='js-local-time' data-iso='" +
    esc_(latestAt || "") +
    "' data-empty='—'>" +
    esc_(latestAt || "—") +
    "</strong></p>" +
    "</div>" +
    "<div class='hero-actions'>" +
    "<a class='btn btn-ghost' href='" +
    esc_(hrefStatus) +
    "' target='_top' rel='noopener'>Refresh</a>" +
    "<a class='btn btn-primary' href='" +
    esc_(hrefRun) +
    "' target='_top' rel='noopener'>Run Snapshot</a>" +
    "</div>" +
    "</header>" +
    notice +
    "<div class='stats stats-3'>" +
    "<article class='stat'><p class='stat-label'>Total Packages</p><p class='stat-value'>" +
    num(totalPackages) +
    "</p></article>" +
    "<article class='stat'><p class='stat-label'>Total Versions</p><p class='stat-value'>" +
    num(totalVersions) +
    "</p></article>" +
    "<article class='stat'><p class='stat-label'>Trend Window</p><p class='stat-value' id='statTrend'>" +
    chartDays +
    "d</p></article>" +
    "</div>" +
    "<section class='panel' id='pulsePanel'>" +
    "<div class='pulse-head'>" +
    "<h2>Last 3 days</h2>" +
    "<p class='chart-sub' id='pulseRange'>Comparing snapshots…</p>" +
    "</div>" +
    "<div class='pulse-stats' id='pulseStats'></div>" +
    "<div class='pulse-days' id='pulseDays'></div>" +
    "<div id='pulseList'></div>" +
    "</section>" +
    "<section class='panel' id='trendPanel'>" +
    "<div class='section-head'>" +
    "<h2 id='trendHeading'>Package Trend</h2>" +
    "<div class='trend-controls'>" +
    "<div class='seg' id='trendEco' role='group' aria-label='Ecosystem'>" +
    ecoButtons +
    "</div>" +
    "<div class='seg' id='trendDays' role='group' aria-label='Trend Window Presets'>" +
    segButtons +
    "</div>" +
    "</div>" +
    "</div>" +
    "<p class='chart-sub' id='chartRange'>Loading trend…</p>" +
    "<div class='chart-wrap'><canvas id='catalogChart'></canvas></div>" +
    "</section>" +
    "<section class='panel' id='snapshotPanel'>" +
    "<div class='section-head'>" +
    "<div>" +
    "<h2>Latest Snapshot</h2>" +
    "<p class='chart-sub snapshot-note' id='snapshotDeltaNote'>Comparing with the previous day…</p>" +
    "</div>" +
    "<div class='seg' id='snapshotDelta' role='group' aria-label='How far back to measure the change'>" +
    "<button type='button' class='seg-btn is-active' data-days='1' aria-pressed='true'>1D</button>" +
    "<button type='button' class='seg-btn' data-days='7' aria-pressed='false'>7D</button>" +
    "<button type='button' class='seg-btn' data-days='14' aria-pressed='false'>14D</button>" +
    "<button type='button' class='seg-btn' data-days='30' aria-pressed='false'>30D</button>" +
    "</div>" +
    "</div>" +
    "<div class='table-wrap'><table id='snapshotTable'><thead><tr>" +
    "<th>Ecosystem</th><th>Security Level</th>" +
    "<th class='num'>Packages</th><th class='num'>Versions</th>" +
    "</tr></thead><tbody>" +
    latestBody +
    "</tbody></table></div></section>" +
    "<section class='panel'>" +
    "<div class='section-head section-head-stack'>" +
    "<div class='section-title-row'>" +
    "<h2>History</h2>" +
    "<p class='chart-sub' id='historyCountLabel'></p>" +
    "</div>" +
    "<div class='date-filters'>" +
    "<label class='date-field'>From" +
    "<input type='date' id='histFrom' /></label>" +
    "<label class='date-field'>To" +
    "<input type='date' id='histTo' /></label>" +
    "<button type='button' class='btn-text' id='histClearDates'>Clear</button>" +
    "</div>" +
    "</div>" +
    "<div class='table-wrap'><table id='historyTable'><thead><tr>" +
    "<th>Snapshot</th><th>Ecosystem</th><th>Security Level</th>" +
    "<th class='num'>Packages</th><th class='num'>Versions</th>" +
    "</tr></thead><tbody id='historyBody'>" +
    historyBody +
    "</tbody></table></div>" +
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
          (n === DEFAULT_HISTORY_PAGE_SIZE ? " selected" : "") +
          ">" +
          n +
          "</option>"
        );
      })
      .join("") +
    "</select></label></nav>" +
    "</section>" +
    "<footer><span>Generated <span class='js-local-time' data-iso='" +
    esc_(generatedIso) +
    "'>" +
    esc_(generatedIso) +
    "</span></span><span class='dot'>·</span><span>" +
    esc_(options.source || "Catalog") +
    "</span><span class='dot'>·</span><span id='tzFooter'></span></footer>" +
    "<script>window.CATALOG=" +
    catalogJson +
    ";" +
    dashboardClientScript_() +
    "</script>" +
    "</main></body></html>"
  );
}

/** Browser-side timezone formatting, chart day filter, history date filter + pager. */
function dashboardClientScript_() {
  return (
    "(function(){" +
    "var C=window.CATALOG||{rows:[],series:[],defaultDays:30,pageSize:24};" +
    "var tz=Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC';" +
    "var tzEl=document.getElementById('tzLabel');" +
    "var tzFoot=document.getElementById('tzFooter');" +
    "if(tzEl) tzEl.textContent=tz;" +
    "if(tzFoot) tzFoot.textContent=tz;" +
    "function fmt(iso,opts){" +
    "  var t=Date.parse(iso||'');" +
    "  if(!isFinite(t)) return iso||'—';" +
    "  return new Intl.DateTimeFormat(undefined,Object.assign({" +
    "    timeZone:tz,month:'short',day:'2-digit',year:'numeric'," +
    "    hour:'2-digit',minute:'2-digit',hour12:false" +
    "  },opts||{})).format(new Date(t));" +
    "}" +
    "function localDay(iso){" +
    "  var t=Date.parse(iso||'');" +
    "  if(!isFinite(t)) return '';" +
    "  var parts=new Intl.DateTimeFormat('en-CA',{timeZone:tz,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(t));" +
    "  var y='',m='',d='';" +
    "  parts.forEach(function(p){ if(p.type==='year')y=p.value; if(p.type==='month')m=p.value; if(p.type==='day')d=p.value; });" +
    "  return y+'-'+m+'-'+d;" +
    "}" +
    "function fmtDayLabel(day){" +
    "  var t=Date.parse(day+'T12:00:00');" +
    "  if(!isFinite(t)) return day;" +
    "  return new Intl.DateTimeFormat(undefined,{timeZone:tz,month:'short',day:'2-digit'}).format(new Date(t));" +
    "}" +
    "document.querySelectorAll('.js-local-time').forEach(function(el){" +
    "  var iso=el.getAttribute('data-iso')||'';" +
    "  var empty=el.getAttribute('data-empty');" +
    "  el.textContent=iso?fmt(iso):(empty||'—');" +
    "});" +
    "var chartDays=Math.max(7,Math.min(365,Number(C.defaultDays)||30));" +
    "var chartObj=null;" +
    "function syncControls(days){" +
    "  chartDays=Math.max(7,Math.min(365,Math.round(Number(days)||30)));" +
    "  document.querySelectorAll('#trendDays .seg-btn').forEach(function(b){" +
    "    var on=Number(b.getAttribute('data-days'))===chartDays;" +
    "    b.classList.toggle('is-active',on);" +
    "    b.setAttribute('aria-pressed',on?'true':'false');" +
    "  });" +
    "}" +
    "var chartEco='maven';" +
    "function syncEco(){" +
    "  document.querySelectorAll('#trendEco .seg-btn').forEach(function(b){" +
    "    var on=(b.getAttribute('data-eco')||'')===chartEco;" +
    "    b.classList.toggle('is-active',on);" +
    "    b.setAttribute('aria-pressed',on?'true':'false');" +
    "  });" +
    "}" +
    "function ecoLabel(){" +
    "  if(!chartEco) return '';" +
    "  var hit=(C.series||[]).filter(function(s){ return String(s.key||'').indexOf(chartEco+'|')===0; })[0];" +
    "  return hit?String(hit.label||'').split(' · ')[0]:chartEco;" +
    "}" +
    "function buildPayload(days){" +
    "  var cutoff=Date.now()-days*24*60*60*1000;" +
    "  var byStamp={}; var stamps=[];" +
    "  (C.rows||[]).forEach(function(r){" +
    "    var t=Date.parse(r.t||'');" +
    "    if(!isFinite(t)||t<cutoff) return;" +
    "    if(!byStamp[r.t]){ byStamp[r.t]={}; stamps.push(r.t); }" +
    "    byStamp[r.t][r.ecosystem+'|'+r.level]=r.packages;" +
    "  });" +
    "  stamps.sort();" +
    "  var dayLast={}; var dayOrder=[];" +
    "  stamps.forEach(function(stamp){" +
    "    var day=localDay(stamp); if(!day) return;" +
    "    if(!dayLast[day]) dayOrder.push(day);" +
    "    dayLast[day]=stamp;" +
    "  });" +
    "  return {" +
    "    labels:dayOrder.map(fmtDayLabel)," +
    "    rawDays:dayOrder," +
    "    datasets:(C.series||[]).map(function(s){" +
    "      return {key:s.key,label:s.label,color:s.color,data:dayOrder.map(function(day){" +
    "        var map=byStamp[dayLast[day]]||{};" +
    "        return Object.prototype.hasOwnProperty.call(map,s.key)?map[s.key]:null;" +
    "      })};" +
    "    })" +
    "  };" +
    "}" +
    "function niceStep(span){" +
    "  var rough=Math.max(span,1)/4;" +
    "  var pow=Math.pow(10,Math.floor(Math.log10(rough)));" +
    "  var err=rough/pow;" +
    "  var nice=err>=7.5?10:(err>=3.5?5:(err>=1.5?2:1));" +
    "  return nice*pow;" +
    "}" +
    "function fitScale(values,side){" +
    "  var nums=values.filter(function(v){ return v!=null && isFinite(Number(v)); }).map(Number);" +
    "  var scale={position:side||'left',beginAtZero:!nums.length,ticks:{color:'#9ca3af',callback:function(v){return Math.round(Number(v)).toLocaleString();}},grid:{color:side==='right'?'transparent':'rgba(255,255,255,0.04)',drawOnChartArea:side!=='right'}};" +
    "  if(nums.length<1) return scale;" +
    "  var min=Math.min.apply(null,nums), max=Math.max.apply(null,nums);" +
    "  var span=max-min;" +
    "  var pad=span>0?span*0.45:Math.max(Math.abs(max)*0.04,1);" +
    "  var step=niceStep((max+pad)-Math.max(0,min-pad));" +
    "  var lo=Math.max(0,Math.floor(Math.max(0,min-pad)/step)*step);" +
    "  var hi=Math.ceil((max+pad)/step)*step;" +
    "  if(hi<=lo) hi=lo+step;" +
    "  if(hi<=max) hi=max+step;" +
    "  scale.beginAtZero=false; scale.min=lo; scale.max=hi; scale.ticks.stepSize=step;" +
    "  return scale;" +
    "}" +
    "function renderChart(days){" +
    "  syncControls(days);" +
    "  syncEco();" +
    "  var el=document.getElementById('statTrend'); if(el) el.textContent=chartDays+'d';" +
    "  var head=document.getElementById('trendHeading');" +
    "  var name=ecoLabel();" +
    "  if(head) head.textContent='Package Trend (Last '+chartDays+' Days)'+(name?' · '+name:'');" +
    "  var payload=buildPayload(chartDays);" +
    "  var shown=payload.datasets.filter(function(ds){" +
    "    if(!chartEco) return true;" +
    "    return String(ds.key||'').indexOf(chartEco+'|')===0;" +
    "  });" +
    "  var split=!!chartEco && shown.length>1;" +
    "  var range=document.getElementById('chartRange');" +
    "  if(range){" +
    "    var base=payload.labels.length" +
    "      ? (payload.labels[0]+' → '+payload.labels[payload.labels.length-1]+' · '+payload.labels.length+' Snapshot'+(payload.labels.length===1?'':'s'))" +
    "      : 'No Snapshot Data In This Window Yet — Run A Few Days Of Triggers First.';" +
    "    range.textContent=payload.labels.length" +
    "      ? (base+(split?' · each line scaled to its own range':(name?' · axis fitted to '+name:''))+' · '+tz)" +
    "      : base;" +
    "  }" +
    "  var ctx=document.getElementById('catalogChart');" +
    "  if(!ctx||!window.Chart) return;" +
    "  if(chartObj) chartObj.destroy();" +
    "  Chart.defaults.color='#9ca3af';" +
    "  Chart.defaults.borderColor='rgba(255,255,255,0.06)';" +
    "  var scales={" +
    "    x:{ticks:{maxRotation:0,autoSkip:true,maxTicksLimit:10,color:'#9ca3af'},grid:{color:'rgba(255,255,255,0.04)'}}," +
    "    y: chartEco ? fitScale(shown.length?shown[0].data:[],'left') : {beginAtZero:true,ticks:{color:'#9ca3af',callback:function(v){return Number(v).toLocaleString();}},grid:{color:'rgba(255,255,255,0.04)'}}" +
    "  };" +
    "  if(split) scales.y1=fitScale(shown[1].data,'right');" +
    "  chartObj=new Chart(ctx,{" +
    "    type:'line'," +
    "    data:{" +
    "      labels:payload.labels," +
    "      datasets:shown.map(function(ds,i){" +
    "        return {label:ds.label,data:ds.data,borderColor:ds.color,backgroundColor:ds.color," +
    "          yAxisID:split&&i>0?'y1':'y'," +
    "          tension:0.35,pointRadius:payload.labels.length>40?0:3,pointHoverRadius:5,borderWidth:2.25,spanGaps:true};" +
    "      })" +
    "    }," +
    "    options:{" +
    "      responsive:true,maintainAspectRatio:false,interaction:{mode:'index',intersect:false}," +
    "      plugins:{" +
    "        legend:{position:'bottom',labels:{boxWidth:10,usePointStyle:true,color:'#9ca3af',padding:16,font:{family:'Manrope',size:12}}}," +
    "        tooltip:{backgroundColor:'#0a0a0a',titleColor:'#fafafa',bodyColor:'#d4d4d8',borderColor:'#27272a',borderWidth:1,padding:12," +
    "          callbacks:{label:function(c){var v=c.parsed.y; return c.dataset.label+': '+(v==null?'—':Number(v).toLocaleString());}}}" +
    "      }," +
    "      scales:scales" +
    "    }" +
    "  });" +
    "}" +
    "document.querySelectorAll('#trendDays .seg-btn').forEach(function(btn){" +
    "  btn.addEventListener('click',function(){" +
    "    renderChart(Number(btn.getAttribute('data-days'))||30);" +
    "  });" +
    "});" +
    "document.querySelectorAll('#trendEco .seg-btn').forEach(function(btn){" +
    "  btn.addEventListener('click',function(){" +
    "    chartEco=btn.getAttribute('data-eco')||'';" +
    "    renderChart(chartDays);" +
    "  });" +
    "});" +
    "function escHtml(s){" +
    "  return String(s==null?'':s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/\"/g,'&quot;');" +
    "}" +
    "function titleWord(s){ s=String(s||''); if(!s) return '—'; if(s.toLowerCase()==='maven') return 'Java'; return s.charAt(0).toUpperCase()+s.slice(1); }" +
    "function signed(n){ n=Number(n)||0; return (n>0?'+':'')+n.toLocaleString(); }" +
    "function deltaClass(n){ n=Number(n)||0; return n>0?'delta-up':(n<0?'delta-down':'delta-flat'); }" +
    "function pctText(now,then){" +
    "  then=Number(then)||0; now=Number(now)||0; if(!then) return '';" +
    "  var p=((now-then)/then)*100; return (p>0?'+':'')+p.toFixed(1)+'%';" +
    "}" +
    "function shiftDay(day,delta){" +
    "  var parts=String(day||'').split('-'); if(parts.length!==3) return '';" +
    "  var dt=new Date(Number(parts[0]),Number(parts[1])-1,Number(parts[2])+delta,12,0,0);" +
    "  return localDay(dt.toISOString());" +
    "}" +
    "function renderPulse(){" +
    "  var stats=document.getElementById('pulseStats');" +
    "  var daysEl=document.getElementById('pulseDays');" +
    "  var list=document.getElementById('pulseList');" +
    "  var range=document.getElementById('pulseRange');" +
    "  if(!stats||!list) return;" +
    "  function say(msg){" +
    "    if(range) range.textContent=msg;" +
    "    stats.innerHTML=''; if(daysEl) daysEl.innerHTML='';" +
    "    list.innerHTML='<p class=\"pulse-note\">'+escHtml(msg)+'</p>';" +
    "  }" +
    "  var latestStamp={};" +
    "  (C.rows||[]).forEach(function(r){" +
    "    var day=localDay(r.t); if(!day) return;" +
    "    var stamp=String(r.t);" +
    "    if(!latestStamp[day]||Date.parse(stamp)>Date.parse(latestStamp[day])) latestStamp[day]=stamp;" +
    "  });" +
    "  var dayKeys=Object.keys(latestStamp).sort();" +
    "  if(dayKeys.length<2){ say('Need snapshots from at least two different days.'); return; }" +
    "  var maps={};" +
    "  dayKeys.forEach(function(day){ maps[day]={pkgs:{},vers:{},pkgTotal:0,verTotal:0}; });" +
    "  (C.rows||[]).forEach(function(r){" +
    "    var day=localDay(r.t); if(!day||String(r.t)!==latestStamp[day]) return;" +
    "    var key=r.ecosystem+'|'+r.level;" +
    "    maps[day].pkgs[key]=Number(r.packages)||0;" +
    "    maps[day].vers[key]=Number(r.versions)||0;" +
    "  });" +
    "  dayKeys.forEach(function(day){" +
    "    var bucket=maps[day];" +
    "    Object.keys(bucket.pkgs).forEach(function(k){ bucket.pkgTotal+=bucket.pkgs[k]; bucket.verTotal+=bucket.vers[k]||0; });" +
    "  });" +
    "  var end=dayKeys[dayKeys.length-1];" +
    "  var target=shiftDay(end,-3);" +
    "  var start='';" +
    "  for(var i=dayKeys.length-1;i>=0;i--){ if(dayKeys[i]<=target){ start=dayKeys[i]; break; } }" +
    "  if(!start||start===end){ say('Not enough history yet. A 3-day change shows after a snapshot from three days earlier.'); return; }" +
    "  var now=maps[end], then=maps[start];" +
    "  var pkgDelta=now.pkgTotal-then.pkgTotal;" +
    "  var verDelta=now.verTotal-then.verTotal;" +
    "  if(range){" +
    "    range.textContent=(start===target" +
    "      ? (fmtDayLabel(start)+' → '+fmtDayLabel(end)+' · last snapshot each day')" +
    "      : ('Since '+fmtDayLabel(start)+' · nearest snapshot on or before '+fmtDayLabel(target)));" +
    "  }" +
    "  function card(label,delta,nowN,thenN){" +
    "    var pct=pctText(nowN,thenN);" +
    "    return '<article class=\"pulse-card\"><p class=\"pulse-kicker\">'+escHtml(label)+'</p>'+" +
    "      '<p class=\"pulse-num '+deltaClass(delta)+'\">'+escHtml(signed(delta))+'</p>'+" +
    "      '<p class=\"pulse-note\">'+escHtml(Number(nowN).toLocaleString())+' now'+(pct?' · '+pct:'')+' · was '+escHtml(Number(thenN).toLocaleString())+'</p></article>';" +
    "  }" +
    "  stats.innerHTML=card('Packages',pkgDelta,now.pkgTotal,then.pkgTotal)+card('Versions',verDelta,now.verTotal,then.verTotal);" +
    "  var strip=dayKeys.filter(function(day){ return day>=target && day<=end; });" +
    "  if(start<target) strip.unshift(start);" +
    "  if(daysEl){" +
    "    var prev=null;" +
    "    daysEl.innerHTML=strip.map(function(day){" +
    "      var total=maps[day].pkgTotal;" +
    "      var step=prev==null?null:(total-maps[prev].pkgTotal);" +
    "      var html='<article class=\"pulse-day\"><span>'+escHtml(fmtDayLabel(day))+'</span><strong>'+escHtml(total.toLocaleString())+'</strong>'+" +
    "        (step==null?'<span>baseline</span>':'<span class=\"'+deltaClass(step)+'\">'+escHtml(signed(step))+' packages</span>')+" +
    "        '</article>';" +
    "      prev=day; return html;" +
    "    }).join('');" +
    "  }" +
    "  var keys={};" +
    "  Object.keys(now.pkgs).forEach(function(k){ keys[k]=true; });" +
    "  Object.keys(then.pkgs).forEach(function(k){ keys[k]=true; });" +
    "  var rows=Object.keys(keys).map(function(k){" +
    "    var parts=k.split('|');" +
    "    return {name:titleWord(parts[0]),level:titleWord(parts[1]||''),pkg:(now.pkgs[k]||0)-(then.pkgs[k]||0),ver:(now.vers[k]||0)-(then.vers[k]||0)};" +
    "  }).sort(function(a,b){ return Math.abs(b.pkg)-Math.abs(a.pkg)||(b.pkg-a.pkg); });" +
    "  var maxAbs=rows.reduce(function(m,r){ return Math.max(m,Math.abs(r.pkg)); },0);" +
    "  list.innerHTML=rows.map(function(r){" +
    "    var width=!r.pkg||!maxAbs?0:Math.max(6,Math.round(Math.abs(r.pkg)/maxAbs*100));" +
    "    return '<div class=\"pulse-row\"><div class=\"pulse-name\">'+escHtml(r.name)+'<small>'+escHtml(r.level)+'</small></div>'+" +
    "      '<div class=\"pulse-track\" aria-hidden=\"true\"><i class=\"'+(r.pkg<0?'is-down':'')+'\" style=\"width:'+width+'%\"></i></div>'+" +
    "      '<div class=\"pulse-delta '+deltaClass(r.pkg)+'\">'+escHtml(signed(r.pkg))+'<small>'+escHtml(signed(r.ver))+' versions</small></div></div>';" +
    "  }).join('');" +
    "}" +
    "function renderSnapshotDelta(days){" +
    "  days=Math.max(1,Math.round(Number(days)||1));" +
    "  document.querySelectorAll('#snapshotDelta .seg-btn').forEach(function(b){" +
    "    var on=Number(b.getAttribute('data-days'))===days;" +
    "    b.classList.toggle('is-active',on);" +
    "    b.setAttribute('aria-pressed',on?'true':'false');" +
    "  });" +
    "  var note=document.getElementById('snapshotDeltaNote');" +
    "  var latestStamp={};" +
    "  (C.rows||[]).forEach(function(r){" +
    "    var day=localDay(r.t); if(!day) return;" +
    "    var stamp=String(r.t);" +
    "    if(!latestStamp[day]||Date.parse(stamp)>Date.parse(latestStamp[day])) latestStamp[day]=stamp;" +
    "  });" +
    "  var dayKeys=Object.keys(latestStamp).sort();" +
    "  var maps={};" +
    "  dayKeys.forEach(function(day){ maps[day]={pkgs:{},vers:{}}; });" +
    "  (C.rows||[]).forEach(function(r){" +
    "    var day=localDay(r.t); if(!day||String(r.t)!==latestStamp[day]) return;" +
    "    var key=r.ecosystem+'|'+r.level;" +
    "    maps[day].pkgs[key]=Number(r.packages)||0;" +
    "    maps[day].vers[key]=Number(r.versions)||0;" +
    "  });" +
    "  var end=dayKeys.length?dayKeys[dayKeys.length-1]:'';" +
    "  var target=end?shiftDay(end,-days):'';" +
    "  var start='';" +
    "  for(var i=0;i<dayKeys.length;i++){ if(dayKeys[i]>=target && dayKeys[i]<end){ start=dayKeys[i]; break; } }" +
    "  if(!start){ for(var j=dayKeys.length-1;j>=0;j--){ if(dayKeys[j]<=target){ start=dayKeys[j]; break; } } }" +
    "  var comparable=!!(start&&end&&start!==end);" +
    "  if(note){" +
    "    if(!end) note.textContent='No snapshot yet.';" +
    "    else if(!comparable) note.textContent='No earlier snapshot to compare.';" +
    "    else if(start===target) note.textContent='Added since '+fmtDayLabel(start)+' · last snapshot that day';" +
    "    else note.textContent='Added since '+fmtDayLabel(start)+' · earliest snapshot in the last '+days+' day'+(days===1?'':'s');" +
    "  }" +
    "  document.querySelectorAll('#snapshotTable tbody tr[data-series]').forEach(function(tr){" +
    "    var key=tr.getAttribute('data-series')||'';" +
    "    tr.querySelectorAll('.metric').forEach(function(el){" +
    "      var now=Number(el.getAttribute('data-value'))||0;" +
    "      var delta=null;" +
    "      if(comparable){" +
    "        var bucket=el.getAttribute('data-metric')==='versions'?'vers':'pkgs';" +
    "        delta=now-(maps[start][bucket][key]||0);" +
    "      }" +
    "      var badge=delta==null?'':'<span class=\"delta-badge '+deltaClass(delta)+'\">'+escHtml(signed(delta))+'</span>';" +
    "      el.innerHTML=escHtml(now.toLocaleString())+badge;" +
    "    });" +
    "  });" +
    "}" +
    "document.querySelectorAll('#snapshotDelta .seg-btn').forEach(function(btn){" +
    "  btn.addEventListener('click',function(){" +
    "    renderSnapshotDelta(Number(btn.getAttribute('data-days'))||1);" +
    "  });" +
    "});" +
    "renderSnapshotDelta(1);" +
    "renderChart(chartDays);" +
    "renderPulse();" +
    "var allHist=Array.prototype.slice.call(document.querySelectorAll('#historyBody tr.hist-row'));" +
    "var page=1; var pageSize=C.pageSize||24;" +
    "var filtered=allHist.slice();" +
    "var fromEl=document.getElementById('histFrom');" +
    "var toEl=document.getElementById('histTo');" +
    "var countEl=document.getElementById('historyCountLabel');" +
    "function applyDateFilter(){" +
    "  var from=fromEl&&fromEl.value||'';" +
    "  var to=toEl&&toEl.value||'';" +
    "  filtered=allHist.filter(function(tr){" +
    "    var day=localDay(tr.getAttribute('data-iso')||'');" +
    "    if(from&&day<from) return false;" +
    "    if(to&&day>to) return false;" +
    "    return true;" +
    "  });" +
    "  page=1; renderPager();" +
    "}" +
    "function renderPager(){" +
    "  allHist.forEach(function(tr){tr.hidden=true;});" +
    "  var pager=document.getElementById('historyPager');" +
    "  if(!filtered.length){" +
    "    if(countEl) countEl.textContent='0 Rows';" +
    "    if(pager) pager.hidden=true;" +
    "    return;" +
    "  }" +
    "  var pages=Math.max(1,Math.ceil(filtered.length/pageSize));" +
    "  if(page>pages) page=pages; if(page<1) page=1;" +
    "  var start=(page-1)*pageSize; var end=start+pageSize;" +
    "  filtered.forEach(function(tr,i){ tr.hidden=i<start||i>=end; });" +
    "  var shown=Math.min(end,filtered.length)-start;" +
    "  if(countEl) countEl.textContent=filtered.length+' Row'+(filtered.length===1?'':'s');" +
    "  var label=document.getElementById('histPageLabel');" +
    "  if(label) label.textContent='Page '+page+' of '+pages+' · '+(start+1)+'–'+(start+shown)+' of '+filtered.length;" +
    "  var prev=document.getElementById('histPrev'); var next=document.getElementById('histNext');" +
    "  if(prev) prev.disabled=page<=1;" +
    "  if(next) next.disabled=page>=pages;" +
    "  if(pager) pager.hidden=false;" +
    "}" +
    "if(fromEl) fromEl.addEventListener('change',applyDateFilter);" +
    "if(toEl) toEl.addEventListener('change',applyDateFilter);" +
    "var clearBtn=document.getElementById('histClearDates');" +
    "if(clearBtn) clearBtn.addEventListener('click',function(){ if(fromEl) fromEl.value=''; if(toEl) toEl.value=''; applyDateFilter(); });" +
    "var prev=document.getElementById('histPrev'); var next=document.getElementById('histNext');" +
    "var sizeSel=document.getElementById('histPageSize');" +
    "if(prev) prev.addEventListener('click',function(){ page-=1; renderPager(); });" +
    "if(next) next.addEventListener('click',function(){ page+=1; renderPager(); });" +
    "if(sizeSel) sizeSel.addEventListener('change',function(){ pageSize=Number(sizeSel.value)||24; page=1; renderPager(); });" +
    "applyDateFilter();" +
    "})();"
  );
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
    ".topnav{display:flex;flex-wrap:wrap;gap:.4rem;margin:0 0 1.35rem;padding:.35rem;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.03);width:fit-content;max-width:100%}" +
    ".topnav a{text-decoration:none;color:var(--muted);font-weight:700;font-size:.82rem;letter-spacing:.02em;padding:.48rem .9rem;border-radius:999px}" +
    ".topnav a:hover{color:var(--ink);text-decoration:none}" +
    ".topnav a.is-active{background:rgba(74,222,128,.16);color:#bbf7d0}" +
    ".hero{display:flex;flex-wrap:wrap;align-items:flex-end;justify-content:space-between;gap:1.25rem 1.5rem;margin-bottom:1.5rem;padding-bottom:1.35rem;border-bottom:1px solid var(--line)}" +
    ".hero-copy{flex:1 1 18rem;min-width:0}" +
    ".eyebrow{margin:0 0 .65rem;font-size:.7rem;font-weight:700;letter-spacing:.16em;text-transform:uppercase;color:var(--accent)}" +
    "h1{font-family:Sora,ui-sans-serif,sans-serif;font-weight:700;font-size:clamp(1.65rem,3.2vw,2.4rem);margin:0 0 .65rem;letter-spacing:-.035em;line-height:1.12}" +
    ".sub{color:var(--muted);margin:0;max-width:40rem;font-size:.98rem}" +
    ".latest-line{margin:.85rem 0 0;color:var(--muted);font-size:.92rem;line-height:1.45}" +
    ".latest-line strong{display:inline-block;margin-top:.2rem;color:var(--ink);font-family:Sora,ui-sans-serif,sans-serif;font-size:1.05rem;font-weight:700;letter-spacing:-.02em}" +
    ".hero-actions{display:flex;flex-wrap:wrap;gap:.6rem}" +
    ".btn{display:inline-flex;align-items:center;justify-content:center;font:inherit;font-weight:600;font-size:.9rem;text-decoration:none;border-radius:999px;padding:.62rem 1.05rem;border:1px solid transparent;transition:transform .15s ease,background .15s ease,border-color .15s ease}" +
    ".btn:hover{transform:translateY(-1px);text-decoration:none}" +
    ".btn-primary{background:var(--accent);color:#052e16;border-color:transparent}" +
    ".btn-primary:hover{background:#86efac}" +
    ".btn-ghost{background:rgba(255,255,255,.03);color:var(--ink);border-color:var(--line)}" +
    ".btn-ghost:hover{border-color:rgba(255,255,255,.2);background:rgba(255,255,255,.06)}" +
    "code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.86em;color:#e5e7eb;background:rgba(255,255,255,.04);border:1px solid var(--line);border-radius:6px;padding:.1rem .35rem}" +
    ".notice{background:rgba(74,222,128,.08);border:1px solid rgba(74,222,128,.25);border-radius:14px;padding:.8rem 1rem;margin:0 0 1.15rem;color:#bbf7d0;font-size:.92rem}" +
    ".stats{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.75rem;margin-bottom:1.15rem}" +
    ".stats-3{grid-template-columns:repeat(3,minmax(0,1fr))}" +
    "@media (max-width:820px){.stats,.stats-3{grid-template-columns:repeat(2,minmax(0,1fr))}}" +
    "@media (max-width:520px){.stats,.stats-3{grid-template-columns:1fr}}" +
    ".stat{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:1rem 1.05rem;backdrop-filter:blur(10px)}" +
    ".stat-label{margin:0;color:var(--muted);font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}" +
    ".stat-value{margin:.35rem 0 0;font-family:Sora,ui-sans-serif,sans-serif;font-size:1.45rem;font-weight:700;letter-spacing:-.03em;font-variant-numeric:tabular-nums}" +
    ".pulse-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:.35rem .8rem;margin-bottom:.85rem}" +
    ".pulse-head h2{margin:0}" +
    ".pulse-stats{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:.75rem;margin-bottom:.9rem}" +
    "@media (max-width:520px){.pulse-stats{grid-template-columns:1fr}}" +
    ".pulse-card{border:1px solid var(--line);border-radius:14px;padding:.85rem .95rem;background:#0a0a0a}" +
    ".pulse-card p{margin:0}" +
    ".pulse-kicker{color:var(--muted);font-size:.72rem;font-weight:700;letter-spacing:.08em;text-transform:uppercase}" +
    ".pulse-num{margin-top:.3rem;font-family:Sora,ui-sans-serif,sans-serif;font-size:1.7rem;font-weight:700;letter-spacing:-.03em;font-variant-numeric:tabular-nums}" +
    ".pulse-note{margin-top:.2rem;color:var(--muted);font-size:.82rem}" +
    ".delta-up{color:#4ade80}" +
    ".delta-down{color:#fb7185}" +
    ".delta-flat{color:var(--muted)}" +
    ".pulse-days{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.55rem;margin-bottom:.95rem}" +
    "@media (max-width:720px){.pulse-days{grid-template-columns:repeat(2,minmax(0,1fr))}}" +
    ".pulse-day{border:1px solid var(--line);border-radius:12px;padding:.65rem .7rem;background:rgba(255,255,255,.02)}" +
    ".pulse-day strong{display:block;margin-top:.15rem;font-variant-numeric:tabular-nums}" +
    ".pulse-day span{color:var(--muted);font-size:.75rem}" +
    ".pulse-day span.delta-up{color:#4ade80}" +
    ".pulse-day span.delta-down{color:#fb7185}" +
    ".pulse-row{display:grid;grid-template-columns:minmax(9rem,1.15fr) minmax(0,1.6fr) auto;gap:.65rem .8rem;align-items:center;padding:.62rem 0;border-top:1px solid var(--line)}" +
    "@media (max-width:640px){.pulse-row{grid-template-columns:1fr auto;align-items:start}.pulse-track{grid-column:1 / -1;grid-row:2}}" +
    ".pulse-name{font-weight:600;font-size:.9rem}" +
    ".pulse-name small{display:block;color:var(--muted);font-weight:600;font-size:.75rem}" +
    ".pulse-track{height:8px;border-radius:999px;background:rgba(255,255,255,.06);overflow:hidden}" +
    ".pulse-track i{display:block;height:100%;border-radius:999px;background:#4ade80}" +
    ".pulse-track i.is-down{background:#fb7185}" +
    ".pulse-delta{text-align:right;font-variant-numeric:tabular-nums;font-weight:700}" +
    ".pulse-delta small{display:block;color:var(--muted);font-weight:600;font-size:.75rem}" +
    ".panel{background:var(--panel);border:1px solid var(--line);border-radius:18px;padding:1.2rem 1.25rem 1.3rem;margin-bottom:1rem;backdrop-filter:blur(12px);box-shadow:0 20px 50px rgba(0,0,0,.35)}" +
    "h2{margin:0 0 .85rem;font-family:Sora,ui-sans-serif,sans-serif;font-size:1.02rem;font-weight:600;letter-spacing:-.02em;color:var(--ink)}" +
    ".section-head{display:flex;flex-wrap:wrap;align-items:baseline;justify-content:space-between;gap:.5rem .85rem;margin-bottom:.55rem}" +
    ".section-head-stack{flex-direction:column;align-items:stretch;gap:.75rem}" +
    ".section-title-row{display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:.65rem .85rem}" +
    ".trend-controls{display:flex;flex-wrap:wrap;align-items:center;justify-content:flex-end;gap:.45rem}" +
    ".section-head h2{margin:0}" +
    ".section-head .chart-sub{margin:0}" +
    ".chart-sub{margin:-.2rem 0 .85rem;color:var(--muted);font-size:.88rem}" +
    ".seg{display:inline-flex;padding:3px;border-radius:999px;background:rgba(255,255,255,.04);border:1px solid var(--line);gap:2px}" +
    ".seg-btn{appearance:none;border:0;background:transparent;color:var(--muted);font:inherit;font-weight:700;font-size:.78rem;letter-spacing:.04em;padding:.42rem .78rem;border-radius:999px;cursor:pointer;transition:background .15s ease,color .15s ease}" +
    ".seg-btn:hover{color:var(--ink)}" +
    ".seg-btn.is-active{background:rgba(74,222,128,.16);color:#bbf7d0}" +
    ".snapshot-note{margin:.25rem 0 0}" +
    ".metric{display:inline-flex;align-items:center;justify-content:flex-end;gap:.4rem}" +
    ".delta-badge{display:inline-flex;align-items:center;border-radius:999px;padding:.04rem .42rem;font-size:.72rem;font-weight:700;line-height:1.45;letter-spacing:.01em;font-variant-numeric:tabular-nums}" +
    ".delta-badge.delta-up{color:#bbf7d0;background:rgba(74,222,128,.16)}" +
    ".delta-badge.delta-down{color:#fecdd3;background:rgba(251,113,133,.16)}" +
    ".delta-badge.delta-flat{color:#a1a1aa;background:rgba(255,255,255,.06)}" +
    ".date-filters{display:flex;flex-wrap:wrap;align-items:end;gap:.65rem .75rem}" +
    ".date-field{display:flex;flex-direction:column;gap:.28rem;font-size:.72rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:var(--muted)}" +
    ".date-field input[type=date]{font:inherit;font-size:.9rem;font-weight:600;letter-spacing:0;text-transform:none;color:var(--ink);background:#0a0a0a;border:1px solid var(--line);border-radius:10px;padding:.48rem .65rem;min-width:9.5rem;color-scheme:dark}" +
    ".btn-text{appearance:none;border:0;background:transparent;color:var(--accent);font:inherit;font-weight:600;font-size:.88rem;cursor:pointer;padding:.45rem .2rem}" +
    ".btn-text:hover{text-decoration:underline}" +
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

function errorPage_(title, messageHtml, webAppKey) {
  var hrefStatus = webAppHref_({ action: "status", key: webAppKey || "" });
  return (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>" +
    "<title>" +
    esc_(title) +
    "</title>" +
    "<link rel='icon' href='https://www.redhat.com/favicon.ico' type='image/x-icon'/>" +
    "<style>" +
    catalogCss_() +
    "</style></head><body><div class='glow glow-a' aria-hidden='true'></div>" +
    "<main class='fade-in'>" +
    "<h1>" +
    esc_(title) +
    "</h1>" +
    "<section class='panel'>" +
    messageHtml +
    "</section>" +
    "<footer><a href='" +
    esc_(hrefStatus) +
    "' target='_top' rel='noopener'>Back To Dashboard</a></footer>" +
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
