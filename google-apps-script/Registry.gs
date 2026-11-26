/**
 * Authenticated proxy for packages.redhat.com using Script Properties:
 *   LW_USER  — registry username (e.g. 1234567|my-sa)
 *   LW_TOKEN — registry token (Basic Auth password)
 *
 * Browser never sees credentials. Web app access should stay "Only myself" / org + WEBAPP_KEY.
 */

var REGISTRY_ORIGIN = "https://packages.redhat.com";
var REGISTRY_PREFIX = "https://packages.redhat.com/lightwell/";
/** Python simple indexes link artifacts here, not under /lightwell/. */
var REGISTRY_PULP_PREFIX = "https://packages.redhat.com/api/pulp-content/lightwell/";

function getRegistryBasicAuthHeader_() {
  var props = PropertiesService.getScriptProperties();
  var user = (props.getProperty("LW_USER") || "").trim();
  var token = (props.getProperty("LW_TOKEN") || "").trim();
  if (!user || !token) {
    throw new Error(
      "Missing Script Properties LW_USER / LW_TOKEN (registry Basic Auth for packages.redhat.com)"
    );
  }
  return "Basic " + Utilities.base64Encode(user + ":" + token);
}

function stripFragment_(url) {
  var u = String(url || "").trim();
  var hash = u.indexOf("#");
  return hash === -1 ? u : u.slice(0, hash);
}

function isAllowedRegistryUrl_(url) {
  var u = stripFragment_(url);
  var allowed =
    u.indexOf(REGISTRY_PREFIX) === 0 || u.indexOf(REGISTRY_PULP_PREFIX) === 0;
  if (!allowed) {
    return false;
  }
  // Block credential-injection style URLs and traversal noise
  if (u.indexOf("@") !== -1 || u.indexOf("..") !== -1) {
    return false;
  }
  return true;
}

/**
 * Prefer ?path=lightwell/java/... (no nested https:// in the query).
 * Nested full URLs in ?u= are mangled by Google's web-app frontend and
 * often surface as Drive "Sorry, unable to open the file at present."
 */
function registryPathFromUrl_(url) {
  var u = String(url || "").trim();
  if (u.indexOf(REGISTRY_ORIGIN + "/") === 0) {
    return u.slice((REGISTRY_ORIGIN + "/").length);
  }
  return "";
}

function resolveRegistryTarget_(params) {
  params = params || {};
  var full = String(params.u || "").trim();
  if (full && isAllowedRegistryUrl_(full)) {
    return full;
  }
  var path = String(params.path || "")
    .trim()
    .replace(/^\/+/, "");
  if (!path || path.indexOf("..") !== -1 || path.indexOf("@") !== -1) {
    return "";
  }
  // Folder listings live under /lightwell/…; Python files live under pulp-content.
  if (
    path.indexOf("lightwell/") !== 0 &&
    path.indexOf("api/pulp-content/lightwell/") !== 0
  ) {
    return "";
  }
  var target = REGISTRY_ORIGIN + "/" + path;
  return isAllowedRegistryUrl_(target) ? target : "";
}

function registryProxyHref_(targetUrl, linkKey) {
  var path = registryPathFromUrl_(targetUrl);
  if (path) {
    return webAppHref_({ page: "registry", key: linkKey, path: path });
  }
  if (isAllowedRegistryUrl_(targetUrl)) {
    return webAppHref_({ page: "registry", key: linkKey, u: targetUrl });
  }
  return webAppHref_({ page: "browser", key: linkKey });
}

function absolutizeRegistryUrl_(baseUrl, href) {
  href = String(href || "").trim();
  if (!href || href.charAt(0) === "#") {
    return href;
  }
  if (/^https?:\/\//i.test(href)) {
    return href;
  }
  if (href.indexOf("//") === 0) {
    return "https:" + href;
  }
  try {
    var base = String(baseUrl || REGISTRY_PREFIX);
    if (href.charAt(0) === "/") {
      return REGISTRY_ORIGIN + href;
    }
    // Directory-aware join
    var dir = base.replace(/\/[^\/]*$/, "/");
    if (base.slice(-1) === "/") {
      dir = base;
    }
    return dir + href;
  } catch (err) {
    return href;
  }
}

function rewriteRegistryHtml_(html, baseUrl, linkKey) {
  return String(html || "").replace(
    /href\s*=\s*(["'])([^"']*)\1/gi,
    function (match, quote, href) {
      var raw = String(href || "").trim();
      if (!raw || raw.charAt(0) === "#" || /^mailto:/i.test(raw) || /^javascript:/i.test(raw)) {
        return match;
      }
      var abs = stripFragment_(absolutizeRegistryUrl_(baseUrl, stripFragment_(raw)));
      if (isAllowedRegistryUrl_(abs)) {
        var proxy = registryProxyHref_(abs, linkKey);
        return "href=" + quote + proxy + quote + ' target="_top"';
      }
      return match;
    }
  );
}

function wrapRegistryViewer_(innerHtml, targetUrl, linkKey) {
  var back = webAppHref_({ page: "browser", key: linkKey });
  return (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>" +
    "<meta name='color-scheme' content='dark'/>" +
    "<title>Lightwell Registry</title>" +
    "<link rel='icon' href='https://www.redhat.com/favicon.ico' type='image/x-icon'/>" +
    "<link rel='preconnect' href='https://fonts.googleapis.com'/>" +
    "<link href='https://fonts.googleapis.com/css2?family=Sora:wght@600;700&family=Manrope:wght@400;600&display=swap' rel='stylesheet'/>" +
    "<style>" +
    "body{margin:0;font-family:Manrope,sans-serif;background:#000;color:#fafafa}" +
    ".bar{display:flex;flex-wrap:wrap;gap:.75rem;align-items:center;justify-content:space-between;" +
    "padding:.85rem 1.1rem;border-bottom:1px solid rgba(255,255,255,.08);background:#0a0a0a;position:sticky;top:0;z-index:2}" +
    ".bar a{color:#4ade80;text-decoration:none;font-weight:600}" +
    ".path{font-family:ui-monospace,Menlo,monospace;font-size:.78rem;color:#9ca3af;word-break:break-all}" +
    ".frame{padding:1rem 1.1rem 2rem}" +
    ".frame a{color:#86efac}" +
    ".frame body, .frame{color:#e5e7eb}" +
    "pre,tt,code{font-family:ui-monospace,Menlo,monospace}" +
    "</style></head><body>" +
    "<div class='bar'>" +
    "<div><a href='" +
    esc_(back) +
    "' target='_top'>← Catalog Browser</a>" +
    "<div class='path'>" +
    esc_(targetUrl) +
    "</div></div>" +
    "<div class='path'>Authenticated via LW_USER / LW_TOKEN</div>" +
    "</div>" +
    "<div class='frame'>" +
    innerHtml +
    "</div></body></html>"
  );
}

function serveRegistryBinaryPage_(response, targetUrl, linkKey) {
  var headers = response.getHeaders() || {};
  var contentType = String(
    headers["Content-Type"] || headers["content-type"] || "application/octet-stream"
  );
  var bytes = response.getContent();
  var size = bytes ? bytes.length : 0;
  var name = String(targetUrl).replace(/\/+$/, "").split("/").pop() || "download";
  var back = webAppHref_({ page: "browser", key: linkKey });
  var maxInline = 4 * 1024 * 1024;
  var downloadBlock = "";
  if (size > 0 && size <= maxInline) {
    var b64 = Utilities.base64Encode(bytes);
    downloadBlock =
      "<p><a class='btn' download='" +
      esc_(name) +
      "' href='data:" +
      esc_(contentType) +
      ";base64," +
      b64 +
      "'>Download " +
      esc_(name) +
      "</a></p>";
  } else {
    downloadBlock =
      "<p class='muted'>File is " +
      Number(size).toLocaleString() +
      " bytes — too large to inline through Apps Script. " +
      "Use the local downloader with LW_USER / LW_TOKEN, or open a smaller listing page.</p>";
  }
  var html =
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>" +
    "<title>" +
    esc_(name) +
    "</title>" +
    "<link rel='icon' href='https://www.redhat.com/favicon.ico' type='image/x-icon'/>" +
    "<style>" +
    "body{margin:0;font-family:Manrope,sans-serif;background:#000;color:#fafafa;padding:2rem 1.25rem}" +
    "a{color:#4ade80;font-weight:600;text-decoration:none}" +
    ".muted{color:#9ca3af}" +
    ".btn{display:inline-flex;padding:.65rem 1rem;border-radius:999px;background:#4ade80;color:#052e16}" +
    "code{font-family:ui-monospace,Menlo,monospace}" +
    "</style></head><body>" +
    "<p><a href='" +
    esc_(back) +
    "' target='_top'>← Catalog Browser</a></p>" +
    "<h1>" +
    esc_(name) +
    "</h1>" +
    "<p class='muted'><code>" +
    esc_(targetUrl) +
    "</code></p>" +
    "<p>Type: <code>" +
    esc_(contentType) +
    "</code> · Size: " +
    Number(size).toLocaleString() +
    " bytes</p>" +
    downloadBlock +
    "</body></html>";
  return htmlOutput_(html, name);
}

function serveRegistryProxy_(params, linkKey) {
  var target = resolveRegistryTarget_(params);
  if (!target) {
    return htmlOutput_(
      errorPage_(
        "Registry Proxy",
        "<p>Missing or invalid registry target. Use <code>path=lightwell/…</code> (preferred) or <code>u=https://packages.redhat.com/lightwell/…</code>.</p>",
        linkKey
      ),
      "Registry Proxy"
    );
  }

  try {
    var res = UrlFetchApp.fetch(target, {
      method: "get",
      headers: {
        Authorization: getRegistryBasicAuthHeader_(),
        Accept: "text/html,application/xhtml+xml,application/json,*/*",
        "User-Agent": "lightwell-apps-script-registry-proxy/1.0",
      },
      muteHttpExceptions: true,
      followRedirects: true,
    });
    var code = res.getResponseCode();
    var headers = res.getHeaders() || {};
    var contentType = String(
      headers["Content-Type"] || headers["content-type"] || ""
    ).toLowerCase();

    if (code < 200 || code >= 300) {
      return htmlOutput_(
        errorPage_(
          "Registry Error",
          "<p>HTTP " +
            code +
            " fetching registry URL.</p><pre>" +
            esc_(res.getContentText().slice(0, 500)) +
            "</pre>" +
            "<p class='muted'>Check LW_USER / LW_TOKEN Script Properties.</p>",
          linkKey
        ),
        "Registry Error"
      );
    }

    if (
      contentType.indexOf("text/html") !== -1 ||
      contentType.indexOf("text/plain") !== -1 ||
      contentType.indexOf("application/xhtml") !== -1 ||
      (!contentType && /^\s*</.test(res.getContentText().slice(0, 40)))
    ) {
      var rewritten = rewriteRegistryHtml_(res.getContentText(), target, linkKey);
      return htmlOutput_(
        wrapRegistryViewer_(rewritten, target, linkKey),
        "Lightwell Registry"
      );
    }

    return serveRegistryBinaryPage_(res, target, linkKey);
  } catch (err) {
    return htmlOutput_(
      errorPage_(
        "Registry Proxy Failed",
        "<pre>" + esc_(String(err && err.message ? err.message : err)) + "</pre>",
        linkKey
      ),
      "Registry Proxy Failed"
    );
  }
}
