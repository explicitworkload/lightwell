/**
 * Daily package → severity index from the Lightwell OSV trees on packages.redhat.com.
 *
 * Trees: java/python × remediated/predisclosure.
 * Auth: LW_USER / LW_TOKEN (same Basic Auth as the registry proxy).
 * Store: osv-severity-index.json and osv-advisories.json in DRIVE_FOLDER_ID, or My Drive.
 * The advisory file is what CVE / RHLW Lookup searches (id, CVE, package, remediated release).
 *
 * Run syncOsvIndex once by hand, then installTriggers (08:00 and 15:00 Asia/Singapore).
 * A run that runs out of time saves a cursor and schedules syncOsvIndexContinue_.
 * syncOsvIndexForce rebuilds even when today's index is still fresh.
 */

var OSV_INDEX_NAME = "osv-severity-index.json";
var OSV_INDEX_PROP = "OSV_INDEX_FILE_ID";
var OSV_ADVISORY_NAME = "osv-advisories.json";
var OSV_ADVISORY_PROP = "OSV_ADVISORY_FILE_ID";
var OSV_CACHE_KEY = "osv_index_v1";
/** Skip a run only when the last successful index is under 6 hours old, so 15:00 still rebuilds after 08:00. */
var OSV_FRESH_MS = 6 * 60 * 60 * 1000;
var OSV_BUDGET_MS = 240000;
var OSV_BATCH = 20;
var OSV_TREES = [
  "https://packages.redhat.com/lightwell/osv/java/remediated/",
  "https://packages.redhat.com/lightwell/osv/java/predisclosure/",
  "https://packages.redhat.com/lightwell/osv/python/remediated/",
  "https://packages.redhat.com/lightwell/osv/python/predisclosure/",
];

function syncOsvIndex() {
  trustRuntimeOwner_();
  return syncOsvIndex_(false);
}

function syncOsvIndexForce() {
  trustRuntimeOwner_();
  return syncOsvIndex_(true);
}

function syncOsvIndexContinue_() {
  trustRuntimeOwner_();
  return syncOsvIndex_(false);
}

function syncOsvIndex_(force) {
  requireApproved_();
  var lock = LockService.getScriptLock();
  if (!lock.tryLock(8000)) {
    Logger.log("OSV sync skipped; another run holds the lock");
    return { ok: false, error: "OSV sync already running" };
  }
  try {
    var result = syncOsvIndexLocked_(!!force);
    Logger.log(JSON.stringify(result));
    return result;
  } catch (err) {
    var msg = String(err && err.message ? err.message : err);
    Logger.log(msg);
    return { ok: false, error: msg };
  } finally {
    lock.releaseLock();
  }
}

function syncOsvIndexLocked_(force) {
  var started = Date.now();
  var index = readOsvIndex_() || osvBlank_();
  if (!index.pkgs) index.pkgs = {};
  if (!index.draft) index.draft = {};
  if (!index.pending) index.pending = [];
  if (!index.advsDraft) index.advsDraft = [];

  if (!force && index.phase === "ready" && !osvIsStale_(index)) {
    return osvSummary_(index, true);
  }

  var auth = getRegistryBasicAuthHeader_();
  var resume = !force && index.phase === "fetching" && index.pending.length > 0;
  if (!resume) {
    index.phase = "fetching";
    index.draft = {};
    index.advsDraft = [];
    index.advsCollect = true;
    index.seen = 0;
    index.failed = 0;
    index.pending = osvCollectUrls_(auth);
    saveOsvIndex_(index);
  }

  var rateLimited = false;
  while (index.pending.length && Date.now() - started < OSV_BUDGET_MS) {
    var batch = index.pending.splice(0, OSV_BATCH);
    var requests = batch.map(function (url) {
      return {
        url: url,
        method: "get",
        headers: {
          Authorization: auth,
          Accept: "application/json",
        },
        muteHttpExceptions: true,
      };
    });
    var responses = UrlFetchApp.fetchAll(requests);
    for (var i = 0; i < responses.length; i++) {
      var code = responses[i].getResponseCode();
      if (code === 429) {
        index.pending = batch.slice(i).concat(index.pending);
        rateLimited = true;
        break;
      }
      if (code === 401 || code === 403) {
        index.pending = batch.slice(i).concat(index.pending);
        saveOsvIndex_(index);
        throw new Error(
          "Registry auth failed (" +
            code +
            ") while reading OSV. Check LW_USER / LW_TOKEN."
        );
      }
      index.seen += 1;
      if (code !== 200) {
        index.failed += 1;
        continue;
      }
      var record = null;
      try {
        record = JSON.parse(responses[i].getContentText() || "");
      } catch (ignore) {
        index.failed += 1;
        continue;
      }
      if (record && typeof record === "object") {
        osvIngest_(index.draft, record);
        if (index.advsCollect) osvPushAdvisory_(index.advsDraft, record);
      }
    }
    saveOsvIndex_(index);
    if (rateLimited) break;
  }

  if (index.pending.length) {
    scheduleOsvContinue_();
    return osvSummary_(index, false);
  }

  osvPublish_(index);
  saveOsvIndex_(index);
  clearOsvContinueTriggers_();
  return osvSummary_(index, false);
}

function osvBlank_() {
  return {
    updated_at: "",
    phase: "idle",
    pending: [],
    failed: 0,
    seen: 0,
    draft: {},
    pkgs: {},
    advsDraft: [],
    advsCollect: false,
    advisory_count: 0,
  };
}

function osvIsStale_(index) {
  var updated = Date.parse(index.updated_at || "");
  if (!isFinite(updated)) return true;
  return Date.now() - updated >= OSV_FRESH_MS;
}

function osvPublish_(index) {
  var advisories = index.advsDraft || [];
  if (index.advsCollect && advisories.length) {
    saveOsvAdvisories_(advisories);
    index.advisory_count = advisories.length;
  }
  index.advsDraft = [];
  index.advsCollect = false;
  index.pkgs = index.draft || {};
  index.draft = {};
  index.pending = [];
  index.phase = "ready";
  index.updated_at = new Date().toISOString();
}

function osvSummary_(index, skipped) {
  var pkgs = index.pkgs || {};
  return {
    ok: true,
    skipped: !!skipped,
    phase: index.phase || "idle",
    packages: Object.keys(pkgs).length,
    pending: (index.pending || []).length,
    seen: index.seen || 0,
    failed: index.failed || 0,
    updated_at: index.updated_at || "",
    advisories: index.advisory_count || (index.advsDraft || []).length || 0,
  };
}

function osvCollectUrls_(auth) {
  var pending = [];
  var seen = {};
  var readable = 0;
  var denied = [];
  for (var i = 0; i < OSV_TREES.length; i++) {
    var fetched = osvFetchText_(auth, OSV_TREES[i], "text/html");
    if (fetched.code === 401) {
      throw new Error(
        "Registry auth failed (401) listing " +
          OSV_TREES[i] +
          ". Check LW_USER / LW_TOKEN."
      );
    }
    if (fetched.code === 403) {
      denied.push(OSV_TREES[i]);
      Logger.log("OSV tree not entitled, skipped " + OSV_TREES[i]);
      continue;
    }
    if (fetched.code !== 200) {
      Logger.log("OSV tree skipped " + OSV_TREES[i] + " HTTP " + fetched.code);
      continue;
    }
    readable += 1;
    var urls = osvListJson_(fetched.text, OSV_TREES[i]);
    for (var j = 0; j < urls.length; j++) {
      if (!seen[urls[j]]) {
        seen[urls[j]] = true;
        pending.push(urls[j]);
      }
    }
  }
  if (!readable) {
    throw new Error(
      denied.length
        ? "Registry returned 403 for every OSV tree. Check LW_USER / LW_TOKEN and Lightwell entitlement."
        : "No OSV trees could be listed."
    );
  }
  pending.sort();
  Logger.log(
    "OSV listed " +
      pending.length +
      " advisories from " +
      readable +
      " trees" +
      (denied.length ? "; skipped " + denied.length + " not entitled" : "")
  );
  return pending;
}

function osvFetchText_(auth, url, accept) {
  var res = UrlFetchApp.fetch(url, {
    method: "get",
    headers: {
      Authorization: auth,
      Accept: accept || "*/*",
    },
    muteHttpExceptions: true,
  });
  var text = "";
  try {
    text = res.getContentText() || "";
  } catch (ignore) {
    text = "";
  }
  return { code: res.getResponseCode(), text: text };
}

function osvListJson_(html, baseUrl) {
  var re = /href\s*=\s*["']([^"']+)["']/gi;
  var out = [];
  var seen = {};
  var match;
  while ((match = re.exec(String(html || "")))) {
    var href = String(match[1] || "").trim();
    if (!href || href === "../" || href === "./" || href.charAt(0) === "#") continue;
    var path = href.split("?")[0].split("#")[0];
    var name = path.split("/").pop();
    if (!name || name.toLowerCase().slice(-5) !== ".json") continue;
    var abs = osvJoin_(baseUrl, href);
    if (!seen[abs]) {
      seen[abs] = true;
      out.push(abs);
    }
  }
  return out;
}

function osvJoin_(baseUrl, href) {
  if (/^https?:\/\//i.test(href)) return href;
  if (href.charAt(0) === "/") return "https://packages.redhat.com" + href;
  var base = String(baseUrl || "");
  if (base.charAt(base.length - 1) !== "/") base += "/";
  return base + href.replace(/^\.\//, "");
}

function scheduleOsvContinue_() {
  try {
    clearOsvContinueTriggers_();
    ScriptApp.newTrigger("syncOsvIndexContinue_")
      .timeBased()
      .after(60 * 1000)
      .create();
    Logger.log("Scheduled syncOsvIndexContinue_ in about 1 minute");
  } catch (err) {
    Logger.log("Could not schedule OSV continuation: " + err + " — run syncOsvIndex again");
  }
}

function clearOsvContinueTriggers_() {
  ScriptApp.getProjectTriggers().forEach(function (trigger) {
    if (trigger.getHandlerFunction() === "syncOsvIndexContinue_") {
      ScriptApp.deleteTrigger(trigger);
    }
  });
}

function osvIndexFile_(create) {
  requireApproved_();
  var props = PropertiesService.getScriptProperties();
  var id = props.getProperty(OSV_INDEX_PROP);
  if (id) {
    try {
      return DriveApp.getFileById(id);
    } catch (ignore) {
      props.deleteProperty(OSV_INDEX_PROP);
    }
  }
  var folderId = props.getProperty("DRIVE_FOLDER_ID");
  var existing = null;
  if (folderId) {
    var folder = DriveApp.getFolderById(folderId);
    var inFolder = folder.getFilesByName(OSV_INDEX_NAME);
    if (inFolder.hasNext()) existing = inFolder.next();
    else if (create) existing = folder.createFile(OSV_INDEX_NAME, "{}", MimeType.PLAIN_TEXT);
  } else {
    var anywhere = DriveApp.getFilesByName(OSV_INDEX_NAME);
    if (anywhere.hasNext()) existing = anywhere.next();
    else if (create) existing = DriveApp.createFile(OSV_INDEX_NAME, "{}", MimeType.PLAIN_TEXT);
  }
  if (existing) props.setProperty(OSV_INDEX_PROP, existing.getId());
  return existing;
}

function readOsvIndex_() {
  requireApproved_();
  var file = osvIndexFile_(false);
  if (!file) return null;
  var text = "";
  try {
    text = file.getBlob().getDataAsString() || "";
  } catch (ignore) {
    return null;
  }
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch (ignore) {
    return null;
  }
}

function saveOsvIndex_(index) {
  requireApproved_();
  var file = osvIndexFile_(true);
  file.setContent(JSON.stringify(index));
  try {
    CacheService.getScriptCache().remove(OSV_CACHE_KEY);
  } catch (ignore) {}
}

function osvAdvisoryFile_(create) {
  requireApproved_();
  var props = PropertiesService.getScriptProperties();
  var id = props.getProperty(OSV_ADVISORY_PROP);
  if (id) {
    try {
      return DriveApp.getFileById(id);
    } catch (ignore) {
      props.deleteProperty(OSV_ADVISORY_PROP);
    }
  }
  var folderId = props.getProperty("DRIVE_FOLDER_ID");
  var existing = null;
  if (folderId) {
    var folder = DriveApp.getFolderById(folderId);
    var inFolder = folder.getFilesByName(OSV_ADVISORY_NAME);
    if (inFolder.hasNext()) existing = inFolder.next();
    else if (create) existing = folder.createFile(OSV_ADVISORY_NAME, "{}", MimeType.PLAIN_TEXT);
  } else {
    var anywhere = DriveApp.getFilesByName(OSV_ADVISORY_NAME);
    if (anywhere.hasNext()) existing = anywhere.next();
    else if (create) existing = DriveApp.createFile(OSV_ADVISORY_NAME, "{}", MimeType.PLAIN_TEXT);
  }
  if (existing) props.setProperty(OSV_ADVISORY_PROP, existing.getId());
  return existing;
}

function readOsvAdvisories_() {
  requireApproved_();
  var file = osvAdvisoryFile_(false);
  if (!file) return null;
  var text = "";
  try {
    text = file.getBlob().getDataAsString() || "";
  } catch (ignore) {
    return null;
  }
  if (!text) return null;
  try {
    var parsed = JSON.parse(text);
    if (!parsed || !parsed.advisories) return null;
    return parsed;
  } catch (ignore) {
    return null;
  }
}

function saveOsvAdvisories_(rows) {
  requireApproved_();
  var file = osvAdvisoryFile_(true);
  file.setContent(
    JSON.stringify({
      updated_at: new Date().toISOString(),
      count: rows.length,
      advisories: rows,
    })
  );
}

function osvPushAdvisory_(bucket, record) {
  var compact = osvCompactAdvisory_(record);
  if (!compact || !compact.id) return;
  for (var i = 0; i < bucket.length; i++) {
    if (bucket[i].id === compact.id) return;
  }
  bucket.push(compact);
}

function osvCompactAdvisory_(record) {
  if (!record || typeof record !== "object") return null;
  var id = String(record.id || "").trim();
  if (!id) return null;
  var cves = [];
  var aliases = [];
  function addId(list, value) {
    var text = String(value || "").trim();
    if (!text) return;
    for (var i = 0; i < list.length; i++) {
      if (list[i].toLowerCase() === text.toLowerCase()) return;
    }
    list.push(text);
  }
  var upstream = record.upstream || [];
  for (var u = 0; u < upstream.length; u++) {
    var token = String(upstream[u] || "").trim();
    if (/^cve-/i.test(token)) addId(cves, token.toUpperCase());
    else addId(aliases, token);
  }
  var refs = record.references || [];
  var refUrls = [];
  for (var r = 0; r < refs.length && refUrls.length < 4; r++) {
    var ref = refs[r] || {};
    var url = String(ref.url || "").trim();
    if (!url) continue;
    var cveInUrl = url.match(/CVE-\d{4}-\d+/i);
    if (cveInUrl) addId(cves, cveInUrl[0].toUpperCase());
    if (String(ref.type || "").toUpperCase() === "ADVISORY") refUrls.push(url);
  }
  var packages = [];
  var affected = record.affected || [];
  for (var a = 0; a < affected.length; a++) {
    var item = affected[a] || {};
    var pkg = item.package || {};
    var name = String(pkg.name || "").trim();
    if (!name) continue;
    var lightwell = ((item.database_specific || {}).lightwell) || {};
    var fixed = [];
    function addFixed(value) {
      var text = String(value || "").trim();
      if (!text) return;
      for (var i = 0; i < fixed.length; i++) {
        if (fixed[i].toLowerCase() === text.toLowerCase()) return;
      }
      fixed.push(text);
    }
    addFixed(lightwell.remediated_version);
    var ranges = item.ranges || [];
    for (var ri = 0; ri < ranges.length; ri++) {
      var events = (ranges[ri] && ranges[ri].events) || [];
      for (var e = 0; e < events.length; e++) {
        if (events[e] && events[e].fixed) addFixed(events[e].fixed);
      }
    }
    packages.push({
      name: name,
      ecosystem: osvEcoLabel_(pkg.ecosystem),
      base: String(lightwell.backport_base_version || "").trim(),
      fixed: fixed,
    });
  }
  var score = osvCvssScore_(record);
  var details = String(record.details || "").trim();
  if (details.length > 1800) details = details.slice(0, 1800).replace(/\s+\S*$/, "") + "…";
  return {
    id: id,
    summary: String(record.summary || "").trim(),
    details: details,
    published: String(record.published || "").slice(0, 10),
    score: score > 0 ? score : null,
    severity: score > 0 ? osvLabel_(score) : "",
    cves: cves,
    aliases: aliases,
    refs: refUrls,
    packages: packages,
  };
}

function osvEcoLabel_(ecosystem) {
  var text = String(ecosystem || "").toLowerCase();
  if (text.indexOf("maven") !== -1 || text.indexOf("java") !== -1) return "Java";
  if (text.indexOf("pypi") !== -1 || text.indexOf("python") !== -1) return "Python";
  if (text.indexOf("npm") !== -1) return "npm";
  return "";
}

/**
 * Search the published OSV advisory catalog.
 * query: CVE-…, RHLW-…, GHSA-…, a remediated release (…rhlw…), or a package name.
 * minScore: optional CVSS floor. Empty query returns the highest scores.
 */
function lookupOsvAdvisories_(query, minScore) {
  requireApproved_();
  var doc = readOsvAdvisories_();
  if (!doc) {
    return { ok: true, status: "missing", updated_at: "", total: 0, data: [] };
  }
  var q = String(query || "").trim().toLowerCase();
  var min = minScore == null || minScore === "" ? null : Number(minScore);
  if (!isFinite(min)) min = null;
  var kind = "text";
  if (/^cve-\d{4}-/.test(q)) kind = "cve";
  else if (/^ghsa-/.test(q)) kind = "alias";
  else if (/^rhlw-20\d{2}(?:-|$)/.test(q)) kind = "id";
  else if (q.indexOf("rhlw") !== -1) kind = "release";
  var matches = [];
  var rows = doc.advisories || [];
  for (var i = 0; i < rows.length; i++) {
    var row = rows[i];
    if (min != null && !(Number(row.score) >= min)) continue;
    if (q && !osvAdvisoryHit_(row, q, kind)) continue;
    matches.push(row);
  }
  matches.sort(function (a, b) {
    var score = (Number(b.score) || 0) - (Number(a.score) || 0);
    if (score) return score;
    return String(b.published || "").localeCompare(String(a.published || ""));
  });
  return {
    ok: true,
    status: "ready",
    updated_at: doc.updated_at || "",
    total: matches.length,
    data: matches.slice(0, 80),
  };
}

function osvAdvisoryHit_(row, q, kind) {
  function has(list, exact) {
    var items = list || [];
    for (var i = 0; i < items.length; i++) {
      var text = String(items[i] || "").toLowerCase();
      if (exact ? text === q : text.indexOf(q) !== -1) return true;
    }
    return false;
  }
  if (kind === "cve") return has(row.cves, false);
  if (kind === "alias") return has(row.aliases, false);
  if (kind === "id") return String(row.id || "").toLowerCase().indexOf(q) !== -1;
  if (kind === "release") {
    var packages = row.packages || [];
    for (var p = 0; p < packages.length; p++) {
      if (has(packages[p].fixed, false)) return true;
    }
    return false;
  }
  if (String(row.id || "").toLowerCase().indexOf(q) !== -1) return true;
  if (String(row.summary || "").toLowerCase().indexOf(q) !== -1) return true;
  if (has(row.cves, false) || has(row.aliases, false)) return true;
  var pkgs = row.packages || [];
  for (var i = 0; i < pkgs.length; i++) {
    var name = String(pkgs[i].name || "").toLowerCase();
    if (name.indexOf(q) !== -1) return true;
    var colon = name.lastIndexOf(":");
    if (colon !== -1 && name.slice(colon + 1).indexOf(q) !== -1) return true;
  }
  return false;
}

function loadOsvIndex_() {
  requireApproved_();
  var cache = CacheService.getScriptCache();
  try {
    var cached = cache.get(OSV_CACHE_KEY);
    if (cached) return JSON.parse(cached);
  } catch (ignore) {}
  var index = readOsvIndex_();
  if (!index) return null;
  try {
    var text = JSON.stringify(index);
    if (text.length < 90000) cache.put(OSV_CACHE_KEY, text, 300);
  } catch (ignore) {}
  return index;
}

function osvIngest_(draft, record) {
  var score = osvCvssScore_(record);
  if (!(score > 0)) return;
  var affected = record.affected || [];
  for (var i = 0; i < affected.length; i++) {
    var item = affected[i] || {};
    var pkg = item.package || {};
    var names = osvPackageKeys_(pkg.name, pkg.purl);
    if (!names.length) continue;
    var versions = [];
    var lightwell = ((item.database_specific || {}).lightwell) || {};
    if (lightwell.remediated_version) versions.push(lightwell.remediated_version);
    var ranges = item.ranges || [];
    for (var r = 0; r < ranges.length; r++) {
      var events = (ranges[r] && ranges[r].events) || [];
      for (var e = 0; e < events.length; e++) {
        if (events[e] && events[e].fixed) versions.push(events[e].fixed);
      }
    }
    var seenVer = {};
    for (var v = 0; v < versions.length; v++) {
      var canonical = osvCanonical_(versions[v]);
      if (!canonical || seenVer[canonical]) continue;
      seenVer[canonical] = true;
      for (var n = 0; n < names.length; n++) {
        if (!draft[names[n]]) draft[names[n]] = {};
        osvRemember_(draft[names[n]], versions[v], score);
      }
    }
  }
}

function osvPackageKeys_(name, purl) {
  var keys = {};
  function add(value) {
    var text = String(value || "").trim().toLowerCase();
    if (text) keys[text] = true;
  }
  add(name);
  var raw = String(name || "");
  var colon = raw.lastIndexOf(":");
  if (colon !== -1) add(raw.slice(colon + 1));
  var path = String(purl || "");
  var at = path.indexOf("@");
  if (at !== -1) path = path.slice(0, at);
  var maven = path.match(/^pkg:[^/]+\/(.+)\/([^/@]+)$/i);
  if (maven) {
    add(maven[2]);
    add(String(maven[1]).replace(/\//g, ".") + ":" + maven[2]);
  } else {
    var slash = path.lastIndexOf("/");
    if (slash !== -1) add(path.slice(slash + 1));
  }
  return Object.keys(keys);
}

function osvLookupNames_(rows, packageName) {
  var keys = {};
  function add(value) {
    var text = String(value || "").trim().toLowerCase();
    if (text) keys[text] = true;
  }
  add(packageName);
  (rows || []).forEach(function (row) {
    add(row && row.name);
    if (row && row.group && row.name) add(String(row.group) + ":" + String(row.name));
    add(row && row.coordinates);
    var path = String((row && row.purl) || "");
    var at = path.indexOf("@");
    if (at !== -1) path = path.slice(0, at);
    var maven = path.match(/^pkg:[^/]+\/(.+)\/([^/@]+)$/i);
    if (maven) {
      add(maven[2]);
      add(String(maven[1]).replace(/\//g, ".") + ":" + maven[2]);
    } else {
      var slash = path.lastIndexOf("/");
      if (slash !== -1) add(path.slice(slash + 1));
    }
  });
  return Object.keys(keys);
}

function osvCanonical_(version) {
  var value = String(version || "").trim().toLowerCase();
  var match = value.match(/^(.*)([.+-])(rhlw(?:[.+-].*)?)$/);
  if (match && match[1]) return match[1] + "-" + match[3];
  return value;
}

function osvVersionAliases_(version) {
  var value = String(version || "").trim().toLowerCase();
  if (!value) return [];
  var out = {};
  out[value] = true;
  out[osvCanonical_(value)] = true;
  var match = value.match(/^(.*)([.+-])(rhlw(?:[.+-].*)?)$/);
  if (match && match[1]) {
    out[match[1] + "." + match[3]] = true;
    out[match[1] + "-" + match[3]] = true;
    out[match[1] + "+" + match[3]] = true;
  }
  return Object.keys(out);
}

function osvRemember_(bucket, version, score) {
  var primary = osvCanonical_(version);
  if (!primary || !(score > 0)) return;
  var current = bucket[primary];
  if (!current || typeof current === "string" || typeof current.s !== "number") {
    current = { s: 0, n: 0 };
  }
  current.n += 1;
  if (score > current.s) current.s = score;
  bucket[primary] = current;
  var aliases = osvVersionAliases_(version);
  for (var i = 0; i < aliases.length; i++) {
    if (aliases[i] === primary) continue;
    if (bucket[aliases[i]] == null || typeof bucket[aliases[i]] === "string") {
      bucket[aliases[i]] = primary;
    }
  }
}

function osvResolveEntry_(bucket, key) {
  var seen = {};
  var current = String(key || "");
  for (var guard = 0; guard < 5; guard++) {
    if (!current || seen[current]) return null;
    seen[current] = true;
    var value = bucket[current];
    if (!value) return null;
    if (typeof value === "string") {
      current = value;
      continue;
    }
    if (typeof value.s === "number") return { id: current, entry: value };
    return null;
  }
  return null;
}

function osvReadablePkgs_(index) {
  if (!index) return null;
  var pkgs = index.pkgs || {};
  if (Object.keys(pkgs).length) return pkgs;
  var draft = index.draft || {};
  if (Object.keys(draft).length) return draft;
  return null;
}

function osvStatus_(index) {
  if (!index) return "missing";
  var pkgs = index.pkgs || {};
  if (Object.keys(pkgs).length) return "ready";
  var draft = index.draft || {};
  if (Object.keys(draft).length || index.phase === "fetching" || index.phase === "listing") {
    return "partial";
  }
  return "missing";
}

function osvLabel_(score) {
  if (score >= 9) return "critical";
  if (score >= 7) return "important";
  if (score >= 4) return "moderate";
  if (score > 0) return "low";
  return "";
}

function osvBucketsFor_(pkgs, row, packageName) {
  var names = osvLookupNames_([row], packageName || (row && row.name));
  var buckets = [];
  for (var i = 0; i < names.length; i++) {
    if (pkgs[names[i]]) buckets.push(pkgs[names[i]]);
  }
  return buckets;
}

/** Set severity, severity_score, and cve_count on one version row. */
function osvApplyRow_(pkgs, row, packageName) {
  var buckets = osvBucketsFor_(pkgs, row, packageName);
  if (!buckets.length) return false;
  var keys = versionMatchKeys_(row);
  var found = {};
  Object.keys(keys).forEach(function (key) {
    for (var b = 0; b < buckets.length; b++) {
      var hit = osvResolveEntry_(buckets[b], key);
      if (!hit) continue;
      var prev = found[hit.id];
      if (!prev || hit.entry.s > prev.s || (hit.entry.s === prev.s && (hit.entry.n || 0) > (prev.n || 0))) {
        found[hit.id] = hit.entry;
      }
    }
  });
  var ids = Object.keys(found);
  if (!ids.length) {
    var lined = osvLineMatch_(buckets, row && row.version);
    if (!lined) {
      row.severity = row.severity || "";
      row.severity_score = row.severity_score != null ? row.severity_score : null;
      row.cve_count = row.cve_count || 0;
      return false;
    }
    found[lined.id] = lined.entry;
    ids = [lined.id];
  }
  var best = null;
  var count = 0;
  for (var j = 0; j < ids.length; j++) {
    var entry = found[ids[j]];
    count += entry.n || 1;
    if (!best || entry.s > best.s) best = entry;
  }
  var score = Number(best.s);
  row.severity = osvLabel_(score);
  row.severity_score = isFinite(score) ? score : null;
  row.cve_count = count;
  return true;
}

function osvLineMatch_(buckets, version) {
  var prefix = String(version || "").trim().toLowerCase();
  if (!prefix) return null;
  var best = null;
  var bestId = "";
  var seen = {};
  for (var b = 0; b < buckets.length; b++) {
    var bucket = buckets[b];
    var keys = Object.keys(bucket);
    for (var i = 0; i < keys.length; i++) {
      var key = keys[i];
      if (
        key.indexOf(prefix + ".rhlw") !== 0 &&
        key.indexOf(prefix + "-rhlw") !== 0 &&
        key.indexOf(prefix + "+rhlw") !== 0
      ) {
        continue;
      }
      var hit = osvResolveEntry_(bucket, key);
      if (!hit || seen[hit.id]) continue;
      seen[hit.id] = true;
      if (!best || hit.entry.s > best.s) {
        best = hit.entry;
        bestId = hit.id;
      }
    }
  }
  if (!best) return null;
  return { id: bestId, entry: best };
}

/** Attach severity fields from the Drive index. One package name covers every row. */
function applyOsvSeverity_(rows, packageName) {
  var index = loadOsvIndex_();
  var status = osvStatus_(index);
  var pkgs = osvReadablePkgs_(index);
  if (!pkgs) return { hit: false, status: status };
  var any = false;
  (rows || []).forEach(function (row) {
    if (osvApplyRow_(pkgs, row, packageName || row.name)) any = true;
  });
  return { hit: any, status: status };
}

/** Recent Releases: severity of each package's newest release. Index is read once. */
function attachRecentSeverity_(rows) {
  var index = loadOsvIndex_();
  var pkgs = osvReadablePkgs_(index);
  if (!pkgs) return rows;
  (rows || []).forEach(function (pkg) {
    var latest = (pkg.latest_releases && pkg.latest_releases[0]) || {};
    var probe = {
      name: pkg.name,
      group: pkg.group,
      version: latest.version || "",
      release: latest.release || "",
    };
    osvApplyRow_(pkgs, probe, pkg.name);
    pkg.severity = probe.severity || "";
    pkg.severity_score = probe.severity_score != null ? probe.severity_score : null;
    pkg.cve_count = probe.cve_count || 0;
  });
  return rows;
}

function osvCvssScore_(record) {
  var best = 0;
  var items = (record && record.severity) || [];
  for (var i = 0; i < items.length; i++) {
    var score = items[i] && items[i].score;
    if (typeof score === "number" && isFinite(score)) {
      if (score > best) best = score;
      continue;
    }
    if (typeof score !== "string") continue;
    if (score.indexOf("CVSS:") === 0) {
      var parsed = osvScoreVector_(score);
      if (parsed > best) best = parsed;
      continue;
    }
    var numeric = parseFloat(score);
    if (isFinite(numeric) && numeric > best) best = numeric;
  }
  var db = record && record.database_specific;
  if (db && typeof db === "object") {
    var fields = ["severity_score", "cvss_score", "score"];
    for (var f = 0; f < fields.length; f++) {
      var val = db[fields[f]];
      if (typeof val === "number" && isFinite(val) && val > best) best = val;
    }
  }
  return best;
}

function osvRoundup_(input) {
  var intInput = Math.round(input * 100000);
  if (intInput % 10000 === 0) return intInput / 100000;
  return (Math.floor(intInput / 10000) + 1) / 10;
}

function osvPr_(scope, value) {
  if (scope === "C") {
    if (value === "N") return 0.85;
    if (value === "L") return 0.68;
    if (value === "H") return 0.5;
    return 0;
  }
  if (value === "N") return 0.85;
  if (value === "L") return 0.62;
  if (value === "H") return 0.27;
  return 0;
}

function osvScoreVector_(vector) {
  var parts = String(vector || "").trim().split("/");
  if (!parts.length) return 0;
  var head = parts[0].toUpperCase();
  if (head !== "CVSS:3.0" && head !== "CVSS:3.1") return 0;
  var metrics = {};
  for (var i = 1; i < parts.length; i++) {
    var pair = parts[i].split(":");
    if (pair.length === 2) metrics[pair[0].toUpperCase()] = pair[1].toUpperCase();
  }
  var AV = { N: 0.85, A: 0.62, L: 0.55, P: 0.2 };
  var AC = { L: 0.77, H: 0.44 };
  var UI = { N: 0.85, R: 0.62 };
  var CIA = { N: 0, L: 0.22, H: 0.56 };
  if (AV[metrics.AV] == null || AC[metrics.AC] == null || UI[metrics.UI] == null) return 0;
  if (CIA[metrics.C] == null || CIA[metrics.I] == null || CIA[metrics.A] == null) return 0;
  if (metrics.S !== "U" && metrics.S !== "C") return 0;
  var pr = osvPr_(metrics.S, metrics.PR);
  if (!pr) return 0;
  var iss = 1 - (1 - CIA[metrics.C]) * (1 - CIA[metrics.I]) * (1 - CIA[metrics.A]);
  var impact = metrics.S === "U"
    ? 6.42 * iss
    : 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  if (impact <= 0) return 0;
  var exploit = 8.22 * AV[metrics.AV] * AC[metrics.AC] * pr * UI[metrics.UI];
  var raw = metrics.S === "U" ? impact + exploit : 1.08 * (impact + exploit);
  if (raw > 10) raw = 10;
  return osvRoundup_(raw);
}
