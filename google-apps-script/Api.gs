/**
 * Content-sources API helpers + google.script.run endpoints for Browser / CVE / Match.
 */

function apiGetJson_(token, path, params) {
  params = params || {};
  var qs = Object.keys(params)
    .filter(function (k) {
      return params[k] !== "" && params[k] !== null && params[k] !== undefined;
    })
    .map(function (k) {
      return encodeURIComponent(k) + "=" + encodeURIComponent(String(params[k]));
    })
    .join("&");
  var url = API_BASE + path + (qs ? "?" + qs : "");
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
    throw new Error("API HTTP " + code + " for " + path + ": " + body.slice(0, 400));
  }
  return JSON.parse(body);
}

function registryBrowseUrl_(pkg) {
  pkg = pkg || {};
  var ecosystem = String(pkg.ecosystem || "").toLowerCase();
  var repo = String(pkg.repository || "");
  var level = "validated";
  if (repo.indexOf("remediated") !== -1) {
    level = "remediated";
  } else if (repo.indexOf("predisclosure") !== -1) {
    level = "predisclosure";
  } else if (pkg.security_level) {
    level = String(pkg.security_level);
  }
  var name = String(pkg.name || "");
  var group = String(pkg.group || "");

  if (ecosystem === "maven") {
    var base = "https://packages.redhat.com/lightwell/java/" + level + "/";
    if (group && name) {
      return base + group.replace(/\./g, "/") + "/" + name + "/";
    }
    return base;
  }
  if (ecosystem === "python") {
    return (
      "https://packages.redhat.com/lightwell/python/" +
      level +
      "/simple/" +
      encodeURIComponent(name) +
      "/"
    );
  }
  if (ecosystem === "npm") {
    return (
      "https://packages.redhat.com/lightwell/javascript/" +
      level +
      "/" +
      encodeURIComponent(name)
    );
  }
  return "https://packages.redhat.com/lightwell/";
}

function stampMs_(value) {
  var t = Date.parse(String(value || ""));
  return isFinite(t) ? t : 0;
}

/**
 * Newest-first dotted version compare (4.2.2 > 3.6.9 > 3.5.1).
 * Uses explicit numeric segments — do not rely on localeCompare options
 * (Apps Script runtimes are inconsistent with { numeric: true }).
 */
function cmpVersionDesc_(a, b) {
  var pa = String(a || "")
    .replace(/^v/i, "")
    .split(/[^0-9A-Za-z]+/);
  var pb = String(b || "")
    .replace(/^v/i, "")
    .split(/[^0-9A-Za-z]+/);
  var n = Math.max(pa.length, pb.length);
  for (var i = 0; i < n; i++) {
    var sa = pa[i] || "0";
    var sb = pb[i] || "0";
    var na = parseInt(sa, 10);
    var nb = parseInt(sb, 10);
    var aNum = sa !== "" && String(na) === sa;
    var bNum = sb !== "" && String(nb) === sb;
    if (aNum && bNum) {
      if (na !== nb) {
        return nb - na;
      }
      continue;
    }
    if (aNum !== bNum) {
      return aNum ? -1 : 1;
    }
    var c = sb.toLowerCase().localeCompare(sa.toLowerCase());
    if (c) {
      return c;
    }
  }
  return 0;
}

/** Newest last_publication first. */
function sortPackagesNewestFirst_(rows) {
  return (rows || []).slice().sort(function (a, b) {
    var d = stampMs_(b.last_publication) - stampMs_(a.last_publication);
    if (d) {
      return d;
    }
    return cmpVersionDesc_(
      (a.versions && a.versions[0]) || "",
      (b.versions && b.versions[0]) || ""
    );
  });
}

/**
 * Latest version → oldest (e.g. 4.2.2, 3.6.9, 3.5.1, 3.5.0).
 * Same version: higher release, then newest created_at.
 */
function sortVersionsNewestFirst_(rows) {
  return (rows || []).slice().sort(function (a, b) {
    var v = cmpVersionDesc_(a.version, b.version);
    if (v) {
      return v;
    }
    var r = cmpVersionDesc_(a.release, b.release);
    if (r) {
      return r;
    }
    return stampMs_(b.created_at) - stampMs_(a.created_at);
  });
}

function enrichPackageRow_(row) {
  row = row || {};
  var releases = sortVersionsNewestFirst_(
    (row.latest_releases || []).map(function (r) {
      return {
        version: r.version || "",
        release: r.release || "",
        created_at: r.created_at || "",
      };
    })
  );
  // Prefer release order for the short version preview list
  var versions = releases.length
    ? releases.map(function (r) {
        return r.version;
      }).filter(function (v, i, arr) {
        return v && arr.indexOf(v) === i;
      })
    : (row.versions || []).slice().sort(cmpVersionDesc_);

  return {
    name: row.name || "",
    group: row.group || "",
    ecosystem: row.ecosystem || "",
    repository: row.repository || "",
    repository_uuid: row.repository_uuid || "",
    versions: versions,
    latest_releases: releases,
    last_publication: row.last_publication || "",
    // Direct registry URL — client wraps via registryProxyUrl() using LW_USER/LW_TOKEN proxy
    registry_url: registryBrowseUrl_(row),
  };
}

function enrichVersionRow_(row) {
  row = row || {};
  return {
    name: row.name || "",
    group: row.group || "",
    version: row.version || "",
    release: row.release || "",
    ecosystem: row.ecosystem || "",
    repository: row.repository || "",
    coordinates: row.coordinates || "",
    purl: row.purl || "",
    created_at: row.created_at || "",
    registry_url: registryBrowseUrl_(row),
  };
}

function splitPackageQuery_(raw) {
  var text = String(raw || "").trim();
  var colon = text.indexOf(":");
  if (colon <= 0 || colon >= text.length - 1) return null;
  var group = text.slice(0, colon).trim();
  var artifact = text.slice(colon + 1).split(":")[0].trim();
  if (!group || !artifact || group.indexOf("/") !== -1) return null;
  return { group: group, artifact: artifact };
}

/** "jackson, requests, lodash" → three terms. A single name stays one term. */
function splitSearchTerms_(raw) {
  var text = String(raw || "").trim();
  if (!text) return [];
  if (text.indexOf(",") === -1) return [text];
  var seen = {};
  var out = [];
  text.split(",").forEach(function (part) {
    var term = String(part || "").trim();
    var key = term.toLowerCase();
    if (!term || seen[key]) return;
    seen[key] = true;
    out.push(term);
  });
  return out.slice(0, 12);
}

function packageRowKey_(row) {
  return [
    row && row.ecosystem,
    row && row.repository,
    row && row.group,
    row && row.name,
  ]
    .join("|")
    .toLowerCase();
}

function filterCoordRows_(rows, coord) {
  if (!coord) return rows || [];
  var group = coord.group.toLowerCase();
  var artifact = coord.artifact.toLowerCase();
  return (rows || []).filter(function (row) {
    return (
      String(row.group || "").toLowerCase() === group &&
      String(row.name || "").toLowerCase().indexOf(artifact) !== -1
    );
  });
}

function catalogSearchParams_(opts, term, limit, offset) {
  var params = {
    limit: String(limit),
    offset: String(offset),
  };
  if (opts.ecosystem) params.ecosystem = opts.ecosystem;
  if (opts.security_level) params.security_level = opts.security_level;
  if (opts.repository) params.repository = opts.repository;
  var coord = splitPackageQuery_(term);
  if (coord) {
    params.name = coord.artifact;
    params.search = coord.group;
  } else if (term) {
    params.search = term;
  }
  if (opts.name) params.name = opts.name;
  if (!term) params.sort_by = "last_publication:desc";
  return { params: params, coord: coord };
}

/** google.script.run — Catalog Browser package search */
function apiCatalogSearch(opts) {
  opts = opts || {};
  try {
    requireApproved_();
    var props = PropertiesService.getScriptProperties();
    var token = getAccessToken_(props);
    var terms = splitSearchTerms_(opts.search);
    var pageLimit = Math.min(100, Math.max(1, Number(opts.limit) || 25));
    var pageOffset = Math.max(0, Number(opts.offset) || 0);
    if (terms.length > 1) {
      return apiCatalogSearchMany_(token, opts, terms, pageLimit, pageOffset);
    }
    var term = terms.length ? terms[0] : "";
    var built = catalogSearchParams_(opts, term, pageLimit, pageOffset);
    var json = apiGetJson_(token, "/lightwell/packages", built.params);
    var data = filterCoordRows_(
      (json.data || []).map(enrichPackageRow_),
      built.coord
    );
    data = sortPackagesNewestFirst_(data);
    var meta = json.meta || {};
    if (built.coord) meta = { count: data.length, limit: meta.limit, offset: meta.offset };
    return { ok: true, meta: meta, data: data };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

/** One catalog lookup per comma-separated name, then one merged page. */
function apiCatalogSearchMany_(token, opts, terms, pageLimit, pageOffset) {
  var perTerm = 40;
  var merged = [];
  var seen = {};
  var partial = false;
  terms.forEach(function (term) {
    var built = catalogSearchParams_(opts, term, perTerm, 0);
    var json = apiGetJson_(token, "/lightwell/packages", built.params);
    var rows = filterCoordRows_(
      (json.data || []).map(enrichPackageRow_),
      built.coord
    );
    var apiCount = Number((json.meta && json.meta.count) || rows.length);
    if (!built.coord && apiCount > rows.length) partial = true;
    rows.forEach(function (row) {
      var key = packageRowKey_(row);
      if (seen[key]) return;
      seen[key] = true;
      merged.push(row);
    });
  });
  merged = sortPackagesNewestFirst_(merged);
  return {
    ok: true,
    meta: {
      count: merged.length,
      partial: partial,
      terms: terms.length,
    },
    data: merged.slice(pageOffset, pageOffset + pageLimit),
  };
}

/**
 * google.script.run — Recent Releases: newest packages by last_publication.
 * Capped at 300 rows (client paginates within that window).
 */
function apiCatalogRecent(opts) {
  opts = opts || {};
  try {
    requireApproved_();
    var props = PropertiesService.getScriptProperties();
    var token = getAccessToken_(props);
    var maxTotal = 300;
    var offset = Math.max(0, Number(opts.offset) || 0);
    var pageSize = Math.min(100, Math.max(1, Number(opts.limit) || 50));
    if (offset >= maxTotal) {
      return {
        ok: true,
        meta: { count: maxTotal },
        data: [],
        capped_at: maxTotal,
      };
    }
    pageSize = Math.min(pageSize, maxTotal - offset);
    var params = {
      limit: String(pageSize),
      offset: String(offset),
      sort_by: "last_publication:desc",
    };
    if (opts.ecosystem) {
      params.ecosystem = opts.ecosystem;
    }
    if (opts.security_level) {
      params.security_level = opts.security_level;
    }
    var json = apiGetJson_(token, "/lightwell/packages", params);
    // Keep API order (already newest-first); enrich only.
    var data = (json.data || []).map(enrichPackageRow_);
    try {
      attachRecentSeverity_(data);
    } catch (ignore) {}
    var apiCount = Number((json.meta && json.meta.count) || data.length);
    return {
      ok: true,
      meta: {
        count: Math.min(apiCount, maxTotal),
        api_count: apiCount,
      },
      data: data,
      capped_at: maxTotal,
    };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

function severityRank_(severity) {
  var key = String(severity || "").toLowerCase();
  if (key === "critical") return 4;
  if (key === "important") return 3;
  if (key === "moderate") return 2;
  if (key === "low") return 1;
  return 0;
}

function versionMatchKeys_(row) {
  var version = String((row && row.version) || "").trim().toLowerCase();
  var release = String((row && row.release) || "").trim().toLowerCase();
  var keys = {};
  if (version) keys[version] = true;
  if (version && release) {
    keys[version + "+" + release] = true;
    keys[version + "." + release] = true;
    keys[version + "-" + release] = true;
  }
  var purl = String((row && row.purl) || "");
  var at = purl.lastIndexOf("@");
  if (at !== -1 && at < purl.length - 1) {
    var qual = purl.slice(at + 1).split("?")[0].split("#")[0].trim().toLowerCase();
    if (qual) keys[qual] = true;
  }
  return keys;
}

function advisoryHitsVersion_(adv, keys) {
  function hit(value) {
    return !!keys[String(value || "").trim().toLowerCase()];
  }
  if (hit(adv.package_version)) return true;
  var fixed = adv.fixed_versions || [];
  for (var i = 0; i < fixed.length; i++) {
    if (hit(fixed[i])) return true;
  }
  return false;
}

/** Advisories for one package name. Capped so a version drill-down stays fast. */
function fetchPackageAdvisories_(token, packageName) {
  var name = String(packageName || "").trim();
  if (!name) return [];
  var all = [];
  var offset = 0;
  var page = 100;
  var guard = 0;
  while (guard < 3 && all.length < 300) {
    guard += 1;
    var json = apiGetJson_(token, "/lightwell/advisories", {
      package_name: name,
      limit: String(page),
      offset: String(offset),
    });
    var rows = json.data || [];
    all = all.concat(rows);
    var total = Number((json.meta && json.meta.count) || 0);
    offset += rows.length;
    if (!rows.length || rows.length < page || (total && offset >= total)) break;
  }
  return all;
}

function attachVersionSeverity_(rows, advisories) {
  return (rows || []).map(function (row) {
    var keys = versionMatchKeys_(row);
    var best = null;
    var count = 0;
    (advisories || []).forEach(function (adv) {
      if (!advisoryHitsVersion_(adv, keys)) return;
      count += 1;
      if (!best) {
        best = adv;
        return;
      }
      var rank = severityRank_(adv.severity) - severityRank_(best.severity);
      var score = Number(adv.severity_score || 0) - Number(best.severity_score || 0);
      if (rank > 0 || (rank === 0 && score > 0)) best = adv;
    });
    var rawScore = best && best.severity_score != null ? Number(best.severity_score) : NaN;
    var rawLabel = best ? String(best.severity || "").toLowerCase() : "";
    if (!isFinite(rawScore)) rawScore = parseFloat(rawLabel);
    var named = rawLabel === "critical" || rawLabel === "important" || rawLabel === "moderate" || rawLabel === "low";
    row.severity = named ? rawLabel : osvLabel_(rawScore);
    row.severity_score = isFinite(rawScore) && rawScore > 0 ? rawScore : null;
    row.cve_count = count;
    return row;
  });
}

/** google.script.run — package versions for a selected package */
function apiCatalogVersions(opts) {
  opts = opts || {};
  try {
    requireApproved_();
    var props = PropertiesService.getScriptProperties();
    var token = getAccessToken_(props);
    var params = {
      limit: String(Math.min(100, Math.max(1, Number(opts.limit) || 50))),
      offset: String(Math.max(0, Number(opts.offset) || 0)),
    };
    if (opts.ecosystem) {
      params.ecosystem = opts.ecosystem;
    }
    if (opts.security_level) {
      params.security_level = opts.security_level;
    }
    if (opts.name) {
      params.name = opts.name;
    }
    if (opts.repository) {
      params.repository = opts.repository;
    }
    var json = apiGetJson_(token, "/lightwell/package_versions", params);
    var data = sortVersionsNewestFirst_(
      (json.data || []).map(enrichVersionRow_)
    );
    var osv = { hit: false, status: "missing" };
    try {
      osv = applyOsvSeverity_(data, opts.name);
    } catch (ignore) {
      osv = { hit: false, status: "missing" };
    }
    if (!osv.hit && osv.status === "missing") {
      var advisories = [];
      try {
        advisories = fetchPackageAdvisories_(token, opts.name);
      } catch (ignoreAdv) {
        advisories = [];
      }
      data = attachVersionSeverity_(data, advisories);
    }
    return {
      ok: true,
      meta: json.meta || {},
      data: data,
      osv: osv.status,
    };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

/** google.script.run — advisories by CVE id (or severity floor) */
function apiCatalogAdvisories(opts) {
  opts = opts || {};
  try {
    requireApproved_();
    var props = PropertiesService.getScriptProperties();
    var token = getAccessToken_(props);
    var params = {
      limit: String(Math.min(100, Math.max(1, Number(opts.limit) || 25))),
      offset: String(Math.max(0, Number(opts.offset) || 0)),
    };
    if (opts.cve_id) {
      params.cve_id = String(opts.cve_id).trim();
    }
    if (opts.package_name) {
      params.package_name = opts.package_name;
    }
    if (opts.severity_min !== "" && opts.severity_min != null) {
      params.severity_min = String(opts.severity_min);
    }
    if (opts.repository) {
      params.repository = opts.repository;
    }
    var json = apiGetJson_(token, "/lightwell/advisories", params);
    var data = (json.data || []).map(function (row) {
      return {
        advisory_id: row.advisory_id || "",
        severity: row.severity || "",
        severity_score: row.severity_score,
        summary: row.summary || "",
        details: row.details || "",
        package_name: row.package_name || "",
        package_version: row.package_version || "",
        repository: row.repository || "",
        fixed_versions: row.fixed_versions || [],
        published: row.published || row.created_at || "",
        reference_urls: row.reference_urls || [],
      };
    });
    return { ok: true, meta: json.meta || {}, data: data };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

/**
 * google.script.run — CVE / RHLW lookup against the OSV advisory catalog.
 * Accepts a CVE id, an RHLW- advisory id, a GHSA id, a remediated release, or a package name.
 * Until the catalog exists, a CVE id falls back to the content-sources advisories API.
 */
function apiAdvisoryLookup(opts) {
  var denied = clientAccess_();
  if (denied) return denied;
  opts = opts || {};
  var query = String(opts.query || opts.cve_id || "").trim();
  var minScore = opts.severity_min === "" || opts.severity_min == null ? "" : opts.severity_min;
  var found = null;
  try {
    found = lookupOsvAdvisories_(query, minScore);
  } catch (err) {
    found = null;
  }
  if (found && found.status !== "missing") return found;
  if (/^cve-\d{4}-/i.test(query)) {
    var catalog = apiCatalogAdvisories({
      cve_id: query,
      severity_min: minScore,
      limit: 50,
    });
    if (!catalog || !catalog.ok) return catalog;
    return {
      ok: true,
      status: "catalog",
      updated_at: "",
      total: (catalog.data || []).length,
      note: "OSV index is not built yet. These rows are from the catalog advisories API. Run syncOsvIndexForce for RHLW ids.",
      data: (catalog.data || []).map(catalogAdvisoryRow_),
    };
  }
  return {
    ok: false,
    error:
      "Advisory index not built yet. In Apps Script, run syncOsvIndexForce once, then search again.",
  };
}

function catalogAdvisoryRow_(row) {
  var score = row && row.severity_score != null ? Number(row.severity_score) : NaN;
  var label = String((row && row.severity) || "").toLowerCase();
  var named = label === "critical" || label === "important" || label === "moderate" || label === "low";
  if (!named && isFinite(score)) label = osvLabel_(score);
  var fixed = (row && row.fixed_versions) || [];
  if (!fixed.length && row && row.package_version) fixed = [row.package_version];
  return {
    id: (row && row.advisory_id) || "",
    summary: (row && row.summary) || "",
    details: (row && row.details) || "",
    published: String((row && row.published) || "").slice(0, 10),
    score: isFinite(score) && score > 0 ? score : null,
    severity: named || label ? label : "",
    cves: [],
    aliases: [],
    refs: (row && row.reference_urls) || [],
    packages: [
      {
        name: (row && row.package_name) || "",
        ecosystem: "",
        base: "",
        fixed: fixed,
      },
    ],
  };
}

/**
 * google.script.run — dependency match: look up a batch of package names.
 * Client should send small batches (e.g. 10) to stay under Apps Script time limits.
 */
function apiDependencyMatch(opts) {
  opts = opts || {};
  try {
    requireApproved_();
    var names = opts.names || [];
    if (!Array.isArray(names)) {
      names = String(names || "")
        .split(/\r?\n/)
        .map(function (s) {
          return s.trim();
        })
        .filter(Boolean);
    }
    names = names.slice(0, 15);
    var props = PropertiesService.getScriptProperties();
    var token = getAccessToken_(props);
    var ecosystem = opts.ecosystem || "";
    // Empty ecosystem → search java (maven), python, and npm
    var ecosystems = ecosystem
      ? [ecosystem]
      : ["maven", "python", "npm"];
    var securityLevel = opts.security_level || "";
    var results = names.map(function (raw) {
      var name = String(raw).trim();
      // Allow "group:artifact" for Java/Maven
      var group = "";
      if (name.indexOf(":") !== -1) {
        var parts = name.split(":");
        group = parts[0];
        name = parts[1] || name;
      }
      try {
        var merged = [];
        var totalCount = 0;
        var seen = {};
        ecosystems.forEach(function (eco) {
          var params = {
            limit: "5",
            offset: "0",
            name: name,
            ecosystem: eco,
          };
          if (securityLevel) {
            params.security_level = securityLevel;
          }
          if (group) {
            params.search = group;
          }
          var json = apiGetJson_(token, "/lightwell/packages", params);
          totalCount += Number((json.meta && json.meta.count) || 0);
          (json.data || []).map(enrichPackageRow_).forEach(function (row) {
            var key =
              String(row.ecosystem || "") +
              "|" +
              String(row.repository || "") +
              "|" +
              String(row.group || "") +
              "|" +
              String(row.name || "");
            if (!seen[key]) {
              seen[key] = true;
              merged.push(row);
            }
          });
        });
        var exact = merged.filter(function (r) {
          return String(r.name).toLowerCase() === name.toLowerCase();
        });
        return {
          query: raw,
          ok: true,
          count: totalCount || merged.length,
          matches: (exact.length ? exact : merged).slice(0, 5),
        };
      } catch (err) {
        return {
          query: raw,
          ok: false,
          error: String(err && err.message ? err.message : err),
          matches: [],
        };
      }
    });
    return { ok: true, results: results };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}
