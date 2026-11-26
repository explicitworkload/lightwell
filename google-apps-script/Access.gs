/**
 * Approved-email gate for the web app.
 *
 * The deployment stays "Execute as: Me" so registry tokens and Drive files
 * remain the owner's. "Who has access" must be the Red Hat domain, otherwise
 * nobody else can open the URL. This list is the real gate.
 *
 * Script properties (written automatically, not typed by hand):
 *   ACCESS_ADMIN     owner email (the account the script runs as)
 *   APPROVED_USERS   JSON array of lowercase emails; the owner is always included
 */

var ACCESS_ADMIN_PROP = "ACCESS_ADMIN";
var ACCESS_USERS_PROP = "APPROVED_USERS";
var ACCESS_MAX_USERS = 100;
/** Always approved, and the only account that can edit the list. */
var ACCESS_OWNER_EMAIL = "jgoh@redhat.com";

function normalizeAccessEmail_(email) {
  return String(email || "").trim().toLowerCase();
}

function validAccessEmail_(email) {
  return (
    email.length <= 254 &&
    /^[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}$/.test(email)
  );
}

function scriptOwnerEmail_() {
  try {
    return normalizeAccessEmail_(Session.getEffectiveUser().getEmail());
  } catch (err) {
    return "";
  }
}

function visitorEmail_() {
  try {
    return normalizeAccessEmail_(Session.getActiveUser().getEmail());
  } catch (err) {
    return "";
  }
}

function loadAccess_(props) {
  var configured = normalizeAccessEmail_(ACCESS_OWNER_EMAIL);
  var runtimeOwner = scriptOwnerEmail_();
  var visitor = visitorEmail_();
  var storedAdmin = normalizeAccessEmail_(props.getProperty(ACCESS_ADMIN_PROP));
  // Prefer the configured owner. Execute-as-me often hides that account's
  // email, so fall back to whoever is signed in when nothing is stored yet.
  var admin = configured || runtimeOwner || storedAdmin || visitor;

  var users = [];
  var raw = props.getProperty(ACCESS_USERS_PROP);
  if (raw) {
    try {
      var parsed = JSON.parse(raw);
      if (Object.prototype.toString.call(parsed) === "[object Array]") {
        parsed.forEach(function (item) {
          var email = normalizeAccessEmail_(item);
          if (email && users.indexOf(email) === -1) users.push(email);
        });
      }
    } catch (err) {
      users = [];
    }
  }

  function ensure(email) {
    if (email && users.indexOf(email) === -1) users.unshift(email);
  }
  ensure(runtimeOwner);
  ensure(admin);

  var listJson = JSON.stringify(users);
  if (admin && admin !== storedAdmin) props.setProperty(ACCESS_ADMIN_PROP, admin);
  if (listJson !== (raw || "[]")) props.setProperty(ACCESS_USERS_PROP, listJson);
  return { admin: admin, users: users };
}

function accessRows_(state) {
  var rows = state.users.map(function (email) {
    return { email: email, owner: email === state.admin };
  });
  rows.sort(function (a, b) {
    if (a.owner !== b.owner) return a.owner ? -1 : 1;
    if (a.email < b.email) return -1;
    if (a.email > b.email) return 1;
    return 0;
  });
  return rows;
}

function accessGate_() {
  var props = PropertiesService.getScriptProperties();
  var state = loadAccess_(props);
  var email = visitorEmail_();
  return {
    email: email,
    adminEmail: state.admin,
    users: state.users,
    approved: !!(email && state.users.indexOf(email) !== -1),
    admin: !!(email && state.admin && email === state.admin),
  };
}

function requireApproved_() {
  var gate = accessGate_();
  if (!gate.approved) {
    throw new Error("You do not have access to this app.");
  }
  return gate;
}

function requireAdmin_() {
  var gate = requireApproved_();
  if (!gate.admin) {
    throw new Error("Only the owner can manage access.");
  }
  return gate;
}

/** google.script.run failure shape for pages that already return { ok, error }. */
function clientAccess_() {
  try {
    requireApproved_();
    return null;
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

function accessLock_() {
  var lock = LockService.getScriptLock();
  lock.waitLock(10000);
  return lock;
}

/** google.script.run — owner only. */
function apiAccessList() {
  try {
    var gate = requireAdmin_();
    return {
      ok: true,
      email: gate.email,
      users: accessRows_({ admin: gate.adminEmail, users: gate.users }),
    };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  }
}

/** google.script.run — owner only. One email address. */
function apiAccessAdd(email) {
  var lock = null;
  try {
    requireAdmin_();
    var next = normalizeAccessEmail_(email);
    if (!validAccessEmail_(next)) {
      return { ok: false, error: "Enter one full email address." };
    }
    lock = accessLock_();
    var props = PropertiesService.getScriptProperties();
    var state = loadAccess_(props);
    if (state.users.indexOf(next) === -1) {
      if (state.users.length >= ACCESS_MAX_USERS) {
        return { ok: false, error: "The approved list is full." };
      }
      state.users.push(next);
      props.setProperty(ACCESS_USERS_PROP, JSON.stringify(state.users));
    }
    return { ok: true, users: accessRows_(state) };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  } finally {
    if (lock) lock.releaseLock();
  }
}

/** google.script.run — owner only. The owner row cannot be removed. */
function apiAccessRemove(email) {
  var lock = null;
  try {
    requireAdmin_();
    var next = normalizeAccessEmail_(email);
    if (!next) return { ok: false, error: "Missing email." };
    lock = accessLock_();
    var props = PropertiesService.getScriptProperties();
    var state = loadAccess_(props);
    if (next === state.admin) {
      return { ok: false, error: "The owner stays on the list." };
    }
    var kept = state.users.filter(function (item) {
      return item !== next;
    });
    if (state.admin && kept.indexOf(state.admin) === -1) kept.unshift(state.admin);
    state.users = kept;
    props.setProperty(ACCESS_USERS_PROP, JSON.stringify(kept));
    return { ok: true, users: accessRows_(state) };
  } catch (err) {
    return { ok: false, error: String(err && err.message ? err.message : err) };
  } finally {
    if (lock) lock.releaseLock();
  }
}

/**
 * Run once from the editor if the Access page cannot see your email.
 * Execution log shows the account Apps Script will compare to the list.
 */
function logAccessIdentity() {
  var gate = accessGate_();
  Logger.log(
    "visitor=%s owner=%s approved=%s admin=%s count=%s",
    gate.email || "(blank)",
    gate.adminEmail || "(blank)",
    gate.approved,
    gate.admin,
    gate.users.length
  );
  return gate;
}

function accessDeniedPage_(email) {
  var who = normalizeAccessEmail_(email);
  var detail = who
    ? "<p>Signed in as <strong>" +
      esc_(who) +
      "</strong>. This account is not on the approved list.</p><p>Ask the owner to add that address.</p>"
    : "<p>Google did not share an email for this visit. Sign in with your Red Hat Google account and open the app again.</p>";
  return (
    "<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'/>" +
    "<meta name='viewport' content='width=device-width, initial-scale=1'/>" +
    "<title>Access Denied</title>" +
    "<link rel='icon' href='https://www.redhat.com/favicon.ico' type='image/x-icon'/>" +
    "<style>" +
    catalogCss_() +
    "</style></head><body><div class='glow glow-a' aria-hidden='true'></div>" +
    "<main class='fade-in'>" +
    "<p class='eyebrow'>Lightwell Network</p>" +
    "<h1>Access Denied</h1>" +
    "<section class='panel'>" +
    detail +
    "</section></main></body></html>"
  );
}
