# Lightwell catalog snapshot (Google Apps Script)

Cloud replacement for the local Mac `launchd` job. Runs **08:00** and **15:00 Asia/Singapore (SGT)**, appends rows with **SGT timestamps** (`…+08:00`) to a Google Sheet, and optionally refreshes `catalog-summary.html` in a Drive folder.

## Why Apps Script (not your Mac)

- No need to leave the laptop on
- Native Drive/Sheets integration
- Timezone-aware triggers (`Asia/Singapore`)

## One-time setup

1. Create a Google Sheet (e.g. **Lightwell Catalog Summary**) and copy its id from the URL:  
   `https://docs.google.com/spreadsheets/d/<SPREADSHEET_ID>/edit`
2. Open [script.google.com](https://script.google.com) → **New project** → paste `Code.gs`.
3. **Project Settings → Script properties** — add:

| Property | Value |
|---|---|
| `AUTH_MODE` | `offline` *(works with your `rh-ee-…` Repositories Viewer)* **or** `service_account` |
| `OFFLINE_TOKEN` | Offline token from [Red Hat API Tokens](https://access.redhat.com/management/api) *(if `offline`)* |
| `CLIENT_ID` / `CLIENT_SECRET` | Hybrid Console SA *(if `service_account` — SA must be in a group with Repositories viewer)* |
| `SPREADSHEET_ID` | Sheet id from step 1 |
| `SHEET_NAME` | `CatalogSummary` *(optional)* |
| `DRIVE_FOLDER_ID` | Optional Drive folder id for `catalog-summary.html` (your **AI → Lightwell** folder) |
| `WRITE_HTML` | `true` *(default if folder set)* |
| `WEBAPP_KEY` | Optional shared secret for the Web app (`?key=…`) |
| `CHART_DAYS` | `30` *(optional trend window)* |

4. Paste the updated `Code.gs` (dashboard Web app + chart).
5. Run **`runCatalogSnapshot`** once from the editor (authorize UrlFetch + Drive/Sheets).  
   Data lands on tab **`CatalogSummary`** (not necessarily Sheet1).
6. Run **`installTriggers`** once to schedule 08:00 + 15:00 Asia/Singapore.
7. **Deploy → New deployment → Web app**
   - Execute as: **Me**
   - Who has access: **Only myself** (safest) or your org  
   - Optional: set Script property `WEBAPP_KEY` and open with `?key=…`
8. Open the Web app `/exec` URL → **dashboard** matching `catalog-summary.html`:
   - 30-day package trend chart (top)
   - **Latest snapshot** + **History** tables (same columns/highlights as the HTML file)
   - default / `?action=status` → Sheet only (no Red Hat API call)
   - `?action=run` → fetch + append, then show dashboard

### Offline token tip

Offline tokens expire after **30 days of inactivity**. Either:

- Refresh by using the script regularly, or regenerate the offline token, **or**
- Prefer `AUTH_MODE=service_account` once the SA has Repositories viewer (better for unattended jobs).

## Manual test

- Editor: select `runCatalogSnapshot` → **Run** → check **Executions** + tab **CatalogSummary**
- Web app: open the `/exec` URL (redeploy after code changes)

## Troubleshooting empty spreadsheet

1. Open the spreadsheet whose id is `SPREADSHEET_ID` (confirm the id matches the URL).
2. Look for tab **`CatalogSummary`** — the script does not write to Sheet1 by default.
3. If the Web app or Run failed, open **Executions** and read the error (often bad `OFFLINE_TOKEN` or wrong Sheet id).
