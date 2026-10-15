/**
 * Cloudflare Worker — אימות קודי נוכחות ורישום ב-Firestore.
 *
 * נקודות גישה לסטודנטים (POST, גוף JSON עם id, lec, exp, sig):
 *   /names  — מחזיר את רשימת הסטודנטים, רק עבור קוד תקף שעוד לא נוצל
 *   /       — רושם נוכחות (בנוסף צריך name)
 *
 * נקודות גישה למרצה:
 *   GET  /dashboard   — דף הדשבורד (בלי נתונים; הנתונים נטענים אחרי כניסה)
 *   GET  /admin/data  — נתוני נוכחות והרצאות. דורש Authorization: Bearer <ADMIN_TOKEN>.
 *                       ?since=<ISO> מחזיר רק מה שהשתנה מאז (חוסך קריאות ב-Firestore)
 *   POST /lectures    — generate.py מדווח על הפקת קודים. חתום ב-HMAC_SECRET.
 *
 * רשימת הסטודנטים (students.json) נארזת לתוך ה-Worker בזמן הפריסה.
 * היא לא נמצאת ב-GitHub ולא חשופה לציבור.
 *
 * Secrets (wrangler secret put):
 *   HMAC_SECRET               — המפתח הסודי (אותה מחרוזת בדיוק שב-secret.key אצל המרצה)
 *   FIREBASE_SERVICE_ACCOUNT  — תוכן קובץ ה-JSON של ה-service account
 *   ADMIN_TOKEN               — סיסמת הכניסה לדשבורד
 * Vars (wrangler.toml):
 *   ALLOWED_ORIGIN            — כתובת אתר ה-GitHub Pages, למשל https://user.github.io
 */

import students from "../../students.json" with { type: "json" };
import dashboardHtml from "./dashboard.html";

const STUDENT_LIST = students.map((s) => s.normalize("NFC").trim());
const STUDENTS = new Set(STUDENT_LIST);

const ID_RE = /^[A-Za-z0-9_-]{22}$/; // 16 בייטים ב-base64url בלי ריפוד
const LEC_RE = /^\d+-\d{4}-\d{2}-\d{2}$/;
const EXP_RE = /^\d{1,12}$/;
const SIG_RE = /^[A-Za-z0-9_-]{43}$/; // 32 בייטים (HMAC-SHA256) ב-base64url

const enc = new TextEncoder();

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const route = url.pathname.replace(/\/+$/, "");

    // ---- נקודות הגישה של המרצה ----
    if (route === "/dashboard" && request.method === "GET") {
      return new Response(dashboardHtml, {
        headers: {
          "Content-Type": "text/html; charset=utf-8",
          "Cache-Control": "no-store",
          "Content-Security-Policy":
            "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
          "X-Robots-Tag": "noindex",
          "Referrer-Policy": "no-referrer",
        },
      });
    }
    if (route === "/admin/data" && request.method === "GET") {
      if (!(await isAdmin(request, env))) {
        return json({ ok: false, error: "unauthorized" }, 401);
      }
      try {
        return json(await adminData(env, url.searchParams.get("since")), 200);
      } catch (err) {
        console.error("admin data error:", err?.message ?? err);
        return json({ ok: false, error: "server" }, 500);
      }
    }
    if (route === "/lectures" && request.method === "POST") {
      return reportLecture(request, env);
    }

    // ---- נקודות הגישה של הסטודנטים ----
    const cors = corsHeaders(request, env);

    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: cors });
    }
    if (request.method !== "POST") {
      return json({ ok: false, error: "method" }, 405, cors);
    }

    let body;
    try {
      const text = await request.text();
      if (text.length > 4096) throw new Error("too large");
      body = JSON.parse(text);
    } catch {
      return json({ ok: false, error: "bad_request" }, 400, cors);
    }

    const { id, lec, exp, sig } = body ?? {};
    const name = typeof body?.name === "string" ? body.name.normalize("NFC").trim() : "";

    // 1+2. צורה, חתימה ותוקף
    const codeError = await checkCode(env, { id, lec, exp, sig });
    if (codeError) {
      return json({ ok: false, error: codeError.error }, codeError.status, cors);
    }

    // רשימת השמות — רק למי שמחזיק קוד תקף שעוד לא נוצל
    if (route === "/names") {
      try {
        if (await isUsed(env, id)) {
          return json({ ok: false, error: "used" }, 409, cors);
        }
      } catch (err) {
        console.error("firestore error:", err?.message ?? err);
        return json({ ok: false, error: "server" }, 500, cors);
      }
      return json({ ok: true, names: STUDENT_LIST }, 200, cors);
    }
    if (route !== "") {
      return json({ ok: false, error: "not_found" }, 404, cors);
    }

    // אימות שם מול רשימת הסטודנטים
    if (!STUDENTS.has(name)) {
      return json({ ok: false, error: "unknown_name" }, 400, cors);
    }

    // 3+4. כתיבה אטומית: used/{id} + attendance/{id} + registered/{lec+שם}, כולן עם exists=false.
    // אם הקוד כבר נוצל או שהסטודנט כבר נרשם להרצאה — ה-commit כולו נכשל ושום דבר לא נכתב.
    try {
      const result = await recordAttendance(env, { id, lec, name });
      if (result === "used") {
        return json({ ok: false, error: "used" }, 409, cors);
      }
      if (result === "already_registered") {
        return json({ ok: false, error: "already_registered", name }, 409, cors);
      }
      return json({ ok: true, name, lec }, 200, cors);
    } catch (err) {
      console.error("firestore error:", err?.message ?? err);
      return json({ ok: false, error: "server" }, 500, cors);
    }
  },
};

// ---------- בדיקת קוד ----------

async function checkCode(env, { id, lec, exp, sig }) {
  // צורה בסיסית של הפרמטרים — כל דבר אחר הוא "קוד לא תקין"
  if (
    typeof id !== "string" || !ID_RE.test(id) || /^__.*__$/.test(id) ||
    typeof lec !== "string" || !LEC_RE.test(lec) ||
    typeof exp !== "string" || !EXP_RE.test(exp) ||
    typeof sig !== "string" || !SIG_RE.test(sig)
  ) {
    return { error: "invalid", status: 400 };
  }
  // 1. אימות חתימה (crypto.subtle.verify משווה ב-constant time)
  if (!(await verifySignature(env.HMAC_SECRET, `${id}|${lec}|${exp}`, sig))) {
    return { error: "invalid", status: 403 };
  }
  // 2. תוקף
  if (Math.floor(Date.now() / 1000) >= Number(exp)) {
    return { error: "expired", status: 410 };
  }
  return null;
}

// ---------- HMAC ----------

async function verifySignature(secret, message, sigB64url) {
  secret = (secret || "").trim();
  if (!secret) throw new Error("HMAC_SECRET is not configured");
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["verify"],
  );
  let sigBytes;
  try {
    sigBytes = b64urlDecode(sigB64url);
  } catch {
    return false;
  }
  return crypto.subtle.verify("HMAC", key, sigBytes, enc.encode(message));
}

// ---------- Firestore ----------

// בדיקה בלבד (לתצוגת הרשימה). מניעת השימוש הכפול עצמה נעשית ב-commit האטומי.
async function isUsed(env, id) {
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const token = await getAccessToken(sa);
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents/used/${id}?mask.fieldPaths=lec`,
    { headers: { Authorization: `Bearer ${token}` } },
  );
  if (res.status === 404) return false;
  if (res.ok) return true;
  throw new Error(`get failed: ${res.status} ${await res.text()}`);
}

// מזהה מסמך לזוג (הרצאה, סטודנט) — מבטיח רישום אחד לכל סטודנט בכל הרצאה
async function registrationId(lec, name) {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(`${lec}|${name}`));
  return b64urlEncode(new Uint8Array(digest));
}

async function recordAttendance(env, { id, lec, name }) {
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const token = await getAccessToken(sa);
  const base = `projects/${sa.project_id}/databases/(default)/documents`;
  const now = new Date().toISOString();
  const regId = await registrationId(lec, name);

  const res = await fetch(
    `https://firestore.googleapis.com/v1/${base}:commit`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        writes: [
          {
            update: {
              name: `${base}/used/${id}`,
              fields: {
                lec: { stringValue: lec },
                usedAt: { timestampValue: now },
              },
            },
            currentDocument: { exists: false },
          },
          {
            update: {
              name: `${base}/attendance/${id}`,
              fields: {
                id: { stringValue: id },
                lec: { stringValue: lec },
                name: { stringValue: name },
                timestamp: { timestampValue: now },
              },
            },
            currentDocument: { exists: false },
          },
          {
            update: {
              name: `${base}/registered/${regId}`,
              fields: {
                lec: { stringValue: lec },
                name: { stringValue: name },
                id: { stringValue: id },
              },
            },
            currentDocument: { exists: false },
          },
        ],
      }),
    },
  );

  if (res.ok) return "ok";

  const err = await res.json().catch(() => ({}));
  const status = err?.error?.status;
  // precondition exists=false נכשל → אחד המסמכים כבר קיים.
  // Firestore לא אומר איזה, אז בודקים: אם הקוד נוצל → "used", אחרת הסטודנט כבר רשום.
  if (status === "ALREADY_EXISTS" || status === "FAILED_PRECONDITION") {
    return (await isUsed(env, id)) ? "used" : "already_registered";
  }
  throw new Error(`commit failed: ${res.status} ${JSON.stringify(err)}`);
}

// access token נשמר בזיכרון ה-isolate עד דקה לפני שפג
let cachedToken = null;

async function getAccessToken(sa) {
  const now = Math.floor(Date.now() / 1000);
  if (cachedToken && cachedToken.exp - 60 > now) return cachedToken.token;

  const header = { alg: "RS256", typ: "JWT" };
  const claims = {
    iss: sa.client_email,
    scope: "https://www.googleapis.com/auth/datastore",
    aud: sa.token_uri || "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
  const unsigned = `${b64urlEncode(enc.encode(JSON.stringify(header)))}.${b64urlEncode(enc.encode(JSON.stringify(claims)))}`;

  const key = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(sa.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key, enc.encode(unsigned));
  const jwt = `${unsigned}.${b64urlEncode(new Uint8Array(signature))}`;

  const res = await fetch(claims.aud, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: jwt,
    }),
  });
  if (!res.ok) throw new Error(`token request failed: ${res.status} ${await res.text()}`);
  const data = await res.json();
  cachedToken = { token: data.access_token, exp: now + (data.expires_in || 3600) };
  return cachedToken.token;
}

// ---------- מרצה: דשבורד ודיווח הפקה ----------

// השוואת הסיסמה ב-constant time: משווים hash של שני הצדדים
async function isAdmin(request, env) {
  const expected = (env.ADMIN_TOKEN || "").trim();
  const given = (request.headers.get("Authorization") || "").replace(/^Bearer\s+/i, "").trim();
  if (!expected || !given) return false;
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(given)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  const x = new Uint8Array(a), y = new Uint8Array(b);
  let diff = 0;
  for (let i = 0; i < x.length; i++) diff |= x[i] ^ y[i];
  return diff === 0;
}

async function runQuery(sa, token, collectionId, field, since) {
  const structuredQuery = {
    from: [{ collectionId }],
    orderBy: [{ field: { fieldPath: field }, direction: "ASCENDING" }],
  };
  if (since) {
    structuredQuery.where = {
      fieldFilter: {
        field: { fieldPath: field },
        op: "GREATER_THAN_OR_EQUAL",
        value: { timestampValue: since },
      },
    };
  }
  const res = await fetch(
    `https://firestore.googleapis.com/v1/projects/${sa.project_id}/databases/(default)/documents:runQuery`,
    {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({ structuredQuery }),
    },
  );
  if (!res.ok) throw new Error(`runQuery ${collectionId} failed: ${res.status} ${await res.text()}`);
  const rows = await res.json();
  return rows.filter((r) => r.document).map((r) => r.document);
}

const str = (f) => f?.stringValue ?? null;
const ts = (f) => f?.timestampValue ?? null;
const int = (f) => (f?.integerValue != null ? Number(f.integerValue) : 0);

async function adminData(env, sinceParam) {
  let since = null;
  if (sinceParam) {
    const d = new Date(sinceParam);
    if (!isNaN(d)) since = d.toISOString();
  }
  const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
  const token = await getAccessToken(sa);
  const serverTime = new Date().toISOString();
  const [att, lecs] = await Promise.all([
    runQuery(sa, token, "attendance", "timestamp", since),
    runQuery(sa, token, "lectures", "updatedAt", since),
  ]);
  return {
    ok: true,
    serverTime,
    full: !since,
    students: STUDENT_LIST,
    attendance: att.map((d) => ({
      id: d.name.split("/").pop(),
      lec: str(d.fields.lec),
      name: str(d.fields.name),
      timestamp: ts(d.fields.timestamp),
    })),
    lectures: lecs.map((d) => ({
      lec: str(d.fields.lec),
      codesGenerated: int(d.fields.codesGenerated),
      lastGeneratedAt: ts(d.fields.lastGeneratedAt),
      expiresAt: ts(d.fields.expiresAt),
    })),
  };
}

// generate.py מדווח: {lec, count, exp, batch, ts, sig}
// sig = HMAC(secret, "lecture|lec|count|exp|batch|ts"). batch אקראי — דיווח חוזר לא נספר פעמיים.
async function reportLecture(request, env) {
  let b;
  try {
    const text = await request.text();
    if (text.length > 2048) throw new Error("too large");
    b = JSON.parse(text);
  } catch {
    return json({ ok: false, error: "bad_request" }, 400);
  }
  const count = Number(b?.count);
  if (
    typeof b?.lec !== "string" || !LEC_RE.test(b.lec) ||
    !Number.isInteger(count) || count < 1 || count > 1000 ||
    typeof b?.exp !== "string" || !EXP_RE.test(b.exp) ||
    typeof b?.batch !== "string" || !ID_RE.test(b.batch) ||
    typeof b?.ts !== "string" || !EXP_RE.test(b.ts) ||
    typeof b?.sig !== "string" || !SIG_RE.test(b.sig)
  ) {
    return json({ ok: false, error: "invalid" }, 400);
  }
  const msg = `lecture|${b.lec}|${count}|${b.exp}|${b.batch}|${b.ts}`;
  if (!(await verifySignature(env.HMAC_SECRET, msg, b.sig))) {
    return json({ ok: false, error: "invalid" }, 403);
  }
  if (Math.abs(Date.now() / 1000 - Number(b.ts)) > 600) {
    return json({ ok: false, error: "stale" }, 400);
  }

  try {
    const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT);
    const token = await getAccessToken(sa);
    const base = `projects/${sa.project_id}/databases/(default)/documents`;
    const now = new Date().toISOString();
    const expIso = new Date(Number(b.exp) * 1000).toISOString();
    const res = await fetch(`https://firestore.googleapis.com/v1/${base}:commit`, {
      method: "POST",
      headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" },
      body: JSON.stringify({
        writes: [
          {
            update: {
              name: `${base}/lectures/${b.lec}/batches/${b.batch}`,
              fields: {
                count: { integerValue: String(count) },
                expiresAt: { timestampValue: expIso },
                createdAt: { timestampValue: now },
              },
            },
            currentDocument: { exists: false },
          },
          {
            update: {
              name: `${base}/lectures/${b.lec}`,
              fields: {
                lec: { stringValue: b.lec },
                lastGeneratedAt: { timestampValue: now },
                expiresAt: { timestampValue: expIso },
                updatedAt: { timestampValue: now },
              },
            },
            updateMask: { fieldPaths: ["lec", "lastGeneratedAt", "expiresAt", "updatedAt"] },
            updateTransforms: [
              { fieldPath: "codesGenerated", increment: { integerValue: String(count) } },
            ],
          },
        ],
      }),
    });
    if (res.ok) return json({ ok: true }, 200);
    const err = await res.json().catch(() => ({}));
    const status = err?.error?.status;
    // אותו batch כבר דווח — לא סופרים שוב
    if (status === "ALREADY_EXISTS" || status === "FAILED_PRECONDITION") return json({ ok: true, duplicate: true }, 200);
    throw new Error(`commit failed: ${res.status} ${JSON.stringify(err)}`);
  } catch (err) {
    console.error("lecture report error:", err?.message ?? err);
    return json({ ok: false, error: "server" }, 500);
  }
}

// ---------- helpers ----------

function pemToDer(pem) {
  const b64 = pem.replace(/-----[^-]+-----/g, "").replace(/\s+/g, "");
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (str.length % 4)) % 4);
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function corsHeaders(request, env) {
  const allowed = (env.ALLOWED_ORIGIN || "").split(",").map((s) => s.trim()).filter(Boolean);
  const origin = request.headers.get("Origin") || "";
  const headers = {
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Max-Age": "86400",
    Vary: "Origin",
  };
  if (allowed.includes(origin)) headers["Access-Control-Allow-Origin"] = origin;
  return headers;
}

function json(obj, status, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders,
    },
  });
}
