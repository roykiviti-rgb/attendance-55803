#!/usr/bin/env python3
"""
הפקת קודי QR חד-פעמיים לרישום נוכחות — יסודות המימון (55803).

שימוש:
    python generate.py --date 2026-10-20
    python generate.py --date 2026-10-20 -n 20 --hours 30 --layout 2x2

המפתח הסודי נקרא ממשתנה הסביבה ATTENDANCE_SECRET, או מהקובץ secret.key
שליד הסקריפט. אם אף אחד מהם לא קיים — נוצר secret.key חדש (פעם אחת בלבד).
secret.key נמצא ב-.gitignore ואסור שיגיע ל-GitHub.

תלויות:  pip install qrcode reportlab
"""

import argparse
import base64
import datetime as dt
import hashlib
import hmac
import os
import secrets
import sys
import time
from pathlib import Path
from urllib.parse import urlencode

import qrcode
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen import canvas

# ---------- הגדרות ----------

COURSE_NAME = "Fundamentals of Finance"
COURSE_NUMBER = "55803"

# כתובת אתר ה-GitHub Pages (עם / בסוף). אפשר לדרוס עם --base-url.
BASE_URL = "https://roykiviti-rgb.github.io/attendance-55803/"

HERE = Path(__file__).resolve().parent
SECRET_FILE = HERE / "secret.key"
OUT_DIR = HERE / "out"

# הטקסט ב-PDF באנגלית, אז מספיקים הגופנים המובנים של PDF
FONT = "Helvetica"
FONT_BOLD = "Helvetica-Bold"


# ---------- מפתח וחתימה ----------

def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def load_secret() -> str:
    env = os.environ.get("ATTENDANCE_SECRET", "").strip()
    if env:
        return env
    if SECRET_FILE.exists():
        value = SECRET_FILE.read_text(encoding="utf-8").strip()
        if value:
            return value
    value = secrets.token_urlsafe(32)
    SECRET_FILE.write_text(value + "\n", encoding="utf-8")
    print(
        f"נוצר מפתח סודי חדש ונשמר ב-{SECRET_FILE.name}.\n"
        "  יש להעלות אותו ל-Worker (פעם אחת):\n"
        "    cd worker && npx wrangler secret put HMAC_SECRET\n"
        "  ולהדביק את התוכן של secret.key. לא לשתף ולא להעלות ל-GitHub!\n",
        file=sys.stderr,
    )
    return value


def sign(secret: str, code_id: str, lec: str, exp: str) -> str:
    msg = f"{code_id}|{lec}|{exp}".encode("utf-8")
    return b64url(hmac.new(secret.encode("utf-8"), msg, hashlib.sha256).digest())


def new_id(taken: set) -> str:
    while True:
        code_id = b64url(secrets.token_bytes(16))
        # Firestore לא מקבל document ID מהצורה __...__
        if code_id not in taken and not (code_id.startswith("__") and code_id.endswith("__")):
            taken.add(code_id)
            return code_id


def make_codes(secret, base_url, lec, exp, count):
    taken = set()
    codes = []
    for _ in range(count):
        code_id = new_id(taken)
        params = {"id": code_id, "lec": lec, "exp": exp, "sig": sign(secret, code_id, lec, exp)}
        codes.append(f"{base_url}?{urlencode(params)}")
    return codes


# ---------- PDF ----------

def draw_fitted(c, cx, y, text, font, size, max_width):
    """כותב טקסט ממורכז, ומקטין את הגופן אם הוא רחב מדי לתא."""
    width = stringWidth(text, font, size)
    if width > max_width:
        size *= max_width / width
    c.setFont(font, size)
    c.drawCentredString(cx, y, text)


def draw_qr(c, url, x, y, size):
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=0)
    qr.add_data(url)
    qr.make(fit=True)
    matrix = qr.get_matrix()
    n = len(matrix)
    module = size / n
    # נתיב אחד לכל ה-QR, כדי שלא ייווצרו רווחים דקים בין המודולים
    path = c.beginPath()
    for r, row in enumerate(matrix):
        col = 0
        while col < n:
            if row[col]:
                start = col
                while col < n and row[col]:
                    col += 1
                path.rect(x + start * module, y + (n - 1 - r) * module,
                          (col - start) * module, module)
            else:
                col += 1
    c.setFillColorRGB(0, 0, 0)
    c.drawPath(path, stroke=0, fill=1)


def build_pdf(path, codes, lec, lecture_date, exp_ts, cols, rows):
    page_w, page_h = A4
    margin = 8 * mm
    cell_w = (page_w - 2 * margin) / cols
    cell_h = (page_h - 2 * margin) / rows
    per_page = cols * rows

    scale = min(cell_w / (63 * mm), cell_h / (92 * mm), 1.6)
    fs_title = 10 * scale
    fs_small = 7.5 * scale
    line = fs_small * 1.35
    text_block = fs_title * 1.4 + line * 3
    pad = 6 * mm * scale  # שוליים לבנים סביב ה-QR (quiet zone)

    qr_size = min(cell_w - 2 * pad, cell_h - text_block - 3 * pad)
    exp_str = dt.datetime.fromtimestamp(exp_ts).strftime("%d %b %Y, %H:%M")
    date_str = lecture_date.strftime("%d %b %Y")
    text_w = cell_w - 2 * pad

    c = canvas.Canvas(str(path), pagesize=A4)
    c.setTitle(f"{COURSE_NAME} — {lec}")

    for page_start in range(0, len(codes), per_page):
        page_codes = codes[page_start:page_start + per_page]

        for i, url in enumerate(page_codes):
            # סדר משמאל לימין, מלמעלה למטה
            col = i % cols
            row = i // cols
            x0 = margin + col * cell_w
            y0 = page_h - margin - (row + 1) * cell_h
            cx = x0 + cell_w / 2

            qr_x = cx - qr_size / 2
            qr_y = y0 + cell_h - pad - qr_size
            draw_qr(c, url, qr_x, qr_y, qr_size)

            ty = qr_y - pad - fs_title
            draw_fitted(c, cx, ty, f"{COURSE_NAME} · {COURSE_NUMBER}", FONT_BOLD, fs_title, text_w)
            ty -= line * 1.15
            draw_fitted(c, cx, ty, f"Lecture {date_str}  ·  {lec}", FONT, fs_small, text_w)
            ty -= line
            draw_fitted(c, cx, ty, f"Valid until {exp_str}", FONT, fs_small, text_w)
            ty -= line
            c.setFillColorRGB(0.35, 0.35, 0.35)
            draw_fitted(c, cx, ty, 'Scan, select your name, tap "Mark attendance"', FONT, fs_small, text_w)
            c.setFont(FONT, fs_small * 0.8)
            c.drawString(x0 + 2 * mm, y0 + 2 * mm, f"#{page_start + i + 1}")
            c.setFillColorRGB(0, 0, 0)

        # קווי חיתוך מקווקווים
        if per_page > 1:
            c.setStrokeColorRGB(0.55, 0.55, 0.55)
            c.setLineWidth(0.5)
            c.setDash(4, 3)
            for k in range(1, cols):
                x = margin + k * cell_w
                c.line(x, 0, x, page_h)
            for k in range(1, rows):
                y = page_h - margin - k * cell_h
                c.line(0, y, page_w, y)
            c.setDash()

        c.showPage()

    c.save()


# ---------- main ----------

def parse_layout(value):
    try:
        cols, rows = (int(v) for v in value.lower().split("x"))
        if not (1 <= cols <= 4 and 1 <= rows <= 5):
            raise ValueError
        return cols, rows
    except ValueError:
        raise argparse.ArgumentTypeError("פריסה בפורמט COLSxROWS, למשל 3x3, 2x2 או 1x1")


def main():
    p = argparse.ArgumentParser(description="הפקת קודי QR לנוכחות")
    p.add_argument("--date", default=dt.date.today().isoformat(),
                   help="תאריך ההרצאה YYYY-MM-DD (ברירת מחדל: היום)")
    p.add_argument("-n", "--count", type=int, default=17, help="מספר קודים (ברירת מחדל: 17)")
    p.add_argument("--hours", type=float, default=24, help="שעות תוקף מרגע ההפקה (ברירת מחדל: 24)")
    p.add_argument("--layout", type=parse_layout, default=(3, 3),
                   help="קודים לעמוד: COLSxROWS (ברירת מחדל: 3x3; 1x1 = קוד אחד לעמוד)")
    p.add_argument("--base-url", default=BASE_URL, help="כתובת אתר ה-GitHub Pages")
    p.add_argument("-o", "--output", help="נתיב קובץ ה-PDF")
    p.add_argument("--init-secret", action="store_true",
                   help="רק ליצור את secret.key (אם לא קיים) ולצאת")
    args = p.parse_args()

    if args.init_secret:
        existed = SECRET_FILE.exists()
        load_secret()
        if existed:
            print(f"{SECRET_FILE.name} כבר קיים — לא נוצר מפתח חדש.")
        return

    try:
        lecture_date = dt.date.fromisoformat(args.date)
    except ValueError:
        sys.exit("תאריך לא תקין, צריך להיות YYYY-MM-DD")
    if args.count < 1:
        sys.exit("מספר הקודים חייב להיות לפחות 1")
    if "<user>" in args.base_url or "<repo>" in args.base_url:
        sys.exit("יש לעדכן את BASE_URL ב-generate.py (או להעביר --base-url) לכתובת אתר ה-GitHub Pages.")
    base_url = args.base_url if args.base_url.endswith("/") else args.base_url + "/"

    secret = load_secret()
    lec = f"{COURSE_NUMBER}-{lecture_date.isoformat()}"
    exp_ts = int(time.time() + args.hours * 3600)

    codes = make_codes(secret, base_url, lec, str(exp_ts), args.count)

    out = Path(args.output) if args.output else OUT_DIR / f"attendance-{lec}.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    cols, rows = args.layout
    build_pdf(out, codes, lec, lecture_date, exp_ts, cols, rows)

    print(f"נוצרו {len(codes)} קודים להרצאה {lec}")
    print(f"בתוקף עד {dt.datetime.fromtimestamp(exp_ts):%d.%m.%Y %H:%M}")
    print(f"PDF: {out}")


if __name__ == "__main__":
    main()
