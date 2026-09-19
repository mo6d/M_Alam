from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, send_file, Response
import sqlite3
from datetime import datetime, date, timedelta
from pathlib import Path
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import csv
import io
import json
import os
import sys
import secrets

APP_NAME = "Al-Masrya"

RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
app = Flask(__name__, template_folder=str(RESOURCE_DIR / "templates"), static_folder=str(RESOURCE_DIR / "static"))
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024

BASE_DIR = Path(os.environ.get("ALMASRYA_BASE_DIR", Path(os.path.dirname(os.path.abspath(__file__)))))
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent

SECRET_FILE = BASE_DIR / ".almasrya_secret"
if os.environ.get("ALMASRYA_SECRET_KEY"):
    app.secret_key = os.environ["ALMASRYA_SECRET_KEY"]
else:
    try:
        if SECRET_FILE.exists():
            app.secret_key = SECRET_FILE.read_text(encoding="utf-8").strip()
        else:
            app.secret_key = secrets.token_hex(32)
            SECRET_FILE.write_text(app.secret_key, encoding="utf-8")
    except Exception:
        app.secret_key = secrets.token_hex(32)

DB = BASE_DIR / "almasrya.db"
UPLOAD_DIR = BASE_DIR / "uploads" / "products"
ALLOWED_IMAGE_EXTS = {"png", "jpg", "jpeg", "webp", "gif"}

# The data directory may be supplied through ALMASRYA_BASE_DIR (for portable
# installs, tests, and packaged deployments).  SQLite cannot create parent
# directories itself, so ensure the directory exists before the first db()
# call during module initialization.
BASE_DIR.mkdir(parents=True, exist_ok=True)

# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------
def csrf_token_value():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token

app.jinja_env.globals["csrf_token"] = csrf_token_value
app.jinja_env.globals["app_name"] = APP_NAME

@app.before_request
def enforce_csrf():
    if request.method == "POST":
        expected = session.get("_csrf_token")
        provided = request.form.get("csrf_token", "")
        if not expected or not provided or not secrets.compare_digest(str(expected), str(provided)):
            return "طلب غير صالح (CSRF).", 400


@app.before_request
def enforce_password_change():
    if "user_id" not in session:
        return
    allowed_endpoints = {"change_password", "logout", "static"}
    if request.endpoint in allowed_endpoints:
        return
    con = db()
    row = con.execute("SELECT must_change_password FROM users WHERE id=?", (session["user_id"],)).fetchone()
    con.close()
    if row and row["must_change_password"]:
        return redirect(url_for("change_password"))


@app.before_request
def enforce_viewer_readonly():
    """Viewer role can browse everywhere but cannot submit any form that
    changes data. All state-changing routes are POST, so blocking POST
    for Viewers here covers the whole app without annotating every route."""
    if session.get("role") == "Viewer" and request.method == "POST" and request.endpoint not in {"logout", "change_password"}:
        flash("صلاحيتك (مشاهدة فقط) لا تسمح بتعديل البيانات", "danger")
        return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(ValueError)
def handle_bad_number(e):
    flash("تم إدخال قيمة غير صحيحة (رقم متوقع في أحد الحقول). برجاء المراجعة والمحاولة مرة أخرى.", "danger")
    return redirect(request.referrer or url_for("dashboard"))


@app.errorhandler(TypeError)
def handle_missing_field(e):
    flash("حقل مطلوب غير موجود أو فارغ. برجاء استكمال البيانات والمحاولة مرة أخرى.", "danger")
    return redirect(request.referrer or url_for("dashboard"))


# ---------------------------------------------------------------------------
# DB helpers
# ---------------------------------------------------------------------------
def db():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def init_db():
    con = db()
    con.executescript("""
    CREATE TABLE IF NOT EXISTS users(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        full_name TEXT,
        role TEXT DEFAULT 'Employee',
        is_active INTEGER DEFAULT 1
    );

    CREATE TABLE IF NOT EXISTS warehouses(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL,
        location TEXT,
        notes TEXT
    );

    CREATE TABLE IF NOT EXISTS categories(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT UNIQUE NOT NULL
    );

    CREATE TABLE IF NOT EXISTS suppliers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        notes TEXT
    );

    CREATE TABLE IF NOT EXISTS customers(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT,
        address TEXT,
        notes TEXT
    );

    CREATE TABLE IF NOT EXISTS products(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sku TEXT UNIQUE,
        name TEXT NOT NULL,
        category_id INTEGER,
        unit TEXT DEFAULT 'قطعة',
        sale_price REAL DEFAULT 0,
        cost_price REAL DEFAULT 0,
        min_stock REAL DEFAULT 0,
        notes TEXT,
        is_active INTEGER DEFAULT 1,
        created_at TEXT,
        FOREIGN KEY(category_id) REFERENCES categories(id)
    );

    CREATE TABLE IF NOT EXISTS product_stock(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        warehouse_id INTEGER NOT NULL,
        quantity REAL DEFAULT 0,
        UNIQUE(product_id, warehouse_id),
        FOREIGN KEY(product_id) REFERENCES products(id),
        FOREIGN KEY(warehouse_id) REFERENCES warehouses(id)
    );

    CREATE TABLE IF NOT EXISTS purchase_invoices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_no TEXT UNIQUE,
        supplier_id INTEGER,
        warehouse_id INTEGER NOT NULL,
        invoice_date TEXT NOT NULL,
        total REAL DEFAULT 0,
        notes TEXT,
        created_by TEXT,
        created_at TEXT,
        FOREIGN KEY(supplier_id) REFERENCES suppliers(id),
        FOREIGN KEY(warehouse_id) REFERENCES warehouses(id)
    );

    CREATE TABLE IF NOT EXISTS purchase_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        unit_price REAL NOT NULL,
        total REAL NOT NULL,
        FOREIGN KEY(invoice_id) REFERENCES purchase_invoices(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS sale_invoices(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_no TEXT UNIQUE,
        customer_id INTEGER,
        warehouse_id INTEGER NOT NULL,
        invoice_date TEXT NOT NULL,
        total REAL DEFAULT 0,
        notes TEXT,
        created_by TEXT,
        created_at TEXT,
        FOREIGN KEY(customer_id) REFERENCES customers(id),
        FOREIGN KEY(warehouse_id) REFERENCES warehouses(id)
    );

    CREATE TABLE IF NOT EXISTS sale_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        unit_price REAL NOT NULL,
        total REAL NOT NULL,
        FOREIGN KEY(invoice_id) REFERENCES sale_invoices(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    );

    CREATE TABLE IF NOT EXISTS stock_movements(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER NOT NULL,
        warehouse_id INTEGER NOT NULL,
        movement_type TEXT NOT NULL,
        quantity REAL NOT NULL,
        balance_after REAL,
        ref_type TEXT,
        ref_id INTEGER,
        note TEXT,
        created_by TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(product_id) REFERENCES products(id),
        FOREIGN KEY(warehouse_id) REFERENCES warehouses(id)
    );

    CREATE TABLE IF NOT EXISTS settings(
        key TEXT PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_log(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        action TEXT NOT NULL,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS payments(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_type TEXT NOT NULL,      -- 'sale' or 'purchase'
        invoice_id INTEGER NOT NULL,
        amount REAL NOT NULL,
        payment_date TEXT NOT NULL,
        method TEXT,
        note TEXT,
        created_by TEXT,
        created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS stocktakes(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        warehouse_id INTEGER NOT NULL,
        stocktake_date TEXT NOT NULL,
        note TEXT,
        created_by TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY(warehouse_id) REFERENCES warehouses(id)
    );

    CREATE TABLE IF NOT EXISTS stocktake_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        stocktake_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        system_qty REAL NOT NULL,
        counted_qty REAL NOT NULL,
        diff REAL NOT NULL,
        FOREIGN KEY(stocktake_id) REFERENCES stocktakes(id),
        FOREIGN KEY(product_id) REFERENCES products(id)
    );
    """)

    # Merge any legacy duplicate stock rows before using stock counts or adjustments.
    duplicate_stock_groups = con.execute("""SELECT product_id, warehouse_id, MIN(id) AS keep_id, SUM(quantity) AS total_qty, COUNT(*) AS row_count
                                             FROM product_stock GROUP BY product_id, warehouse_id HAVING COUNT(*) > 1""").fetchall()
    for group in duplicate_stock_groups:
        con.execute("UPDATE product_stock SET quantity=? WHERE id=?", (group["total_qty"], group["keep_id"]))
        con.execute("DELETE FROM product_stock WHERE product_id=? AND warehouse_id=? AND id<>?", (group["product_id"], group["warehouse_id"], group["keep_id"]))

    # Payment-tracking migration for older DB files.
    pur_cols = [r["name"] for r in con.execute("PRAGMA table_info(purchase_invoices)").fetchall()]
    if "paid_amount" not in pur_cols:
        con.execute("ALTER TABLE purchase_invoices ADD COLUMN paid_amount REAL DEFAULT 0")

    sal_cols = [r["name"] for r in con.execute("PRAGMA table_info(sale_invoices)").fetchall()]
    if "paid_amount" not in sal_cols:
        con.execute("ALTER TABLE sale_invoices ADD COLUMN paid_amount REAL DEFAULT 0")

    # Cancellation-tracking migration.
    pur_cols = [r["name"] for r in con.execute("PRAGMA table_info(purchase_invoices)").fetchall()]
    if "is_cancelled" not in pur_cols:
        con.execute("ALTER TABLE purchase_invoices ADD COLUMN is_cancelled INTEGER DEFAULT 0")
        con.execute("ALTER TABLE purchase_invoices ADD COLUMN cancelled_by TEXT")
        con.execute("ALTER TABLE purchase_invoices ADD COLUMN cancelled_at TEXT")
        con.execute("ALTER TABLE purchase_invoices ADD COLUMN cancel_reason TEXT")

    sal_cols = [r["name"] for r in con.execute("PRAGMA table_info(sale_invoices)").fetchall()]
    if "is_cancelled" not in sal_cols:
        con.execute("ALTER TABLE sale_invoices ADD COLUMN is_cancelled INTEGER DEFAULT 0")
        con.execute("ALTER TABLE sale_invoices ADD COLUMN cancelled_by TEXT")
        con.execute("ALTER TABLE sale_invoices ADD COLUMN cancelled_at TEXT")
        con.execute("ALTER TABLE sale_invoices ADD COLUMN cancel_reason TEXT")

    # Preserve the product cost used at the moment each sale line was created.
    # This keeps historical profit reports stable after a product cost is edited.
    sale_item_cols = [r["name"] for r in con.execute("PRAGMA table_info(sale_items)").fetchall()]
    if "cost_price" not in sale_item_cols:
        con.execute("ALTER TABLE sale_items ADD COLUMN cost_price REAL")
    con.execute("""
        UPDATE sale_items
        SET cost_price = (
            SELECT COALESCE(p.cost_price, 0)
            FROM products p
            WHERE p.id = sale_items.product_id
        )
        WHERE cost_price IS NULL
    """)

    # Self password-change tracking (forces change of the default admin password).
    user_cols = [r["name"] for r in con.execute("PRAGMA table_info(users)").fetchall()]
    if "must_change_password" not in user_cols:
        con.execute("ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0")
    if "permissions" not in user_cols:
        con.execute("ALTER TABLE users ADD COLUMN permissions TEXT DEFAULT ''")
    default_employee_permissions = "edit_invoices,manage_payments,manage_returns,manage_inventory,manage_contacts,view_reports"
    con.execute("UPDATE users SET permissions=? WHERE role IN ('Employee','Manager') AND (permissions IS NULL OR permissions='')", (default_employee_permissions,))

    # Invoice-level discount/tax migration.
    for table in ("purchase_invoices", "sale_invoices"):
        cols = [r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()]
        if "subtotal" not in cols:
            con.execute(f"ALTER TABLE {table} ADD COLUMN subtotal REAL DEFAULT 0")
        if "discount_percent" not in cols:
            con.execute(f"ALTER TABLE {table} ADD COLUMN discount_percent REAL DEFAULT 0")
        if "tax_percent" not in cols:
            con.execute(f"ALTER TABLE {table} ADD COLUMN tax_percent REAL DEFAULT 0")
    # Backfill: for pre-existing rows, subtotal = total (no discount/tax retroactively).
    con.execute("UPDATE purchase_invoices SET subtotal = total WHERE subtotal = 0 AND total > 0")
    con.execute("UPDATE sale_invoices SET subtotal = total WHERE subtotal = 0 AND total > 0")

    # Product photo migration.
    prod_cols = [r["name"] for r in con.execute("PRAGMA table_info(products)").fetchall()]
    if "photo_path" not in prod_cols:
        con.execute("ALTER TABLE products ADD COLUMN photo_path TEXT")
    if "barcode" not in prod_cols:
        con.execute("ALTER TABLE products ADD COLUMN barcode TEXT")
    
    # Wholesale price migration
    if "wholesale_price" not in prod_cols:
        con.execute("ALTER TABLE products ADD COLUMN wholesale_price REAL DEFAULT 0")

    # Treasury/Cash Flow table
    con.execute("""CREATE TABLE IF NOT EXISTS treasury(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        transaction_date TEXT NOT NULL,
        transaction_type TEXT NOT NULL,
        category TEXT,
        amount REAL NOT NULL,
        description TEXT,
        reference_type TEXT,
        reference_id INTEGER,
        created_by TEXT,
        created_at TEXT NOT NULL
    )""")

    # Profit & Loss classification for treasury movements.
    # Mark whether a treasury movement belongs in the profit/loss calculation.
    treasury_cols = [r["name"] for r in con.execute("PRAGMA table_info(treasury)").fetchall()]
    if "affects_profit" not in treasury_cols:
        con.execute("ALTER TABLE treasury ADD COLUMN affects_profit INTEGER DEFAULT 1")

    con.execute("""CREATE TABLE IF NOT EXISTS profit_loss_records(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        report_date TEXT NOT NULL,
        sale_amount REAL DEFAULT 0,
        cost_amount REAL DEFAULT 0,
        gross_profit REAL DEFAULT 0,
        expenses REAL DEFAULT 0,
        net_profit REAL DEFAULT 0,
        created_at TEXT NOT NULL
    )""")
    audit_cols = [r["name"] for r in con.execute("PRAGMA table_info(audit_log)").fetchall()]
    for col, definition in (("before_data", "TEXT"), ("after_data", "TEXT"), ("document_type", "TEXT"), ("document_id", "INTEGER")):
        if col not in audit_cols:
            con.execute(f"ALTER TABLE audit_log ADD COLUMN {col} {definition}")

    # Partial returns are stored separately so original invoices remain auditable.
    con.execute("""CREATE TABLE IF NOT EXISTS returns(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        invoice_type TEXT NOT NULL,
        invoice_id INTEGER NOT NULL,
        return_date TEXT NOT NULL,
        amount REAL NOT NULL DEFAULT 0,
        reason TEXT,
        created_by TEXT,
        created_at TEXT NOT NULL
    )""")
    for table in ("returns", "payments"):
        cols = [r["name"] for r in con.execute(f"PRAGMA table_info({table})").fetchall()]
        if "document_no" not in cols:
            con.execute(f"ALTER TABLE {table} ADD COLUMN document_no TEXT")
    con.execute("""CREATE TABLE IF NOT EXISTS return_items(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        return_id INTEGER NOT NULL,
        invoice_item_id INTEGER NOT NULL,
        quantity REAL NOT NULL,
        unit_price REAL NOT NULL,
        cost_price REAL DEFAULT 0,
        total REAL NOT NULL,
        FOREIGN KEY(return_id) REFERENCES returns(id) ON DELETE CASCADE
    )""")
    return_cols = [r["name"] for r in con.execute("PRAGMA table_info(returns)").fetchall()]
    if "refund_method" not in return_cols:
        con.execute("ALTER TABLE returns ADD COLUMN refund_method TEXT DEFAULT 'خصم من رصيد العميل'")
    if "refund_amount" not in return_cols:
        con.execute("ALTER TABLE returns ADD COLUMN refund_amount REAL DEFAULT 0")
    con.execute("UPDATE returns SET refund_method='خصم من رصيد العميل' WHERE refund_method IS NULL AND invoice_type='sale'")
    con.execute("UPDATE returns SET refund_method='خصم من رصيد المورد' WHERE refund_method IS NULL AND invoice_type='purchase'")

    # Repair historical invoice payments and rebuild their cash-ledger entries.
    backfill_missing_invoice_payments(con)
    backfill_treasury_from_payments(con)

    if con.execute("SELECT COUNT(*) c FROM users").fetchone()["c"] == 0:
        con.execute("""INSERT INTO users(username,password,full_name,role,must_change_password)
                        VALUES(?,?,?,?,1)""",
                    ("admin", generate_password_hash("admin123"), "المدير العام", "Admin"))

    if con.execute("SELECT COUNT(*) c FROM warehouses").fetchone()["c"] == 0:
        con.execute("INSERT INTO warehouses(name,location,notes) VALUES(?,?,?)",
                    ("المخزن الرئيسي", "", ""))

    defaults = {"company_name": APP_NAME, "currency": "ج.م", "closed_period_until": ""}
    for k, v in defaults.items():
        if con.execute("SELECT COUNT(*) c FROM settings WHERE key=?", (k,)).fetchone()["c"] == 0:
            con.execute("INSERT INTO settings(key,value) VALUES(?,?)", (k, v))

    con.commit()
    con.close()


def get_setting(key, default=""):
    con = db()
    row = con.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
    con.close()
    return row["value"] if row else default


def financial_period_closed(transaction_date):
    """Return True when a transaction date is on or before the closed date."""
    closed_until = get_setting("closed_period_until", "").strip()
    if not closed_until or not transaction_date:
        return False
    try:
        return date.fromisoformat(str(transaction_date)) <= date.fromisoformat(closed_until)
    except ValueError:
        return False


def reject_if_period_closed(transaction_date, endpoint):
    if financial_period_closed(transaction_date):
        flash(f"الفترة المالية مغلقة حتى {get_setting('closed_period_until')}. لا يمكن تسجيل حركة بتاريخ {transaction_date}.", "danger")
        return redirect(url_for(endpoint))
    return None


def audit(action, before=None, after=None, document_type=None, document_id=None):
    try:
        con = db()
        before_json = json.dumps(before, ensure_ascii=False, default=str) if before is not None else None
        after_json = json.dumps(after, ensure_ascii=False, default=str) if after is not None else None
        con.execute("""INSERT INTO audit_log(username,action,created_at,before_data,after_data,document_type,document_id)
                       VALUES(?,?,?,?,?,?,?)""",
                    (session.get("username", "system"), action, datetime.now().isoformat(timespec="seconds"),
                     before_json, after_json, document_type, document_id))
        con.commit()
        con.close()
    except Exception:
        pass

def next_document_no(prefix, table, con):
    row = con.execute(f"SELECT COUNT(*) AS c FROM {table}").fetchone()
    return f"{prefix}-{datetime.now().strftime('%Y%m')}-{(row['c'] or 0) + 1:04d}"


def next_invoice_no(prefix, table, con=None):
    """Generate a candidate invoice number. Not guaranteed unique under
    concurrency by itself — callers must retry on IntegrityError using
    insert_with_invoice_no() below."""
    should_close = con is None
    if con is None:
        con = db()
    row = con.execute(f"SELECT COUNT(*) c FROM {table}").fetchone()
    if should_close:
        con.close()
    n = (row["c"] or 0) + 1
    return f"{prefix}-{datetime.now().strftime('%Y%m')}-{n:04d}"


def insert_with_unique_invoice_no(con, prefix, table, insert_fn, max_attempts=5):
    """Call insert_fn(invoice_no) which must INSERT the invoice row and
    return its lastrowid. If the invoice_no collides (rare, only under
    concurrent saves), regenerate a new number and retry."""
    last_error = None
    for _ in range(max_attempts):
        invoice_no = next_invoice_no(prefix, table, con=con)
        try:
            invoice_id = insert_fn(invoice_no)
            return invoice_no, invoice_id
        except sqlite3.IntegrityError as e:
            last_error = e
            continue
    raise last_error


def record_payment_treasury(con, payment_id):
    """Create the cash movement belonging to one invoice payment exactly once."""
    row = con.execute("""
        SELECT p.*, COALESCE(si.invoice_no, pi.invoice_no) AS invoice_no
        FROM payments p
        LEFT JOIN sale_invoices si ON p.invoice_type='sale' AND si.id=p.invoice_id
        LEFT JOIN purchase_invoices pi ON p.invoice_type='purchase' AND pi.id=p.invoice_id
        WHERE p.id=?
    """, (payment_id,)).fetchone()
    if not row or row["invoice_type"] not in {"sale", "purchase"}:
        return
    amount = float(row["amount"] or 0)
    if amount <= 0:
        return
    reference_type = "sale_payment" if row["invoice_type"] == "sale" else "purchase_payment"
    if con.execute("SELECT 1 FROM treasury WHERE reference_type=? AND reference_id=? LIMIT 1",
                   (reference_type, payment_id)).fetchone():
        return
    is_sale = row["invoice_type"] == "sale"
    transaction_type = "دخول" if is_sale else "خروج"
    category = "تحصيل مبيعات" if is_sale else "سداد مشتريات"
    action = "تحصيل من عميل" if is_sale else "سداد لمورد"
    description = f"{action} - فاتورة {row['invoice_no'] or row['invoice_id']}"
    if row["method"]:
        description += f" - الطريقة: {row['method']}"
    if row["note"]:
        description += f" - {row['note']}"
    transaction_date = row["payment_date"] or date.today().isoformat()
    created_at = row["created_at"] or datetime.now().isoformat(timespec="seconds")
    con.execute("""INSERT INTO treasury(
        transaction_date, transaction_type, category, amount, description,
        reference_type, reference_id, affects_profit, created_by, created_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
    (transaction_date, transaction_type, category, amount, description,
     reference_type, payment_id, 0, row["created_by"], created_at))


def record_invoice_cancel_treasury(con, invoice_type, invoice_id, invoice_no,
                                   paid_amount, cancelled_at=None, created_by=None):
    """Reverse the net cash paid on a cancelled invoice, idempotently."""
    amount = float(paid_amount or 0)
    if invoice_type == "sale":
        refunded = con.execute(
            "SELECT COALESCE(SUM(refund_amount),0) AS total FROM returns WHERE invoice_type='sale' AND invoice_id=?",
            (invoice_id,)).fetchone()["total"] or 0
        amount = max(amount - float(refunded), 0.0)
        reference_type, transaction_type = "sale_cancel", "خروج"
        category, action = "عكس تحصيل بيع", "عكس تحصيل فاتورة بيع"
    else:
        reference_type, transaction_type = "purchase_cancel", "دخول"
        category, action = "عكس سداد شراء", "عكس سداد فاتورة توريد"
    if amount <= 0 or con.execute(
        "SELECT 1 FROM treasury WHERE reference_type=? AND reference_id=? LIMIT 1",
        (reference_type, invoice_id)).fetchone():
        return
    stamp = cancelled_at or datetime.now().isoformat(timespec="seconds")
    con.execute("""INSERT INTO treasury(
        transaction_date, transaction_type, category, amount, description,
        reference_type, reference_id, affects_profit, created_by, created_at
    ) VALUES(?,?,?,?,?,?,?,?,?,?)""",
    (str(stamp)[:10], transaction_type, category, round(amount, 2),
     f"{action} {invoice_no or invoice_id}", reference_type, invoice_id, 0,
     created_by, stamp))


def backfill_missing_invoice_payments(con):
    """Repair old invoices whose paid_amount was not represented in payments."""
    for invoice_type, table, prefix in (
        ("sale", "sale_invoices", "PAY-SAL"),
        ("purchase", "purchase_invoices", "PAY-PUR"),
    ):
        rows = con.execute(f"""
            SELECT i.id, i.invoice_no, i.invoice_date, i.paid_amount, i.created_by,
                   COALESCE(SUM(p.amount),0) AS recorded_paid
            FROM {table} i
            LEFT JOIN payments p ON p.invoice_type=? AND p.invoice_id=i.id
            WHERE COALESCE(i.paid_amount,0) > 0
            GROUP BY i.id
            HAVING i.paid_amount > COALESCE(SUM(p.amount),0) + 0.001
        """, (invoice_type,)).fetchall()
        for row in rows:
            amount = round(float(row["paid_amount"] or 0) - float(row["recorded_paid"] or 0), 2)
            if amount <= 0:
                continue
            cur = con.execute("""INSERT INTO payments(
                invoice_type, invoice_id, amount, payment_date, method, note,
                document_no, created_by, created_at
            ) VALUES(?,?,?,?,?,?,?,?,?)""",
            (invoice_type, row["id"], amount, row["invoice_date"] or date.today().isoformat(),
             "نقدي", "مزامنة دفعة تاريخية من رصيد الفاتورة",
             next_document_no(prefix, "payments", con), row["created_by"],
             datetime.now().isoformat(timespec="seconds")))
            record_payment_treasury(con, cur.lastrowid)


def backfill_treasury_from_payments(con):
    """Backfill the treasury ledger for all existing invoice payments."""
    rows = con.execute("SELECT id FROM payments ORDER BY id").fetchall()
    for row in rows:
        record_payment_treasury(con, row["id"])
    for invoice_type, table in (("sale", "sale_invoices"), ("purchase", "purchase_invoices")):
        rows = con.execute(f"""
            SELECT id, invoice_no, paid_amount, cancelled_at, created_by
            FROM {table} WHERE COALESCE(is_cancelled,0)=1 AND COALESCE(paid_amount,0)>0
        """).fetchall()
        for row in rows:
            record_invoice_cancel_treasury(con, invoice_type, row["id"], row["invoice_no"],
                                           row["paid_amount"], row["cancelled_at"], row["created_by"])


# ---------------------------------------------------------------------------
# Auth decorators and granular permissions
# ---------------------------------------------------------------------------
DEFAULT_EMPLOYEE_PERMISSIONS = {"edit_invoices", "manage_payments", "manage_returns", "manage_inventory", "manage_contacts", "view_reports"}
PERMISSION_LABELS = {
    "edit_invoices": "تعديل الفواتير",
    "manage_payments": "التحصيل والسداد",
    "manage_returns": "المرتجعات",
    "manage_inventory": "تعديل المخزون والتحويل والجرد",
    "manage_contacts": "العملاء والموردون",
    "view_reports": "التقارير والحسابات",
}

def has_permission(permission):
    if session.get("role") == "Admin":
        return True
    if session.get("role") == "Viewer":
        return False
    con = db()
    row = con.execute("SELECT role, permissions FROM users WHERE id=?", (session.get("user_id"),)).fetchone()
    con.close()
    if not row:
        return False
    if row["role"] in ("Employee", "Manager") and not (row["permissions"] or "").strip():
        return permission in DEFAULT_EMPLOYEE_PERMISSIONS
    return permission in {x.strip() for x in (row["permissions"] or "").split(",") if x.strip()}

def permission_required(permission):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if not has_permission(permission):
                flash(f"لا تملك صلاحية: {PERMISSION_LABELS.get(permission, permission)}", "danger")
                return redirect(request.referrer or url_for("dashboard"))
            return fn(*args, **kwargs)
        return wrapper
    return decorator

def login_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return fn(*args, **kwargs)
    return wrapper


def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "Admin":
            flash("هذه العملية متاحة للمدير فقط", "danger")
            return redirect(request.referrer or url_for("dashboard"))
        return fn(*args, **kwargs)
    return wrapper


@app.context_processor
def inject_now():
    low_stock_count = 0
    overdue_debt_count = 0
    underpriced_count = 0
    if "user_id" in session:
        try:
            con = db()
            low_stock_count = con.execute("""
                SELECT COUNT(*) c FROM product_stock ps
                JOIN products p ON p.id = ps.product_id
                WHERE p.is_active = 1 AND p.min_stock > 0 AND ps.quantity <= p.min_stock
            """).fetchone()["c"]
            overdue_debt_count = con.execute("""
                SELECT COUNT(*) c FROM (
                  SELECT si.id FROM sale_invoices si WHERE si.is_cancelled=0 AND si.total - si.paid_amount - COALESCE((SELECT SUM(amount) FROM returns WHERE invoice_type='sale' AND invoice_id=si.id),0) > 0.001
                  UNION ALL
                  SELECT pi.id FROM purchase_invoices pi WHERE pi.is_cancelled=0 AND pi.total - pi.paid_amount - COALESCE((SELECT SUM(amount) FROM returns WHERE invoice_type='purchase' AND invoice_id=pi.id),0) > 0.001
                )
            """).fetchone()["c"]
            underpriced_count = con.execute("""
                SELECT COUNT(*) c FROM sale_items si JOIN sale_invoices inv ON inv.id=si.invoice_id
                WHERE inv.is_cancelled=0 AND si.unit_price < si.cost_price
            """).fetchone()["c"]
            con.close()
        except Exception:
            low_stock_count = 0
    return {"now": datetime.now().strftime("%Y-%m-%d %H:%M"),
            "company_name": get_setting("company_name", APP_NAME),
            "currency": get_setting("currency", "ج.م"),
            "low_stock_count": low_stock_count,
            "overdue_debt_count": locals().get("overdue_debt_count", 0),
            "underpriced_count": locals().get("underpriced_count", 0)}


# ---------------------------------------------------------------------------
# Auth routes
# ---------------------------------------------------------------------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        con = db()
        user = con.execute("SELECT * FROM users WHERE username=?", (u,)).fetchone()
        con.close()
        valid = False
        if user and user["is_active"]:
            try:
                valid = check_password_hash(user["password"], p)
            except Exception:
                valid = (user["password"] == p)
        if valid:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["full_name"] = user["full_name"]
            session["role"] = user["role"]
            audit("تسجيل دخول")
            if user["must_change_password"]:
                flash("برجاء تغيير كلمة المرور الافتراضية قبل المتابعة", "danger")
                return redirect(url_for("change_password"))
            return redirect(url_for("dashboard"))
        flash("اسم المستخدم أو كلمة المرور غير صحيحة", "danger")
    return render_template("login.html", title="تسجيل الدخول")


@app.route("/logout")
def logout():
    audit("تسجيل خروج")
    session.clear()
    return redirect(url_for("login"))


@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    con = db()
    user = con.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if request.method == "POST":
        current = request.form.get("current_password", "")
        new_pw = request.form.get("new_password", "")
        confirm = request.form.get("confirm_password", "")
        try:
            current_ok = check_password_hash(user["password"], current)
        except Exception:
            current_ok = (user["password"] == current)

        if not current_ok:
            flash("كلمة المرور الحالية غير صحيحة", "danger")
        elif len(new_pw) < 6:
            flash("كلمة المرور الجديدة يجب ألا تقل عن 6 أحرف", "danger")
        elif new_pw != confirm:
            flash("كلمة المرور الجديدة وتأكيدها غير متطابقين", "danger")
        else:
            con.execute("UPDATE users SET password=?, must_change_password=0 WHERE id=?",
                        (generate_password_hash(new_pw), user["id"]))
            con.commit()
            con.close()
            audit("تغيير كلمة المرور الذاتية")
            flash("تم تغيير كلمة المرور بنجاح", "success")
            return redirect(url_for("dashboard"))
    con.close()
    return render_template("change_password.html", title="تغيير كلمة المرور",
                            force_change=bool(user["must_change_password"]))


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
@app.route("/")
@login_required
def dashboard():
    con = db()
    products_count = con.execute("SELECT COUNT(*) c FROM products WHERE is_active=1").fetchone()["c"]
    warehouses_count = con.execute("SELECT COUNT(*) c FROM warehouses").fetchone()["c"]
    total_qty = con.execute("SELECT COALESCE(SUM(quantity),0) s FROM product_stock").fetchone()["s"]
    stock_value = con.execute("""
        SELECT COALESCE(SUM(ps.quantity * p.cost_price),0) v
        FROM product_stock ps JOIN products p ON p.id = ps.product_id
    """).fetchone()["v"]

    low_stock = con.execute("""
        SELECT p.id, p.name, p.min_stock, w.name AS warehouse, ps.quantity
        FROM product_stock ps
        JOIN products p ON p.id = ps.product_id
        JOIN warehouses w ON w.id = ps.warehouse_id
        WHERE p.is_active=1 AND p.min_stock > 0 AND ps.quantity <= p.min_stock
        ORDER BY ps.quantity ASC
        LIMIT 8
    """).fetchall()

    today = date.today().isoformat()
    month_start = date.today().replace(day=1).isoformat()
    sales_today = con.execute(
        "SELECT COALESCE(SUM(total),0) s FROM sale_invoices WHERE invoice_date=? AND is_cancelled=0",
        (today,)).fetchone()["s"]
    sales_today -= con.execute(
        "SELECT COALESCE(SUM(amount),0) s FROM returns WHERE invoice_type='sale' AND return_date=?",
        (today,)).fetchone()["s"]
    sales_month = con.execute(
        "SELECT COALESCE(SUM(total),0) s FROM sale_invoices WHERE invoice_date>=? AND is_cancelled=0",
        (month_start,)).fetchone()["s"]
    sales_month -= con.execute(
        "SELECT COALESCE(SUM(amount),0) s FROM returns WHERE invoice_type='sale' AND return_date>=?",
        (month_start,)).fetchone()["s"]
    purchases_month = con.execute(
        "SELECT COALESCE(SUM(total),0) s FROM purchase_invoices WHERE invoice_date>=? AND is_cancelled=0",
        (month_start,)).fetchone()["s"]
    purchases_month -= con.execute(
        "SELECT COALESCE(SUM(amount),0) s FROM returns WHERE invoice_type='purchase' AND return_date>=?",
        (month_start,)).fetchone()["s"]

    recent_movements = con.execute("""
        SELECT sm.*, p.name AS product_name, w.name AS warehouse_name
        FROM stock_movements sm
        JOIN products p ON p.id = sm.product_id
        JOIN warehouses w ON w.id = sm.warehouse_id
        ORDER BY sm.id DESC LIMIT 10
    """).fetchall()

    # Last 14 days of sales totals, for the dashboard chart.
    chart_rows = con.execute("""
        SELECT invoice_date, COALESCE(SUM(total),0) AS total
        FROM sale_invoices
        WHERE is_cancelled = 0 AND invoice_date >= date('now', '-13 days')
        GROUP BY invoice_date
    """).fetchall()
    sales_by_date = {r["invoice_date"]: r["total"] for r in chart_rows}
    return_rows = con.execute("""
        SELECT return_date, COALESCE(SUM(amount),0) AS total
        FROM returns WHERE invoice_type='sale' AND return_date >= date('now', '-13 days')
        GROUP BY return_date
    """).fetchall()
    for row in return_rows:
        sales_by_date[row["return_date"]] = sales_by_date.get(row["return_date"], 0) - row["total"]
    chart_labels = []
    chart_values = []
    for i in range(13, -1, -1):
        d = (date.today() - timedelta(days=i)).isoformat()
        chart_labels.append(d[5:])  # MM-DD
        chart_values.append(round(max(sales_by_date.get(d, 0), 0), 2))

    con.close()
    return render_template("dashboard.html", title="لوحة التحكم",
                            products_count=products_count, warehouses_count=warehouses_count,
                            total_qty=total_qty, stock_value=stock_value,
                            low_stock=low_stock, sales_today=sales_today,
                            sales_month=sales_month, purchases_month=purchases_month,
                            recent_movements=recent_movements,
                            chart_labels=chart_labels, chart_values=chart_values)


# ---------------------------------------------------------------------------
# Warehouses
# ---------------------------------------------------------------------------
@app.route("/warehouses", methods=["GET", "POST"])
@login_required
def warehouses():
    con = db()
    if request.method == "POST":
        if not has_permission("manage_inventory"):
            flash(f"لا تملك صلاحية: {PERMISSION_LABELS['manage_inventory']}", "danger")
            return redirect(url_for("warehouses"))
        name = request.form.get("name", "").strip()
        location = request.form.get("location", "").strip()
        notes = request.form.get("notes", "").strip()
        if name:
            try:
                con.execute("INSERT INTO warehouses(name,location,notes) VALUES(?,?,?)", (name, location, notes))
                con.commit()
                audit(f"إضافة مخزن: {name}")
                flash("تم إضافة المخزن", "success")
            except sqlite3.IntegrityError:
                flash("يوجد مخزن بهذا الاسم بالفعل", "danger")
        return redirect(url_for("warehouses"))

    rows = con.execute("""
        SELECT w.*, COALESCE(SUM(ps.quantity),0) AS total_qty
        FROM warehouses w
        LEFT JOIN product_stock ps ON ps.warehouse_id = w.id
        GROUP BY w.id ORDER BY w.name
    """).fetchall()
    con.close()
    return render_template("warehouses.html", title="المخازن", warehouses=rows)


@app.route("/warehouses/<int:wid>/delete", methods=["POST"])
@admin_required
def delete_warehouse(wid):
    con = db()
    used = con.execute("SELECT COUNT(*) c FROM product_stock WHERE warehouse_id=? AND quantity>0", (wid,)).fetchone()["c"]
    if used:
        flash("لا يمكن حذف مخزن يحتوي على مخزون. قم بتفريغه أولاً", "danger")
    else:
        w = con.execute("SELECT name FROM warehouses WHERE id=?", (wid,)).fetchone()
        con.execute("DELETE FROM warehouses WHERE id=?", (wid,))
        con.commit()
        audit(f"حذف مخزن: {w['name'] if w else wid}")
        flash("تم حذف المخزن", "success")
    con.close()
    return redirect(url_for("warehouses"))


# ---------------------------------------------------------------------------
# Categories
# ---------------------------------------------------------------------------
@app.route("/categories", methods=["GET", "POST"])
@login_required
def categories():
    con = db()
    if request.method == "POST":
        if not has_permission("manage_inventory"):
            flash(f"لا تملك صلاحية: {PERMISSION_LABELS['manage_inventory']}", "danger")
            con.close()
            return redirect(url_for("categories"))
        name = request.form.get("name", "").strip()
        if name:
            try:
                con.execute("INSERT INTO categories(name) VALUES(?)", (name,))
                con.commit()
                flash("تم إضافة التصنيف", "success")
            except sqlite3.IntegrityError:
                flash("هذا التصنيف موجود بالفعل", "danger")
        return redirect(url_for("categories"))
    rows = con.execute("""
        SELECT c.*, COUNT(p.id) AS product_count
        FROM categories c LEFT JOIN products p ON p.category_id = c.id
        GROUP BY c.id ORDER BY c.name
    """).fetchall()
    con.close()
    return render_template("categories.html", title="التصنيفات", categories=rows)


@app.route("/categories/<int:cid>/delete", methods=["POST"])
@admin_required
def delete_category(cid):
    con = db()
    con.execute("UPDATE products SET category_id=NULL WHERE category_id=?", (cid,))
    con.execute("DELETE FROM categories WHERE id=?", (cid,))
    con.commit()
    con.close()
    flash("تم حذف التصنيف", "success")
    return redirect(url_for("categories"))


# ---------------------------------------------------------------------------
# Suppliers
# ---------------------------------------------------------------------------
@app.route("/suppliers", methods=["GET", "POST"])
@login_required
def suppliers():
    con = db()
    if request.method == "POST":
        if not has_permission("manage_contacts"):
            flash(f"لا تملك صلاحية: {PERMISSION_LABELS['manage_contacts']}", "danger")
            con.close()
            return redirect(url_for("suppliers"))
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        notes = request.form.get("notes", "").strip()
        if name:
            con.execute("INSERT INTO suppliers(name,phone,address,notes) VALUES(?,?,?,?)", (name, phone, address, notes))
            con.commit()
            audit(f"إضافة مورد: {name}")
            flash("تم إضافة المورد", "success")
        return redirect(url_for("suppliers"))
    q = request.args.get("q", "").strip()
    if q:
        prefix = f"{q}%"
        contains = f"%{q}%"
        rows = con.execute("""SELECT * FROM suppliers
            WHERE name LIKE ? OR phone LIKE ?
            ORDER BY CASE WHEN name LIKE ? THEN 0 ELSE 1 END, name""",
            (prefix, contains, prefix)).fetchall()
    else:
        rows = con.execute("SELECT * FROM suppliers ORDER BY name").fetchall()
    con.close()
    return render_template("suppliers.html", title="الموردون", suppliers=rows, q=q)


@app.route("/suppliers/<int:sid>/delete", methods=["POST"])
@admin_required
def delete_supplier(sid):
    con = db()
    used = con.execute("SELECT COUNT(*) c FROM purchase_invoices WHERE supplier_id=?", (sid,)).fetchone()["c"]
    if used:
        flash("لا يمكن حذف مورد مرتبط بفواتير توريد", "danger")
    else:
        con.execute("DELETE FROM suppliers WHERE id=?", (sid,))
        con.commit()
        flash("تم حذف المورد", "success")
    con.close()
    return redirect(url_for("suppliers"))


@app.route("/suppliers/<int:sid>")
@login_required
def supplier_detail(sid):
    con = db()
    supplier = con.execute("SELECT * FROM suppliers WHERE id=?", (sid,)).fetchone()
    if not supplier:
        con.close()
        flash("المورد غير موجود", "danger")
        return redirect(url_for("suppliers"))
    invoices = con.execute("""
        SELECT pi.*, w.name AS warehouse_name,
               COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0) AS returned_amount,
               pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0) AS net_total
        FROM purchase_invoices pi
        JOIN warehouses w ON w.id = pi.warehouse_id
        WHERE pi.supplier_id=? ORDER BY pi.invoice_date DESC, pi.id DESC
    """, (sid,)).fetchall()
    active = [i for i in invoices if not i["is_cancelled"]]
    total_business = sum(i["net_total"] for i in active)
    total_paid = sum(i["paid_amount"] for i in active)
    total_remaining = sum(max(i["net_total"] - i["paid_amount"], 0) for i in active)
    con.close()
    return render_template("supplier_detail.html", title=f"المورد: {supplier['name']}",
                            supplier=supplier, invoices=invoices, total_business=total_business,
                            total_paid=total_paid, total_remaining=total_remaining)


# ---------------------------------------------------------------------------
# Customers
# ---------------------------------------------------------------------------
@app.route("/customers", methods=["GET", "POST"])
@login_required
def customers():
    con = db()
    if request.method == "POST":
        if not has_permission("manage_contacts"):
            flash(f"لا تملك صلاحية: {PERMISSION_LABELS['manage_contacts']}", "danger")
            con.close()
            return redirect(url_for("customers"))
        name = request.form.get("name", "").strip()
        phone = request.form.get("phone", "").strip()
        address = request.form.get("address", "").strip()
        notes = request.form.get("notes", "").strip()
        if name:
            con.execute("INSERT INTO customers(name,phone,address,notes) VALUES(?,?,?,?)", (name, phone, address, notes))
            con.commit()
            audit(f"إضافة عميل: {name}")
            flash("تم إضافة العميل", "success")
        return redirect(url_for("customers"))
    q = request.args.get("q", "").strip()
    if q:
        prefix = f"{q}%"
        contains = f"%{q}%"
        rows = con.execute("""SELECT * FROM customers
            WHERE name LIKE ? OR phone LIKE ?
            ORDER BY CASE WHEN name LIKE ? THEN 0 ELSE 1 END, name""",
            (prefix, contains, prefix)).fetchall()
    else:
        rows = con.execute("SELECT * FROM customers ORDER BY name").fetchall()
    con.close()
    return render_template("customers.html", title="العملاء", customers=rows, q=q)


@app.route("/customers/<int:cid>/delete", methods=["POST"])
@admin_required
def delete_customer(cid):
    con = db()
    used = con.execute("SELECT COUNT(*) c FROM sale_invoices WHERE customer_id=?", (cid,)).fetchone()["c"]
    if used:
        flash("لا يمكن حذف عميل مرتبط بفواتير بيع", "danger")
    else:
        con.execute("DELETE FROM customers WHERE id=?", (cid,))
        con.commit()
        flash("تم حذف العميل", "success")
    con.close()
    return redirect(url_for("customers"))


@app.route("/customers/<int:cid>")
@login_required
def customer_detail(cid):
    con = db()
    customer = con.execute("SELECT * FROM customers WHERE id=?", (cid,)).fetchone()
    if not customer:
        con.close()
        flash("العميل غير موجود", "danger")
        return redirect(url_for("customers"))
    invoices = con.execute("""
        SELECT si.*, w.name AS warehouse_name,
               COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0) AS returned_amount,
               si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0) AS net_total
        FROM sale_invoices si
        JOIN warehouses w ON w.id = si.warehouse_id
        WHERE si.customer_id=? ORDER BY si.invoice_date DESC, si.id DESC
    """, (cid,)).fetchall()
    active = [i for i in invoices if not i["is_cancelled"]]
    total_business = sum(i["net_total"] for i in active)
    total_paid = sum(i["paid_amount"] for i in active)
    total_remaining = sum(max(i["net_total"] - i["paid_amount"], 0) for i in active)
    con.close()
    return render_template("customer_detail.html", title=f"العميل: {customer['name']}",
                            customer=customer, invoices=invoices, total_business=total_business,
                            total_paid=total_paid, total_remaining=total_remaining)


# ---------------------------------------------------------------------------
# Products
# ---------------------------------------------------------------------------
@app.route("/products")
@login_required
def products():
    con = db()
    q = request.args.get("q", "").strip()
    cat = request.args.get("category", "")
    page = max(1, int(request.args.get("page", 1) or 1))
    per_page = 50
    sql = """
        SELECT p.*, c.name AS category_name,
               COALESCE((SELECT SUM(quantity) FROM product_stock WHERE product_id = p.id), 0) AS total_qty
        FROM products p
        LEFT JOIN categories c ON c.id = p.category_id
        WHERE p.is_active = 1
    """
    count_sql = "SELECT COUNT(*) c FROM products p WHERE p.is_active = 1"
    params = []
    count_params = []
    prefix = f"{q}%" if q else ""
    contains = f"%{q}%" if q else ""
    if q:
        cond = " AND (p.name LIKE ? OR p.sku LIKE ? OR p.barcode LIKE ?)"
        sql += cond
        count_sql += cond
        params += [prefix, contains, contains]
        count_params += [prefix, contains, contains]
    if cat:
        sql += " AND p.category_id = ?"
        count_sql += " AND p.category_id = ?"
        params.append(cat)
        count_params.append(cat)
    total_count = con.execute(count_sql, count_params).fetchone()["c"]
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = min(page, total_pages)
    if q:
        sql += " ORDER BY CASE WHEN p.name LIKE ? THEN 0 ELSE 1 END, p.name LIMIT ? OFFSET ?"
        params += [prefix, per_page, (page - 1) * per_page]
    else:
        sql += " ORDER BY p.name LIMIT ? OFFSET ?"
        params += [per_page, (page - 1) * per_page]
    rows = con.execute(sql, params).fetchall()
    cats = con.execute("SELECT * FROM categories ORDER BY name").fetchall()
    con.close()
    return render_template("products.html", title="المنتجات", products=rows, categories=cats, q=q,
                            selected_cat=cat, page=page, total_pages=total_pages, total_count=total_count)


@app.route("/products/new", methods=["GET", "POST"])
@permission_required("manage_inventory")
def product_new():
    con = db()
    if request.method == "POST":
        sku = request.form.get("sku", "").strip() or None
        name = request.form.get("name", "").strip()
        category_id = request.form.get("category_id") or None
        unit = request.form.get("unit", "قطعة").strip()
        sale_price = float(request.form.get("sale_price") or 0)
        cost_price = float(request.form.get("cost_price") or 0)
        min_stock = float(request.form.get("min_stock") or 0)
        notes = request.form.get("notes", "").strip()
        barcode = request.form.get("barcode", "").strip() or None
        init_qty = float(request.form.get("init_qty") or 0)
        init_warehouse = request.form.get("init_warehouse") or None
        photo_path = save_product_photo(request.files.get("photo"))

        if not name:
            flash("اسم المنتج مطلوب", "danger")
            return redirect(url_for("product_new"))
        try:
            cur = con.execute("""INSERT INTO products(sku,name,category_id,unit,sale_price,cost_price,min_stock,notes,barcode,photo_path,created_at)
                                  VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                               (sku, name, category_id, unit, sale_price, cost_price, min_stock, notes, barcode,
                                photo_path, datetime.now().isoformat(timespec="seconds")))
            pid = cur.lastrowid
            if init_qty > 0 and init_warehouse:
                con.execute("INSERT INTO product_stock(product_id,warehouse_id,quantity) VALUES(?,?,?)",
                            (pid, init_warehouse, init_qty))
                con.execute("""INSERT INTO stock_movements(product_id,warehouse_id,movement_type,quantity,balance_after,ref_type,note,created_by,created_at)
                                VALUES(?,?,?,?,?,?,?,?,?)""",
                            (pid, init_warehouse, "in", init_qty, init_qty, "رصيد افتتاحي", "رصيد افتتاحي عند إضافة الصنف",
                             session.get("username"), datetime.now().isoformat(timespec="seconds")))
            con.commit()
            audit(f"إضافة منتج: {name}")
            flash("تم إضافة المنتج", "success")
            return redirect(url_for("products"))
        except sqlite3.IntegrityError:
            flash("رقم الصنف (SKU) مستخدم بالفعل", "danger")
            return redirect(url_for("product_new"))

    cats = con.execute("SELECT * FROM categories ORDER BY name").fetchall()
    whs = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    con.close()
    return render_template("product_form.html", title="إضافة منتج", categories=cats, warehouses=whs, product=None, stocks=[])


@app.route("/products/<int:pid>/edit", methods=["GET", "POST"])
@permission_required("manage_inventory")
def product_edit(pid):
    con = db()
    if request.method == "POST":
        sku = request.form.get("sku", "").strip() or None
        name = request.form.get("name", "").strip()
        category_id = request.form.get("category_id") or None
        unit = request.form.get("unit", "قطعة").strip()
        sale_price = float(request.form.get("sale_price") or 0)
        cost_price = float(request.form.get("cost_price") or 0)
        min_stock = float(request.form.get("min_stock") or 0)
        notes = request.form.get("notes", "").strip()
        barcode = request.form.get("barcode", "").strip() or None
        existing = con.execute("SELECT photo_path FROM products WHERE id=?", (pid,)).fetchone()
        photo_path = save_product_photo(request.files.get("photo"), existing["photo_path"] if existing else None)
        try:
            con.execute("""UPDATE products SET sku=?,name=?,category_id=?,unit=?,sale_price=?,cost_price=?,min_stock=?,notes=?,barcode=?,photo_path=?
                            WHERE id=?""", (sku, name, category_id, unit, sale_price, cost_price, min_stock, notes,
                                             barcode, photo_path, pid))
            con.commit()
            audit(f"تعديل منتج: {name}")
            flash("تم حفظ التعديلات", "success")
            return redirect(url_for("products"))
        except sqlite3.IntegrityError:
            flash("رقم الصنف (SKU) مستخدم بالفعل", "danger")

    product = con.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not product:
        con.close()
        flash("المنتج غير موجود", "danger")
        return redirect(url_for("products"))
    stocks = con.execute("""
        SELECT ps.*, w.name AS warehouse_name FROM product_stock ps
        JOIN warehouses w ON w.id = ps.warehouse_id
        WHERE ps.product_id = ? ORDER BY w.name
    """, (pid,)).fetchall()
    cats = con.execute("SELECT * FROM categories ORDER BY name").fetchall()
    whs = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    con.close()
    return render_template("product_form.html", title="تعديل منتج", categories=cats, warehouses=whs,
                            product=product, stocks=stocks)


@app.route("/products/<int:pid>/delete", methods=["POST"])
@admin_required
def product_delete(pid):
    con = db()
    p = con.execute("SELECT name FROM products WHERE id=?", (pid,)).fetchone()
    con.execute("UPDATE products SET is_active=0 WHERE id=?", (pid,))
    con.commit()
    con.close()
    audit(f"تعطيل منتج: {p['name'] if p else pid}")
    flash("تم إخفاء المنتج من القوائم النشطة", "success")
    return redirect(url_for("products"))


# ---------------------------------------------------------------------------
# Stock helpers
# ---------------------------------------------------------------------------
def get_stock(con, product_id, warehouse_id):
    row = con.execute("SELECT COALESCE(SUM(quantity),0) AS quantity FROM product_stock WHERE product_id=? AND warehouse_id=?",
                       (product_id, warehouse_id)).fetchone()
    return float(row["quantity"] or 0) if row else 0.0


def update_weighted_average_cost(con, product_id, received_qty, received_unit_cost):
    """Update the product's moving weighted-average cost before stock receipt."""
    product = con.execute("SELECT cost_price FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        return
    current_qty = con.execute("SELECT COALESCE(SUM(quantity),0) AS qty FROM product_stock WHERE product_id=?",
                              (product_id,)).fetchone()["qty"] or 0
    current_cost = float(product["cost_price"] or 0)
    received_qty = float(received_qty or 0)
    received_unit_cost = float(received_unit_cost or 0)
    if received_qty <= 0:
        return
    total_qty = float(current_qty) + received_qty
    if total_qty <= 0:
        return
    weighted_cost = ((float(current_qty) * current_cost) + (received_qty * received_unit_cost)) / total_qty
    con.execute("UPDATE products SET cost_price=? WHERE id=?", (round(weighted_cost, 4), product_id))


def remove_weighted_average_cost(con, product_id, removed_qty, removed_unit_cost):
    """Reverse a purchase quantity from the product's moving average cost."""
    product = con.execute("SELECT cost_price FROM products WHERE id=?", (product_id,)).fetchone()
    if not product:
        return
    current_qty = float(con.execute("SELECT COALESCE(SUM(quantity),0) AS qty FROM product_stock WHERE product_id=?",
                                    (product_id,)).fetchone()["qty"] or 0)
    removed_qty = float(removed_qty or 0)
    if removed_qty <= 0 or current_qty <= 0:
        return
    remaining_qty = current_qty - removed_qty
    if remaining_qty <= 0.000001:
        new_cost = 0.0
    else:
        current_value = current_qty * float(product["cost_price"] or 0)
        removed_value = removed_qty * float(removed_unit_cost or 0)
        new_cost = max((current_value - removed_value) / remaining_qty, 0.0)
    con.execute("UPDATE products SET cost_price=? WHERE id=?", (round(new_cost, 4), product_id))


def save_product_photo(file_storage, existing_path=None):
    """Save an uploaded product image to disk and return its relative path,
    or None if no valid file was provided. Deletes the previous photo file
    if a new one replaces it."""
    if not file_storage or not file_storage.filename:
        return existing_path
    ext = file_storage.filename.rsplit(".", 1)[-1].lower() if "." in file_storage.filename else ""
    if ext not in ALLOWED_IMAGE_EXTS:
        return existing_path
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    fname = f"{secrets.token_hex(8)}.{ext}"
    file_storage.save(str(UPLOAD_DIR / fname))
    if existing_path:
        try:
            (UPLOAD_DIR / existing_path).unlink(missing_ok=True)
        except Exception:
            pass
    return fname


@app.route("/product-photo/<path:filename>")
@login_required
def product_photo(filename):
    if "/" in filename or ".." in filename:
        return "", 404
    fpath = UPLOAD_DIR / filename
    if not fpath.exists():
        return "", 404
    return send_file(str(fpath))


def adjust_stock(con, product_id, warehouse_id, delta, movement_type, ref_type, ref_id, note):
    current = get_stock(con, product_id, warehouse_id)
    new_qty = current + delta
    stock_rows = con.execute("SELECT id FROM product_stock WHERE product_id=? AND warehouse_id=? ORDER BY id", (product_id, warehouse_id)).fetchall()
    if stock_rows:
        con.execute("UPDATE product_stock SET quantity=? WHERE id=?", (new_qty, stock_rows[0]["id"]))
        if len(stock_rows) > 1:
            con.execute("DELETE FROM product_stock WHERE product_id=? AND warehouse_id=? AND id<>?", (product_id, warehouse_id, stock_rows[0]["id"]))
    else:
        con.execute("INSERT INTO product_stock(product_id,warehouse_id,quantity) VALUES(?,?,?)",
                    (product_id, warehouse_id, new_qty))
    con.execute("""INSERT INTO stock_movements(product_id,warehouse_id,movement_type,quantity,balance_after,ref_type,ref_id,note,created_by,created_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?)""",
                (product_id, warehouse_id, movement_type, abs(delta), new_qty, ref_type, ref_id, note,
                 session.get("username"), datetime.now().isoformat(timespec="seconds")))
    return new_qty


# ---------------------------------------------------------------------------
# Invoice editing — update a posted invoice while preserving audit links.
# ---------------------------------------------------------------------------
def _edit_invoice(invoice_type, iid, view_endpoint, list_endpoint):
    con = db()
    is_sale = invoice_type == "sale"
    invoice_table = "sale_invoices" if is_sale else "purchase_invoices"
    item_table = "sale_items" if is_sale else "purchase_items"
    party_table = "customers" if is_sale else "suppliers"
    inv = con.execute(f"SELECT * FROM {invoice_table} WHERE id=?", (iid,)).fetchone()
    if not inv:
        con.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for(list_endpoint))
    if inv["is_cancelled"]:
        con.close()
        flash("لا يمكن تعديل فاتورة ملغاة", "danger")
        return redirect(url_for(view_endpoint, iid=iid))
    if financial_period_closed(inv["invoice_date"]):
        con.close()
        flash(f"الفترة المالية مغلقة حتى {get_setting('closed_period_until')}. افتح الفترة من الإعدادات قبل تعديل الفاتورة.", "danger")
        return redirect(url_for(view_endpoint, iid=iid))

    if request.method == "POST":
        new_date = request.form.get("invoice_date") or inv["invoice_date"]
        if financial_period_closed(new_date):
            con.close()
            flash(f"لا يمكن حفظ التعديل بتاريخ داخل فترة مغلقة حتى {get_setting('closed_period_until')}", "danger")
            return redirect(url_for(view_endpoint, iid=iid))
        try:
            party_id = request.form.get("party_id") or None
            warehouse_id = int(request.form.get("warehouse_id"))
            discount_percent = max(0.0, min(100.0, float(request.form.get("discount_percent") or 0)))
            tax_percent = max(0.0, float(request.form.get("tax_percent") or 0))
        except (TypeError, ValueError):
            con.close()
            flash("بيانات رأس الفاتورة غير صحيحة", "danger")
            return redirect(url_for(view_endpoint, iid=iid))
        notes = request.form.get("notes", "").strip()

        old_items = con.execute(f"SELECT * FROM {item_table} WHERE invoice_id=? ORDER BY id", (iid,)).fetchall()
        old_by_id = {int(row["id"]): row for row in old_items}
        returned_rows = con.execute("""
            SELECT ri.invoice_item_id, COALESCE(SUM(ri.quantity),0) AS quantity
            FROM return_items ri JOIN returns r ON r.id=ri.return_id
            WHERE r.invoice_type=? AND r.invoice_id=? GROUP BY ri.invoice_item_id
        """, (invoice_type, iid)).fetchall()
        returned_by_item = {int(row["invoice_item_id"]): float(row["quantity"] or 0) for row in returned_rows}
        has_returns = bool(returned_by_item)
        if has_returns and int(warehouse_id) != int(inv["warehouse_id"]):
            con.close()
            flash("لا يمكن تغيير المخزن بعد تسجيل مرتجعات لهذه الفاتورة حتى لا تتغير جهة حركة المرتجع.", "danger")
            return redirect(url_for(view_endpoint, iid=iid))

        product_ids = request.form.getlist("product_id[]")
        item_ids = request.form.getlist("item_id[]")
        quantities = request.form.getlist("quantity[]")
        prices = request.form.getlist("unit_price[]")
        new_items = []
        errors = []
        seen_existing = set()
        for index, (pidx, qty_raw, price_raw) in enumerate(zip(product_ids, quantities, prices)):
            if not pidx and not qty_raw:
                continue
            try:
                product_id = int(pidx)
                qty = float(qty_raw)
                price = float(price_raw or 0)
            except (TypeError, ValueError):
                errors.append("يوجد بند يحتوي على رقم غير صحيح")
                continue
            if qty <= 0 or price < 0:
                errors.append("يجب أن تكون الكمية أكبر من صفر والسعر غير سالب")
                continue
            raw_item_id = item_ids[index] if index < len(item_ids) else ""
            item_id = int(raw_item_id) if raw_item_id else None
            old = old_by_id.get(item_id) if item_id else None
            if item_id and not old:
                errors.append("تم اكتشاف بند غير تابع لهذه الفاتورة")
                continue
            if item_id:
                seen_existing.add(item_id)
                returned_qty = returned_by_item.get(item_id, 0.0)
                if qty + 0.001 < returned_qty:
                    errors.append(f"لا يمكن جعل كمية البند أقل من المرتجع المسجل ({returned_qty:g})")
                if returned_qty > 0 and int(old["product_id"]) != product_id:
                    errors.append("لا يمكن تغيير الصنف المرتبط بمرتجع مسجل؛ أضف بنداً جديداً بدلاً من ذلك")
                if returned_qty > 0 and abs(price - float(old["unit_price"] or 0)) > 0.001:
                    errors.append("لا يمكن تغيير سعر بند له مرتجع مسجل حتى تبقى قيمة المرتجع التاريخية صحيحة")
            product = con.execute("SELECT id, name, cost_price FROM products WHERE id=?", (product_id,)).fetchone()
            if not product:
                errors.append("تم اختيار صنف غير موجود")
                continue
            if is_sale:
                if old and int(old["product_id"]) == product_id:
                    cost_price = float(old["cost_price"] or 0)
                else:
                    cost_price = float(product["cost_price"] or 0)
                if cost_price > 0 and price < cost_price and session.get("role") != "Admin":
                    errors.append(f"لا يمكن حفظ بيع {product['name']} بأقل من التكلفة ({cost_price:.2f}) إلا بواسطة المدير")
            else:
                cost_price = price
            new_items.append({"id": item_id, "product_id": product_id, "quantity": qty,
                              "unit_price": price, "total": round(qty * price, 2), "cost_price": cost_price})

        for old_id, returned_qty in returned_by_item.items():
            if old_id not in seen_existing:
                errors.append("لا يمكن حذف بند له مرتجع مسجل")

        if errors or not new_items:
            con.close()
            for error in errors or ["يجب إضافة بند واحد على الأقل"]:
                flash(error, "danger")
            return redirect(url_for(view_endpoint, iid=iid))

        stock_deltas = {}
        for old in old_items:
            key = (int(old["warehouse_id"]) if "warehouse_id" in old.keys() else int(inv["warehouse_id"]), int(old["product_id"]))
            stock_deltas[key] = stock_deltas.get(key, 0.0) + (float(old["quantity"]) if is_sale else -float(old["quantity"]))
        for item in new_items:
            key = (int(warehouse_id), int(item["product_id"]))
            stock_deltas[key] = stock_deltas.get(key, 0.0) + (-float(item["quantity"]) if is_sale else float(item["quantity"]))
        for (wh_id, product_id), delta in stock_deltas.items():
            current = float(get_stock(con, product_id, wh_id) or 0)
            if current + delta < -0.001:
                product = con.execute("SELECT name FROM products WHERE id=?", (product_id,)).fetchone()
                errors.append(f"تعديل الفاتورة سيجعل مخزون {product['name'] if product else product_id} سالباً")
        if errors:
            con.close()
            for error in errors:
                flash(error, "danger")
            return redirect(url_for(view_endpoint, iid=iid))

        subtotal = round(sum(item["total"] for item in new_items), 2)
        after_discount = subtotal * (1 - discount_percent / 100)
        total = round(after_discount * (1 + tax_percent / 100), 2)
        returns_total = float(con.execute("SELECT COALESCE(SUM(amount),0) AS total FROM returns WHERE invoice_type=? AND invoice_id=?", (invoice_type, iid)).fetchone()["total"] or 0)
        paid_amount = float(inv["paid_amount"] or 0)
        if total + 0.001 < paid_amount + returns_total:
            con.close()
            flash(f"لا يمكن تخفيض إجمالي الفاتورة إلى {total:.2f}؛ المدفوع والمرتجعات المسجلة يساويان {paid_amount + returns_total:.2f}", "danger")
            return redirect(url_for(view_endpoint, iid=iid))
        old_total = float(inv["total"] or 0)
        old_date = inv["invoice_date"]

        if not is_sale:
            for old in old_items:
                remove_weighted_average_cost(con, old["product_id"], old["quantity"], old["unit_price"])
        for (wh_id, product_id), delta in stock_deltas.items():
            if abs(delta) > 0.000001:
                movement_type = "edit_sale" if is_sale else "edit_purchase"
                adjust_stock(con, product_id, wh_id, delta, "adjust", movement_type, iid,
                             f"تعديل فاتورة {inv['invoice_no']}")
        if not is_sale:
            for item in new_items:
                update_weighted_average_cost(con, item["product_id"], item["quantity"], item["unit_price"])

        before_snapshot = {"invoice_no": inv["invoice_no"], "party_id": inv["customer_id"] if is_sale else inv["supplier_id"], "warehouse_id": inv["warehouse_id"], "invoice_date": inv["invoice_date"], "subtotal": inv["subtotal"], "total": inv["total"], "notes": inv["notes"]}
        after_snapshot = {"invoice_no": inv["invoice_no"], "party_id": party_id, "warehouse_id": warehouse_id, "invoice_date": new_date, "subtotal": subtotal, "total": total, "notes": notes, "items": [{"product_id": x["product_id"], "quantity": x["quantity"], "unit_price": x["unit_price"]} for x in new_items]}
        con.execute(f"""UPDATE {invoice_table}
                       SET { 'customer_id' if is_sale else 'supplier_id' }=?, warehouse_id=?, invoice_date=?,
                           subtotal=?, discount_percent=?, tax_percent=?, total=?, notes=? WHERE id=?""",
                    (party_id, warehouse_id, new_date, subtotal, discount_percent, tax_percent, total, notes, iid))
        old_ids = set(old_by_id)
        new_ids = {item["id"] for item in new_items if item["id"]}
        for item in new_items:
            if item["id"]:
                if is_sale:
                    con.execute("UPDATE sale_items SET product_id=?, quantity=?, unit_price=?, total=?, cost_price=? WHERE id=? AND invoice_id=?",
                                (item["product_id"], item["quantity"], item["unit_price"], item["total"], item["cost_price"], item["id"], iid))
                else:
                    con.execute("UPDATE purchase_items SET product_id=?, quantity=?, unit_price=?, total=? WHERE id=? AND invoice_id=?",
                                (item["product_id"], item["quantity"], item["unit_price"], item["total"], item["id"], iid))
            elif is_sale:
                con.execute("INSERT INTO sale_items(invoice_id,product_id,quantity,unit_price,total,cost_price) VALUES(?,?,?,?,?,?)",
                            (iid, item["product_id"], item["quantity"], item["unit_price"], item["total"], item["cost_price"]))
            else:
                con.execute("INSERT INTO purchase_items(invoice_id,product_id,quantity,unit_price,total) VALUES(?,?,?,?,?)",
                            (iid, item["product_id"], item["quantity"], item["unit_price"], item["total"]))
        deletable = old_ids - new_ids
        for old_id in deletable:
            if is_sale:
                con.execute("DELETE FROM sale_items WHERE id=? AND invoice_id=?", (old_id, iid))
            else:
                con.execute("DELETE FROM purchase_items WHERE id=? AND invoice_id=?", (old_id, iid))
        con.commit()
        audit(f"تعديل فاتورة {'بيع' if is_sale else 'توريد'} {inv['invoice_no']} من {old_total:.2f} إلى {total:.2f}", before_snapshot, after_snapshot, "sale_invoice" if is_sale else "purchase_invoice", iid)
        con.close()
        flash(f"تم تعديل الفاتورة {inv['invoice_no']} وإعادة مزامنة المخزون والتقارير", "success")
        return redirect(url_for(view_endpoint, iid=iid))

    party_rows = con.execute(f"SELECT * FROM {party_table} ORDER BY name").fetchall()
    warehouses = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    products = con.execute("SELECT * FROM products WHERE is_active=1 ORDER BY name").fetchall()
    items = con.execute(f"SELECT it.*, p.name AS product_name, p.unit, p.cost_price AS current_cost, p.sale_price, p.wholesale_price FROM {item_table} it JOIN products p ON p.id=it.product_id WHERE it.invoice_id=? ORDER BY it.id", (iid,)).fetchall()
    con.close()
    return render_template("invoice_edit.html", title=f"تعديل فاتورة {inv['invoice_no']}", invoice=inv,
                           kind=invoice_type, parties=party_rows, warehouses=warehouses, products=products,
                           items=items, today=date.today().isoformat())


@app.route("/sales/<int:iid>/edit", methods=["GET", "POST"])
@permission_required("edit_invoices")
def sale_edit(iid):
    return _edit_invoice("sale", iid, "sale_view", "sales")


@app.route("/purchases/<int:iid>/edit", methods=["GET", "POST"])
@permission_required("edit_invoices")
def purchase_edit(iid):
    return _edit_invoice("purchase", iid, "purchase_view", "purchases")


# ---------------------------------------------------------------------------
# Purchases (الواردات) — stock IN
# ---------------------------------------------------------------------------
@app.route("/purchases")
@login_required
def purchases():
    con = db()
    rows = con.execute("""
        SELECT pi.*, s.name AS supplier_name, w.name AS warehouse_name
        FROM purchase_invoices pi
        LEFT JOIN suppliers s ON s.id = pi.supplier_id
        JOIN warehouses w ON w.id = pi.warehouse_id
        ORDER BY pi.id DESC
    """).fetchall()
    con.close()
    return render_template("purchases.html", title="الواردات (فواتير التوريد)", invoices=rows)


@app.route("/purchases/new", methods=["GET", "POST"])
@permission_required("edit_invoices")
def purchase_new():
    con = db()
    if request.method == "POST":
        supplier_id = request.form.get("supplier_id") or None
        warehouse_id = request.form.get("warehouse_id")
        invoice_date = request.form.get("invoice_date") or date.today().isoformat()
        blocked = reject_if_period_closed(invoice_date, "purchase_new")
        if blocked:
            con.close()
            return blocked
        notes = request.form.get("notes", "").strip()
        paid_amount = float(request.form.get("paid_amount") or 0)
        discount_percent = max(0.0, min(100.0, float(request.form.get("discount_percent") or 0)))
        tax_percent = max(0.0, float(request.form.get("tax_percent") or 0))
        product_ids = request.form.getlist("product_id[]")
        quantities = request.form.getlist("quantity[]")
        prices = request.form.getlist("unit_price[]")

        items = []
        subtotal = 0.0
        for pidx, qty, price in zip(product_ids, quantities, prices):
            if not pidx or not qty:
                continue
            qty = float(qty)
            price = float(price or 0)
            if qty <= 0:
                continue
            line_total = qty * price
            items.append((int(pidx), qty, price, line_total))
            subtotal += line_total

        if not warehouse_id or not items:
            flash("يجب اختيار المخزن وإضافة صنف واحد على الأقل", "danger")
            return redirect(url_for("purchase_new"))

        after_discount = subtotal * (1 - discount_percent / 100)
        total = round(after_discount * (1 + tax_percent / 100), 2)
        paid_amount = max(0.0, min(paid_amount, total))

        def _insert_purchase(invoice_no):
            cur = con.execute("""INSERT INTO purchase_invoices(invoice_no,supplier_id,warehouse_id,invoice_date,subtotal,discount_percent,tax_percent,total,paid_amount,notes,created_by,created_at)
                                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (invoice_no, supplier_id, warehouse_id, invoice_date, subtotal, discount_percent,
                                tax_percent, total, paid_amount, notes,
                                session.get("username"), datetime.now().isoformat(timespec="seconds")))
            return cur.lastrowid

        invoice_no, invoice_id = insert_with_unique_invoice_no(con, "PUR", "purchase_invoices", _insert_purchase)
        for product_id, qty, price, line_total in items:
            con.execute("""INSERT INTO purchase_items(invoice_id,product_id,quantity,unit_price,total)
                            VALUES(?,?,?,?,?)""", (invoice_id, product_id, qty, price, line_total))
            update_weighted_average_cost(con, product_id, qty, price)
            adjust_stock(con, product_id, int(warehouse_id), qty, "in", "purchase", invoice_id,
                         f"توريد - فاتورة {invoice_no}")
        if paid_amount > 0:
            payment_cur = con.execute("""INSERT INTO payments(invoice_type,invoice_id,amount,payment_date,method,note,document_no,created_by,created_at)
                            VALUES(?,?,?,?,?,?,?,?,?)""",
                        ("purchase", invoice_id, paid_amount, invoice_date, "نقدي", "دفعة عند إنشاء الفاتورة",
                         next_document_no("PAY-PUR", "payments", con), session.get("username"), datetime.now().isoformat(timespec="seconds")))
            record_payment_treasury(con, payment_cur.lastrowid)
        con.commit()
        audit(f"فاتورة توريد جديدة: {invoice_no}")
        flash(f"تم حفظ فاتورة التوريد {invoice_no} وزيادة المخزون", "success")
        con.close()
        return redirect(url_for("purchases"))

    suppliers_ = con.execute("SELECT * FROM suppliers ORDER BY name").fetchall()
    whs = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    prods = con.execute("SELECT * FROM products WHERE is_active=1 ORDER BY name").fetchall()
    con.close()
    return render_template("purchase_form.html", title="فاتورة توريد جديدة", suppliers=suppliers_,
                            warehouses=whs, products=prods, today=date.today().isoformat())


@app.route("/purchases/<int:iid>")
@login_required
def purchase_view(iid):
    con = db()
    inv = con.execute("""
        SELECT pi.*, s.name AS supplier_name, w.name AS warehouse_name
        FROM purchase_invoices pi
        LEFT JOIN suppliers s ON s.id = pi.supplier_id
        JOIN warehouses w ON w.id = pi.warehouse_id
        WHERE pi.id=?
    """, (iid,)).fetchone()
    items = con.execute("""
        SELECT pit.*, p.name AS product_name, p.unit FROM purchase_items pit
        JOIN products p ON p.id = pit.product_id WHERE pit.invoice_id=?
    """, (iid,)).fetchall()
    payments_ = con.execute("SELECT * FROM payments WHERE invoice_type='purchase' AND invoice_id=? ORDER BY id",
                             (iid,)).fetchall()
    returns_ = con.execute("SELECT * FROM returns WHERE invoice_type='purchase' AND invoice_id=? ORDER BY id DESC", (iid,)).fetchall()
    returned_rows = con.execute("SELECT invoice_item_id, COALESCE(SUM(quantity),0) AS quantity FROM return_items WHERE return_id IN (SELECT id FROM returns WHERE invoice_type='purchase' AND invoice_id=?) GROUP BY invoice_item_id", (iid,)).fetchall()
    returned_quantities = {row["invoice_item_id"]: row["quantity"] for row in returned_rows}
    returns_total = sum(row["amount"] or 0 for row in returns_)
    con.close()
    if not inv:
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("purchases"))
    remaining = max(round(inv["total"] - returns_total - inv["paid_amount"], 2), 0)
    return render_template("invoice_view.html", title=f"فاتورة توريد {inv['invoice_no']}",
                            invoice=inv, items=items, kind="purchase", payments=payments_, remaining=remaining,
                            returns=returns_, returned_quantities=returned_quantities, returns_total=returns_total)


def _create_return(invoice_type, iid, view_endpoint):
    con = db()
    is_sale = invoice_type == "sale"
    invoice_table = "sale_invoices" if is_sale else "purchase_invoices"
    item_table = "sale_items" if is_sale else "purchase_items"
    inv = con.execute(f"SELECT * FROM {invoice_table} WHERE id=?", (iid,)).fetchone()
    if not inv:
        con.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("sales" if is_sale else "purchases"))
    if inv["is_cancelled"]:
        con.close()
        flash("لا يمكن تسجيل مرتجع لفاتورة ملغاة", "danger")
        return redirect(url_for(view_endpoint, iid=iid))

    items = con.execute(f"SELECT it.*, p.name AS product_name, p.unit, p.cost_price AS current_cost FROM {item_table} it JOIN products p ON p.id=it.product_id WHERE it.invoice_id=?", (iid,)).fetchall()
    returned_rows = con.execute("SELECT invoice_item_id, COALESCE(SUM(quantity),0) AS quantity FROM return_items WHERE return_id IN (SELECT id FROM returns WHERE invoice_type=? AND invoice_id=?) GROUP BY invoice_item_id", (invoice_type, iid)).fetchall()
    returned = {row["invoice_item_id"]: row["quantity"] for row in returned_rows}
    errors = []
    selected = []
    for item in items:
        try:
            qty = float(request.form.get(f"return_qty_{item['id']}") or 0)
        except (TypeError, ValueError):
            errors.append(f"كمية مرتجع غير صحيحة للصنف {item['product_name']}")
            continue
        if qty <= 0:
            continue
        already = float(returned.get(item["id"], 0) or 0)
        remaining_qty = float(item["quantity"] or 0) - already
        if qty > remaining_qty + 0.001:
            errors.append(f"كمية مرتجع {item['product_name']} أكبر من المتبقي ({remaining_qty:g})")
            continue
        if not is_sale and qty > get_stock(con, item["product_id"], inv["warehouse_id"]) + 0.001:
            errors.append(f"لا يمكن إرجاع {item['product_name']} لأن الكمية الموجودة بالمخزون غير كافية")
            continue
        unit_cost = float(item["cost_price"] or item["current_cost"] or 0) if is_sale else float(item["unit_price"] or 0)
        selected.append((item, qty, unit_cost))

    if errors or not selected:
        con.close()
        for error in errors or ["يجب إدخال كمية مرتجع واحدة على الأقل"]:
            flash(error, "danger")
        return redirect(url_for(view_endpoint, iid=iid))

    original_subtotal = float(inv["subtotal"] or 0)
    if original_subtotal <= 0:
        original_subtotal = sum(float(item["total"] or 0) for item in items)
    adjustment_factor = float(inv["total"] or 0) / original_subtotal if original_subtotal else 1
    return_base = sum(qty * float(item["unit_price"] or 0) for item, qty, _ in selected)
    return_amount = round(return_base * adjustment_factor, 2)
    return_date = request.form.get("return_date") or date.today().isoformat()
    reason = request.form.get("return_reason", "").strip() or "مرتجع بدون ملاحظة"
    refund_method = request.form.get("refund_method", "خصم من رصيد العميل" if is_sale else "خصم من رصيد المورد").strip()
    allowed_refund_methods = {"خصم من رصيد العميل", "رد نقدي", "تحويل بنكي"}
    if is_sale and refund_method not in allowed_refund_methods:
        refund_method = "خصم من رصيد العميل"
    if not is_sale:
        refund_method = "خصم من رصيد المورد"
    refund_amount = return_amount if is_sale and refund_method in {"رد نقدي", "تحويل بنكي"} else 0.0
    return_document_no = next_document_no("RET-SAL" if is_sale else "RET-PUR", "returns", con)
    cur = con.execute("""INSERT INTO returns(invoice_type, invoice_id, return_date, amount, refund_method, refund_amount, reason, document_no, created_by, created_at)
                         VALUES(?,?,?,?,?,?,?,?,?,?)""",
                      (invoice_type, iid, return_date, return_amount, refund_method, refund_amount, reason, return_document_no, session.get("username"), datetime.now().isoformat(timespec="seconds")))
    return_id = cur.lastrowid
    for item, qty, unit_cost in selected:
        line_total = round(qty * float(item["unit_price"] or 0) * adjustment_factor, 2)
        con.execute("""INSERT INTO return_items(return_id, invoice_item_id, quantity, unit_price, cost_price, total)
                       VALUES(?,?,?,?,?,?)""",
                    (return_id, item["id"], qty, item["unit_price"], unit_cost, line_total))
        if not is_sale:
            remove_weighted_average_cost(con, item["product_id"], qty, item["unit_price"])
        delta = qty if is_sale else -qty
        movement_type = "return_in" if is_sale else "return_out"
        adjust_stock(con, item["product_id"], inv["warehouse_id"], delta, movement_type,
                     "sale_return" if is_sale else "purchase_return", iid,
                     f"مرتجع فاتورة {inv['invoice_no']} - السبب: {reason}")
    if is_sale and refund_amount > 0:
        con.execute("""INSERT INTO treasury(transaction_date, transaction_type, category, amount, description, reference_type, reference_id, affects_profit, created_by, created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    (return_date, "خروج", "رد قيمة مرتجع بيع", refund_amount,
                     f"رد قيمة مرتجع فاتورة {inv['invoice_no']} - الطريقة: {refund_method}",
                     "sale_return", return_id, 0, session.get("username"), datetime.now().isoformat(timespec="seconds")))
    con.commit()
    con.close()
    audit(f"تسجيل مرتجع فاتورة {inv['invoice_no']} - القيمة {return_amount:.2f}")
    flash(f"تم تسجيل المرتجع بقيمة {return_amount:.2f} وتحديث المخزون", "success")
    return redirect(url_for(view_endpoint, iid=iid))


@app.route("/sales/<int:iid>/return", methods=["POST"])
@permission_required("manage_returns")
def sale_return(iid):
    return _create_return("sale", iid, "sale_view")


@app.route("/purchases/<int:iid>/return", methods=["POST"])
@permission_required("manage_returns")
def purchase_return(iid):
    return _create_return("purchase", iid, "purchase_view")


@app.route("/purchases/<int:iid>/cancel", methods=["POST"])
@admin_required
def purchase_cancel(iid):
    con = db()
    inv = con.execute("SELECT * FROM purchase_invoices WHERE id=?", (iid,)).fetchone()
    if not inv:
        con.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("purchases"))
    blocked = reject_if_period_closed(inv["invoice_date"], "purchase_view")
    if blocked:
        con.close()
        return blocked
    if inv["is_cancelled"]:
        con.close()
        flash("الفاتورة ملغاة بالفعل", "info")
        return redirect(url_for("purchase_view", iid=iid))

    reason = request.form.get("reason", "").strip() or "بدون سبب مذكور"
    items = con.execute("SELECT * FROM purchase_items WHERE invoice_id=?", (iid,)).fetchall()

    # Reverse the stock that this invoice had added — same warehouse, opposite direction.
    insufficient = []
    for it in items:
        available = get_stock(con, it["product_id"], inv["warehouse_id"])
        if it["quantity"] > available:
            prod = con.execute("SELECT name FROM products WHERE id=?", (it["product_id"],)).fetchone()
            insufficient.append(prod["name"] if prod else str(it["product_id"]))

    if insufficient:
        con.close()
        flash("لا يمكن إلغاء الفاتورة لأن الكمية التي دخلت منها تم بيعها/تحويلها بالفعل: "
              + "، ".join(insufficient) + ". قم بتسوية المخزون يدويًا أولًا إذا كنت متأكدًا من الإلغاء.", "danger")
        return redirect(url_for("purchase_view", iid=iid))

    for it in items:
        remove_weighted_average_cost(con, it["product_id"], it["quantity"], it["unit_price"])
        adjust_stock(con, it["product_id"], inv["warehouse_id"], -it["quantity"], "adjust", "purchase_cancel", iid,
                     f"إلغاء فاتورة توريد {inv['invoice_no']} - السبب: {reason}")

    cancelled_at = datetime.now().isoformat(timespec="seconds")
    con.execute("""UPDATE purchase_invoices SET is_cancelled=1, cancelled_by=?, cancelled_at=?, cancel_reason=?
                    WHERE id=?""",
                (session.get("username"), cancelled_at, reason, iid))
    record_invoice_cancel_treasury(con, "purchase", iid, inv["invoice_no"], inv["paid_amount"],
                                   cancelled_at, session.get("username"))
    con.commit()
    audit(f"إلغاء فاتورة توريد: {inv['invoice_no']} - السبب: {reason}")
    flash(f"تم إلغاء فاتورة التوريد {inv['invoice_no']} وإرجاع المخزون لوضعه السابق", "success")
    con.close()
    return redirect(url_for("purchase_view", iid=iid))


# ---------------------------------------------------------------------------
# Sales (الصادرات / المبيعات) — stock OUT, deducted automatically
# ---------------------------------------------------------------------------
@app.route("/sales")
@login_required
def sales():
    con = db()
    rows = con.execute("""
        SELECT si.*, c.name AS customer_name, w.name AS warehouse_name
        FROM sale_invoices si
        LEFT JOIN customers c ON c.id = si.customer_id
        JOIN warehouses w ON w.id = si.warehouse_id
        ORDER BY si.id DESC
    """).fetchall()
    con.close()
    return render_template("sales.html", title="الصادرات (فواتير البيع)", invoices=rows)


@app.route("/sales/new", methods=["GET", "POST"])
@permission_required("edit_invoices")
def sale_new():
    con = db()
    if request.method == "POST":
        customer_id = request.form.get("customer_id") or None
        warehouse_id = request.form.get("warehouse_id")
        invoice_date = request.form.get("invoice_date") or date.today().isoformat()
        blocked = reject_if_period_closed(invoice_date, "sale_new")
        if blocked:
            con.close()
            return blocked
        notes = request.form.get("notes", "").strip()
        paid_amount = float(request.form.get("paid_amount") or 0)
        discount_percent = max(0.0, min(100.0, float(request.form.get("discount_percent") or 0)))
        tax_percent = max(0.0, float(request.form.get("tax_percent") or 0))
        product_ids = request.form.getlist("product_id[]")
        quantities = request.form.getlist("quantity[]")
        prices = request.form.getlist("unit_price[]")

        if not warehouse_id:
            flash("يجب اختيار المخزن", "danger")
            return redirect(url_for("sale_new"))

        items = []
        subtotal = 0.0
        errors = []
        for pidx, qty, price in zip(product_ids, quantities, prices):
            if not pidx or not qty:
                continue
            qty = float(qty)
            price = float(price or 0)
            if qty <= 0:
                continue
            prod = con.execute("SELECT name, cost_price FROM products WHERE id=?", (pidx,)).fetchone()
            available = get_stock(con, int(pidx), int(warehouse_id))
            if qty > available:
                errors.append(f"الكمية المطلوبة من «{prod['name'] if prod else pidx}» ({qty}) أكبر من المتاح في المخزن ({available})")
                continue
            line_total = qty * price
            cost_price = float(prod["cost_price"] or 0) if prod else 0.0
            if cost_price > 0 and price < cost_price and session.get("role") != "Admin":
                errors.append(f"لا يمكن بيع «{prod['name'] if prod else pidx}» بأقل من التكلفة ({cost_price:.2f}) إلا بواسطة المدير")
                continue
            items.append((int(pidx), qty, price, line_total, cost_price))
            subtotal += line_total

        if errors:
            for e in errors:
                flash(e, "danger")
            return redirect(url_for("sale_new"))

        if not items:
            flash("يجب إضافة صنف واحد على الأقل بكمية صحيحة", "danger")
            return redirect(url_for("sale_new"))

        after_discount = subtotal * (1 - discount_percent / 100)
        total = round(after_discount * (1 + tax_percent / 100), 2)
        paid_amount = max(0.0, min(paid_amount, total))

        def _insert_sale(invoice_no):
            cur = con.execute("""INSERT INTO sale_invoices(invoice_no,customer_id,warehouse_id,invoice_date,subtotal,discount_percent,tax_percent,total,paid_amount,notes,created_by,created_at)
                                  VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""",
                               (invoice_no, customer_id, warehouse_id, invoice_date, subtotal, discount_percent,
                                tax_percent, total, paid_amount, notes,
                                session.get("username"), datetime.now().isoformat(timespec="seconds")))
            return cur.lastrowid

        invoice_no, invoice_id = insert_with_unique_invoice_no(con, "SAL", "sale_invoices", _insert_sale)
        for product_id, qty, price, line_total, cost_price in items:
            con.execute("""INSERT INTO sale_items(invoice_id,product_id,quantity,unit_price,total,cost_price)
                            VALUES(?,?,?,?,?,?)""", (invoice_id, product_id, qty, price, line_total, cost_price))
            # This is the automatic deduction: quantity sold is subtracted from the entered stock.
            adjust_stock(con, product_id, int(warehouse_id), -qty, "out", "sale", invoice_id,
                         f"بيع - فاتورة {invoice_no}")
        if paid_amount > 0:
            payment_cur = con.execute("""INSERT INTO payments(invoice_type,invoice_id,amount,payment_date,method,note,document_no,created_by,created_at)
                            VALUES(?,?,?,?,?,?,?,?,?)""",
                        ("sale", invoice_id, paid_amount, invoice_date, "نقدي", "دفعة عند إنشاء الفاتورة",
                         next_document_no("PAY-SAL", "payments", con), session.get("username"), datetime.now().isoformat(timespec="seconds")))
            record_payment_treasury(con, payment_cur.lastrowid)
        con.commit()
        audit(f"فاتورة بيع جديدة: {invoice_no}")
        flash(f"تم حفظ فاتورة البيع {invoice_no} وخصم الكمية من المخزون", "success")
        con.close()
        return redirect(url_for("sales"))

    customers_ = con.execute("SELECT * FROM customers ORDER BY name").fetchall()
    whs = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    prods = con.execute("SELECT * FROM products WHERE is_active=1 ORDER BY name").fetchall()
    stock_rows = con.execute("SELECT product_id, warehouse_id, quantity FROM product_stock").fetchall()
    stock_map = {}
    for r in stock_rows:
        stock_map.setdefault(str(r["product_id"]), {})[str(r["warehouse_id"])] = r["quantity"]
    con.close()
    return render_template("sale_form.html", title="فاتورة بيع جديدة", customers=customers_,
                            warehouses=whs, products=prods, today=date.today().isoformat(),
                            stock_map=stock_map)


@app.route("/sales/<int:iid>")
@login_required
def sale_view(iid):
    con = db()
    inv = con.execute("""
        SELECT si.*, c.name AS customer_name, w.name AS warehouse_name
        FROM sale_invoices si
        LEFT JOIN customers c ON c.id = si.customer_id
        JOIN warehouses w ON w.id = si.warehouse_id
        WHERE si.id=?
    """, (iid,)).fetchone()
    items = con.execute("""
        SELECT sit.*, p.name AS product_name, p.unit FROM sale_items sit
        JOIN products p ON p.id = sit.product_id WHERE sit.invoice_id=?
    """, (iid,)).fetchall()
    payments_ = con.execute("SELECT * FROM payments WHERE invoice_type='sale' AND invoice_id=? ORDER BY id",
                             (iid,)).fetchall()
    returns_ = con.execute("SELECT * FROM returns WHERE invoice_type='sale' AND invoice_id=? ORDER BY id DESC", (iid,)).fetchall()
    returned_rows = con.execute("SELECT invoice_item_id, COALESCE(SUM(quantity),0) AS quantity FROM return_items WHERE return_id IN (SELECT id FROM returns WHERE invoice_type='sale' AND invoice_id=?) GROUP BY invoice_item_id", (iid,)).fetchall()
    returned_quantities = {row["invoice_item_id"]: row["quantity"] for row in returned_rows}
    returns_total = sum(row["amount"] or 0 for row in returns_)
    con.close()
    if not inv:
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("sales"))
    remaining = max(round(inv["total"] - returns_total - inv["paid_amount"], 2), 0)
    return render_template("invoice_view.html", title=f"فاتورة بيع {inv['invoice_no']}",
                            invoice=inv, items=items, kind="sale", payments=payments_, remaining=remaining,
                            returns=returns_, returned_quantities=returned_quantities, returns_total=returns_total)


@app.route("/sales/<int:iid>/cancel", methods=["POST"])
@admin_required
def sale_cancel(iid):
    con = db()
    inv = con.execute("SELECT * FROM sale_invoices WHERE id=?", (iid,)).fetchone()
    if not inv:
        con.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("sales"))
    blocked = reject_if_period_closed(inv["invoice_date"], "sale_view")
    if blocked:
        con.close()
        return blocked
    if inv["is_cancelled"]:
        con.close()
        flash("الفاتورة ملغاة بالفعل", "info")
        return redirect(url_for("sale_view", iid=iid))

    reason = request.form.get("reason", "").strip() or "بدون سبب مذكور"
    items = con.execute("SELECT * FROM sale_items WHERE invoice_id=?", (iid,)).fetchall()

    # Reverse the stock that this invoice had deducted — add it back.
    for it in items:
        adjust_stock(con, it["product_id"], inv["warehouse_id"], it["quantity"], "adjust", "sale_cancel", iid,
                     f"إلغاء فاتورة بيع {inv['invoice_no']} - السبب: {reason}")

    cancelled_at = datetime.now().isoformat(timespec="seconds")
    con.execute("""UPDATE sale_invoices SET is_cancelled=1, cancelled_by=?, cancelled_at=?, cancel_reason=?
                    WHERE id=?""",
                (session.get("username"), cancelled_at, reason, iid))
    record_invoice_cancel_treasury(con, "sale", iid, inv["invoice_no"], inv["paid_amount"],
                                   cancelled_at, session.get("username"))
    con.commit()
    audit(f"إلغاء فاتورة بيع: {inv['invoice_no']} - السبب: {reason}")
    flash(f"تم إلغاء فاتورة البيع {inv['invoice_no']} وإرجاع الكمية للمخزون", "success")
    con.close()
    return redirect(url_for("sale_view", iid=iid))


# ---------------------------------------------------------------------------
# Payments — track what customers paid us / what we paid suppliers
# ---------------------------------------------------------------------------
@app.route("/sales/<int:iid>/payment", methods=["POST"])
@permission_required("manage_payments")
def sale_payment(iid):
    con = db()
    inv = con.execute("SELECT * FROM sale_invoices WHERE id=?", (iid,)).fetchone()
    if not inv:
        con.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("sales"))
    if inv["is_cancelled"]:
        con.close()
        flash("لا يمكن تسجيل دفعة على فاتورة ملغاة", "danger")
        return redirect(url_for("sale_view", iid=iid))
    blocked = reject_if_period_closed(date.today().isoformat(), "sale_view")
    if blocked:
        con.close()
        return blocked
    amount = float(request.form.get("amount") or 0)
    method = request.form.get("method", "نقدي").strip()
    note = request.form.get("note", "").strip()
    returns_total = con.execute("SELECT COALESCE(SUM(amount),0) AS total FROM returns WHERE invoice_type='sale' AND invoice_id=?", (iid,)).fetchone()["total"] or 0
    remaining = max(inv["total"] - returns_total - inv["paid_amount"], 0)
    if amount <= 0:
        flash("قيمة الدفعة غير صحيحة", "danger")
    elif amount > remaining + 0.001:
        flash(f"القيمة المدخلة أكبر من المتبقي على العميل ({remaining:.2f})", "danger")
    else:
        payment_cur = con.execute("""INSERT INTO payments(invoice_type,invoice_id,amount,payment_date,method,note,document_no,created_by,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?)""",
                    ("sale", iid, amount, date.today().isoformat(), method, note,
                     next_document_no("PAY-SAL", "payments", con), session.get("username"), datetime.now().isoformat(timespec="seconds")))
        con.execute("UPDATE sale_invoices SET paid_amount = paid_amount + ? WHERE id=?", (amount, iid))
        record_payment_treasury(con, payment_cur.lastrowid)
        con.commit()
        audit(f"تحصيل دفعة من عميل - فاتورة {inv['invoice_no']}")
        flash("تم تسجيل الدفعة", "success")
    con.close()
    return redirect(url_for("sale_view", iid=iid))


@app.route("/purchases/<int:iid>/payment", methods=["POST"])
@permission_required("manage_payments")
def purchase_payment(iid):
    con = db()
    inv = con.execute("SELECT * FROM purchase_invoices WHERE id=?", (iid,)).fetchone()
    if not inv:
        con.close()
        flash("الفاتورة غير موجودة", "danger")
        return redirect(url_for("purchases"))
    if inv["is_cancelled"]:
        con.close()
        flash("لا يمكن تسجيل دفعة على فاتورة ملغاة", "danger")
        return redirect(url_for("purchase_view", iid=iid))
    blocked = reject_if_period_closed(date.today().isoformat(), "purchase_view")
    if blocked:
        con.close()
        return blocked
    amount = float(request.form.get("amount") or 0)
    method = request.form.get("method", "نقدي").strip()
    note = request.form.get("note", "").strip()
    returns_total = con.execute("SELECT COALESCE(SUM(amount),0) AS total FROM returns WHERE invoice_type='purchase' AND invoice_id=?", (iid,)).fetchone()["total"] or 0
    remaining = max(inv["total"] - returns_total - inv["paid_amount"], 0)
    if amount <= 0:
        flash("قيمة الدفعة غير صحيحة", "danger")
    elif amount > remaining + 0.001:
        flash(f"القيمة المدخلة أكبر من المتبقي للمورد ({remaining:.2f})", "danger")
    else:
        payment_cur = con.execute("""INSERT INTO payments(invoice_type,invoice_id,amount,payment_date,method,note,document_no,created_by,created_at)
                        VALUES(?,?,?,?,?,?,?,?,?)""",
                    ("purchase", iid, amount, date.today().isoformat(), method, note,
                     next_document_no("PAY-PUR", "payments", con), session.get("username"), datetime.now().isoformat(timespec="seconds")))
        con.execute("UPDATE purchase_invoices SET paid_amount = paid_amount + ? WHERE id=?", (amount, iid))
        record_payment_treasury(con, payment_cur.lastrowid)
        con.commit()
        audit(f"سداد دفعة لمورد - فاتورة {inv['invoice_no']}")
        flash("تم تسجيل السداد", "success")
    con.close()
    return redirect(url_for("purchase_view", iid=iid))


@app.route("/payments/<int:pid>/receipt")
@login_required
def payment_receipt(pid):
    con = db()
    row = con.execute("""SELECT p.*, CASE WHEN p.invoice_type='sale' THEN si.invoice_no ELSE pi.invoice_no END AS invoice_no,
                       CASE WHEN p.invoice_type='sale' THEN si.invoice_date ELSE pi.invoice_date END AS invoice_date,
                       CASE WHEN p.invoice_type='sale' THEN COALESCE(c.name,'بدون عميل') ELSE COALESCE(s.name,'بدون مورد') END AS party_name
                       FROM payments p LEFT JOIN sale_invoices si ON p.invoice_type='sale' AND si.id=p.invoice_id
                       LEFT JOIN purchase_invoices pi ON p.invoice_type='purchase' AND pi.id=p.invoice_id
                       LEFT JOIN customers c ON c.id=si.customer_id LEFT JOIN suppliers s ON s.id=pi.supplier_id
                       WHERE p.id=?""", (pid,)).fetchone()
    con.close()
    if not row:
        flash("إيصال الدفعة غير موجود", "danger")
        return redirect(url_for("dashboard"))
    return render_template("receipt.html", title=f"إيصال {row['document_no'] or pid}", receipt=row, receipt_kind="دفعة")


@app.route("/returns/<int:rid>/receipt")
@login_required
def return_receipt(rid):
    con = db()
    row = con.execute("""SELECT r.*, CASE WHEN r.invoice_type='sale' THEN si.invoice_no ELSE pi.invoice_no END AS invoice_no,
                       CASE WHEN r.invoice_type='sale' THEN si.invoice_date ELSE pi.invoice_date END AS invoice_date,
                       CASE WHEN r.invoice_type='sale' THEN COALESCE(c.name,'بدون عميل') ELSE COALESCE(s.name,'بدون مورد') END AS party_name
                       FROM returns r LEFT JOIN sale_invoices si ON r.invoice_type='sale' AND si.id=r.invoice_id
                       LEFT JOIN purchase_invoices pi ON r.invoice_type='purchase' AND pi.id=r.invoice_id
                       LEFT JOIN customers c ON c.id=si.customer_id LEFT JOIN suppliers s ON s.id=pi.supplier_id
                       WHERE r.id=?""", (rid,)).fetchone()
    con.close()
    if not row:
        flash("إيصال المرتجع غير موجود", "danger")
        return redirect(url_for("dashboard"))
    return render_template("receipt.html", title=f"إيصال {row['document_no'] or rid}", receipt=row, receipt_kind="مرتجع")


@app.route("/debts")
@login_required
def debts():
    con = db()
    # Customers who still owe us money (sale invoices not fully paid).
    customer_debts = con.execute("""
        SELECT si.id, si.invoice_no, si.invoice_date,
               (si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0)) AS total,
               si.paid_amount,
               (si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0) - si.paid_amount) AS remaining, c.name AS customer_name
        FROM sale_invoices si
        LEFT JOIN customers c ON c.id = si.customer_id
        WHERE (si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0) - si.paid_amount) > 0.001 AND si.is_cancelled = 0
        ORDER BY si.invoice_date DESC
    """).fetchall()
    total_customers_owe = sum(r["remaining"] for r in customer_debts)

    # Suppliers we still owe money to (purchase invoices not fully paid).
    supplier_debts = con.execute("""
        SELECT pi.id, pi.invoice_no, pi.invoice_date,
               (pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0)) AS total,
               pi.paid_amount,
               (pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0) - pi.paid_amount) AS remaining, s.name AS supplier_name
        FROM purchase_invoices pi
        LEFT JOIN suppliers s ON s.id = pi.supplier_id
        WHERE (pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0) - pi.paid_amount) > 0.001 AND pi.is_cancelled = 0
        ORDER BY pi.invoice_date DESC
    """).fetchall()
    total_we_owe = sum(r["remaining"] for r in supplier_debts)

    con.close()
    return render_template("debts.html", title="المديونيات (لنا وعلينا)",
                            customer_debts=customer_debts, supplier_debts=supplier_debts,
                            total_customers_owe=total_customers_owe, total_we_owe=total_we_owe)


# ---------------------------------------------------------------------------
# Global search — products, customers, suppliers
# ---------------------------------------------------------------------------
@app.route("/search")
@login_required
def search():
    q = request.args.get("q", "").strip()
    invoice_no = request.args.get("invoice_no", "").strip()
    party = request.args.get("party", "").strip()
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()
    status = request.args.get("status", "all").strip()
    products_ = customers_ = suppliers_ = invoices_ = []
    con = db()
    if q:
        prefix = f"{q}%"
        contains = f"%{q}%"
        products_ = con.execute("""SELECT p.*, COALESCE((SELECT SUM(quantity) FROM product_stock WHERE product_id=p.id),0) AS total_qty
            FROM products p
            WHERE p.is_active=1 AND (p.name LIKE ? OR p.sku LIKE ? OR p.barcode LIKE ?)
            ORDER BY CASE WHEN p.name LIKE ? THEN 0 ELSE 1 END, p.name
            LIMIT 50""", (prefix, contains, contains, prefix)).fetchall()
        customers_ = con.execute("""SELECT * FROM customers
            WHERE name LIKE ? OR phone LIKE ?
            ORDER BY CASE WHEN name LIKE ? THEN 0 ELSE 1 END, name
            LIMIT 50""", (prefix, contains, prefix)).fetchall()
        suppliers_ = con.execute("""SELECT * FROM suppliers
            WHERE name LIKE ? OR phone LIKE ?
            ORDER BY CASE WHEN name LIKE ? THEN 0 ELSE 1 END, name
            LIMIT 50""", (prefix, contains, prefix)).fetchall()
    if any((invoice_no, party, from_date, to_date)) or status != "all":
        like_no = f"%{invoice_no}%"; like_party = f"%{party}%"
        query = """SELECT 'بيع' AS kind, si.id, si.invoice_no, si.invoice_date, si.total, si.is_cancelled, COALESCE(c.name,'بدون عميل') AS party_name
                   FROM sale_invoices si LEFT JOIN customers c ON c.id=si.customer_id WHERE si.invoice_no LIKE ? AND COALESCE(c.name,'') LIKE ?
                   UNION ALL
                   SELECT 'توريد', pi.id, pi.invoice_no, pi.invoice_date, pi.total, pi.is_cancelled, COALESCE(s.name,'بدون مورد')
                   FROM purchase_invoices pi LEFT JOIN suppliers s ON s.id=pi.supplier_id WHERE pi.invoice_no LIKE ? AND COALESCE(s.name,'') LIKE ?"""
        params = [like_no, like_party, like_no, like_party]
        if from_date or to_date or status != "all":
            # Apply the optional filters to the union in an outer query.
            query = f"SELECT * FROM ({query}) x WHERE 1=1"
            if from_date: query += " AND invoice_date >= ?"; params.append(from_date)
            if to_date: query += " AND invoice_date <= ?"; params.append(to_date)
            if status == "active": query += " AND is_cancelled=0"
            elif status == "cancelled": query += " AND is_cancelled=1"
        query += " ORDER BY invoice_date DESC LIMIT 100"
        invoices_ = con.execute(query, params).fetchall()
    con.close()
    return render_template("search.html", title="نتائج البحث", q=q, invoice_no=invoice_no, party=party,
                            from_date=from_date, to_date=to_date, status=status,
                            products=products_, customers=customers_, suppliers=suppliers_, invoices=invoices_)


# ---------------------------------------------------------------------------
# Stocktake (الجرد) — compare physical count against system quantity
# ---------------------------------------------------------------------------
@app.route("/stocktake")
@login_required
def stocktake_list():
    con = db()
    rows = con.execute("""
        SELECT st.*, w.name AS warehouse_name,
               (SELECT COUNT(*) FROM stocktake_items WHERE stocktake_id=st.id) AS item_count,
               (SELECT COALESCE(SUM(ABS(diff)),0) FROM stocktake_items WHERE stocktake_id=st.id) AS total_diff
        FROM stocktakes st JOIN warehouses w ON w.id = st.warehouse_id
        ORDER BY st.id DESC
    """).fetchall()
    con.close()
    return render_template("stocktake_list.html", title="الجرد", stocktakes=rows)


@app.route("/stocktake/new", methods=["GET", "POST"])
@permission_required("manage_inventory")
def stocktake_new():
    con = db()
    if request.method == "POST":
        warehouse_id = request.form.get("warehouse_id")
        note = request.form.get("note", "").strip()
        product_ids = request.form.getlist("product_id[]")
        counted_list = request.form.getlist("counted_qty[]")

        if not warehouse_id:
            flash("يجب اختيار المخزن", "danger")
            return redirect(url_for("stocktake_new", warehouse_id=warehouse_id))

        cur = con.execute("""INSERT INTO stocktakes(warehouse_id, stocktake_date, note, created_by, created_at)
                              VALUES(?,?,?,?,?)""",
                           (warehouse_id, date.today().isoformat(), note,
                            session.get("username"), datetime.now().isoformat(timespec="seconds")))
        stocktake_id = cur.lastrowid

        applied = 0
        for pid_, counted in zip(product_ids, counted_list):
            if counted == "" or counted is None:
                continue
            counted = float(counted)
            system_qty = get_stock(con, int(pid_), int(warehouse_id))
            diff = counted - system_qty
            con.execute("""INSERT INTO stocktake_items(stocktake_id,product_id,system_qty,counted_qty,diff)
                            VALUES(?,?,?,?,?)""", (stocktake_id, pid_, system_qty, counted, diff))
            if diff != 0:
                adjust_stock(con, int(pid_), int(warehouse_id), diff, "adjust", "stocktake", stocktake_id,
                             f"جرد مخزن بتاريخ {date.today().isoformat()}")
                applied += 1
        con.commit()
        audit(f"جرد مخزن #{warehouse_id} - عدد الفروق المسواة: {applied}")
        flash("تم حفظ الجرد وتسوية الفروق في المخزون تلقائيًا", "success")
        con.close()
        return redirect(url_for("stocktake_view", sid=stocktake_id))

    warehouse_id = request.args.get("warehouse_id", "")
    whs = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    stock_rows = []
    if warehouse_id:
        stock_rows = con.execute("""
            SELECT p.id AS product_id, p.name, p.unit,
                   COALESCE(ps.quantity, 0) AS quantity
            FROM products p
            LEFT JOIN product_stock ps ON ps.product_id = p.id AND ps.warehouse_id = ?
            WHERE p.is_active = 1
            ORDER BY p.name
        """, (warehouse_id,)).fetchall()
    con.close()
    return render_template("stocktake_new.html", title="جرد مخزن جديد", warehouses=whs,
                            selected_warehouse=warehouse_id, stock_rows=stock_rows)


@app.route("/stocktake/<int:sid>")
@login_required
def stocktake_view(sid):
    con = db()
    st = con.execute("""
        SELECT st.*, w.name AS warehouse_name FROM stocktakes st
        JOIN warehouses w ON w.id = st.warehouse_id WHERE st.id=?
    """, (sid,)).fetchone()
    items = con.execute("""
        SELECT sti.*, p.name AS product_name, p.unit FROM stocktake_items sti
        JOIN products p ON p.id = sti.product_id WHERE sti.stocktake_id=? ORDER BY p.name
    """, (sid,)).fetchall()
    con.close()
    if not st:
        flash("سجل الجرد غير موجود", "danger")
        return redirect(url_for("stocktake_list"))
    return render_template("stocktake_view.html", title=f"جرد #{sid}", st=st, items=items)


# ---------------------------------------------------------------------------
# API helper: get product info for invoice forms (price + stock per warehouse)
# ---------------------------------------------------------------------------
@app.route("/api/product/<int:pid>")
@login_required
def api_product(pid):
    con = db()
    p = con.execute("SELECT * FROM products WHERE id=?", (pid,)).fetchone()
    if not p:
        con.close()
        return jsonify({"error": "not found"}), 404
    stocks = con.execute("SELECT warehouse_id, quantity FROM product_stock WHERE product_id=?", (pid,)).fetchall()
    con.close()
    return jsonify({
        "id": p["id"], "name": p["name"], "unit": p["unit"],
        "sale_price": p["sale_price"], "cost_price": p["cost_price"],
        "stock": {str(r["warehouse_id"]): r["quantity"] for r in stocks}
    })


@app.route("/api/product-by-barcode/<barcode>")
@login_required
def api_product_by_barcode(barcode):
    con = db()
    p = con.execute("SELECT * FROM products WHERE barcode=? AND is_active=1", (barcode,)).fetchone()
    con.close()
    if not p:
        return jsonify({"error": "not found"}), 404
    return jsonify({"id": p["id"], "name": p["name"]})


# ---------------------------------------------------------------------------
# Stock movements log & manual adjustment
# ---------------------------------------------------------------------------
@app.route("/movements")
@login_required
def movements():
    con = db()
    page = max(1, int(request.args.get("page", 1) or 1))
    per_page = 100
    total_count = con.execute("SELECT COUNT(*) c FROM stock_movements").fetchone()["c"]
    total_pages = max(1, (total_count + per_page - 1) // per_page)
    page = min(page, total_pages)
    rows = con.execute("""
        SELECT sm.*, p.name AS product_name, w.name AS warehouse_name
        FROM stock_movements sm
        JOIN products p ON p.id = sm.product_id
        JOIN warehouses w ON w.id = sm.warehouse_id
        ORDER BY sm.id DESC LIMIT ? OFFSET ?
    """, (per_page, (page - 1) * per_page)).fetchall()
    con.close()
    return render_template("movements.html", title="سجل حركة المخزون", movements=rows,
                            page=page, total_pages=total_pages, total_count=total_count)


@app.route("/stock/adjust", methods=["GET", "POST"])
@permission_required("manage_inventory")
def stock_adjust():
    con = db()
    if request.method == "POST":
        product_id = int(request.form.get("product_id"))
        warehouse_id = int(request.form.get("warehouse_id"))
        new_qty = float(request.form.get("new_qty") or 0)
        note = request.form.get("note", "").strip() or "تسوية يدوية للمخزون"
        product = con.execute("SELECT id, name FROM products WHERE id=? AND is_active=1", (product_id,)).fetchone()
        warehouse = con.execute("SELECT id FROM warehouses WHERE id=?", (warehouse_id,)).fetchone()
        stock_row = con.execute("SELECT id FROM product_stock WHERE product_id=? AND warehouse_id=?", (product_id, warehouse_id)).fetchone()
        if not product or not warehouse:
            con.close(); flash("المنتج أو المخزن غير موجود", "danger"); return redirect(url_for("stock_adjust"))
        if not stock_row:
            con.close(); flash(f"لا يوجد رصيد مسجل للصنف «{product['name']}» في المخزن المحدد. استخدم فاتورة توريد أو تحويل أولاً.", "danger"); return redirect(url_for("stock_adjust"))
        if new_qty < 0:
            con.close(); flash("لا يمكن أن تكون الكمية الجديدة سالبة", "danger"); return redirect(url_for("stock_adjust"))
        current = get_stock(con, product_id, warehouse_id)
        delta = new_qty - current
        if delta != 0:
            adjust_stock(con, product_id, warehouse_id, delta, "adjust", "manual", None, note)
            con.commit()
            audit(f"تسوية مخزون يدوية - صنف #{product_id}")
            flash("تم تحديث رصيد المخزون", "success")
        else:
            flash("لا يوجد تغيير في الكمية", "info")
        con.close()
        return redirect(url_for("stock_adjust"))

    whs = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    prods = con.execute("SELECT * FROM products WHERE is_active=1 ORDER BY name").fetchall()
    stock_rows = con.execute("""
        SELECT ps.*, p.name AS product_name, p.unit, w.name AS warehouse_name
        FROM product_stock ps
        JOIN products p ON p.id = ps.product_id
        JOIN warehouses w ON w.id = ps.warehouse_id
        ORDER BY p.name
    """).fetchall()
    con.close()
    return render_template("stock_adjust.html", title="تسوية المخزون", warehouses=whs, products=prods, stock_rows=stock_rows)


@app.route("/stock/transfer", methods=["GET", "POST"])
@permission_required("manage_inventory")
def stock_transfer():
    con = db()
    if request.method == "POST":
        product_id = int(request.form.get("product_id"))
        from_wh = int(request.form.get("from_warehouse"))
        to_wh = int(request.form.get("to_warehouse"))
        qty = float(request.form.get("quantity") or 0)
        note = request.form.get("note", "").strip()

        if from_wh == to_wh:
            flash("لا يمكن التحويل لنفس المخزن", "danger")
        elif qty <= 0:
            flash("الكمية غير صحيحة", "danger")
        else:
            available = get_stock(con, product_id, from_wh)
            if qty > available:
                flash(f"الكمية المتاحة في المخزن المصدر هي {available} فقط", "danger")
            else:
                adjust_stock(con, product_id, from_wh, -qty, "transfer_out", "transfer", None, note or "تحويل بين المخازن")
                adjust_stock(con, product_id, to_wh, qty, "transfer_in", "transfer", None, note or "تحويل بين المخازن")
                con.commit()
                audit(f"تحويل مخزون - صنف #{product_id}")
                flash("تم تحويل الكمية بنجاح", "success")
        con.close()
        return redirect(url_for("stock_transfer"))

    whs = con.execute("SELECT * FROM warehouses ORDER BY name").fetchall()
    prods = con.execute("SELECT * FROM products WHERE is_active=1 ORDER BY name").fetchall()
    con.close()
    return render_template("stock_transfer.html", title="تحويل بين المخازن", warehouses=whs, products=prods)


# ---------------------------------------------------------------------------
# Reports
# ---------------------------------------------------------------------------
@app.route("/reports")
@login_required
def reports():
    con = db()
    from_date = request.args.get("from_date", "").strip()
    to_date = request.args.get("to_date", "").strip()
    try:
        stale_days = max(1, int(request.args.get("stale_days", "60")))
    except ValueError:
        stale_days = 60

    stock_report = con.execute("""
        SELECT p.name, p.sku, p.unit, w.name AS warehouse, ps.quantity, p.min_stock,
               (ps.quantity * p.cost_price) AS value
        FROM product_stock ps JOIN products p ON p.id = ps.product_id JOIN warehouses w ON w.id = ps.warehouse_id
        WHERE p.is_active = 1 ORDER BY p.name
    """).fetchall()
    sale_filter = " AND inv.invoice_date >= ?" if from_date else ""
    sale_filter += " AND inv.invoice_date <= ?" if to_date else ""
    purchase_filter = " AND pi.invoice_date >= ?" if from_date else ""
    purchase_filter += " AND pi.invoice_date <= ?" if to_date else ""
    sale_params = ([from_date] if from_date else []) + ([to_date] if to_date else [])
    purchase_params = ([from_date] if from_date else []) + ([to_date] if to_date else [])

    top_products = con.execute(f"""
        SELECT p.name, SUM(si.quantity) AS qty, SUM(si.total) AS total
        FROM sale_items si JOIN products p ON p.id = si.product_id
        JOIN sale_invoices inv ON inv.id = si.invoice_id AND inv.is_cancelled = 0
        WHERE 1=1 {sale_filter} GROUP BY si.product_id ORDER BY total DESC LIMIT 10
    """, sale_params).fetchall()
    top_suppliers = con.execute(f"""
        SELECT COALESCE(s.name,'بدون مورد'), COUNT(pi.id) AS invoice_count, SUM(pi.total) AS total
        FROM purchase_invoices pi LEFT JOIN suppliers s ON s.id = pi.supplier_id
        WHERE pi.is_cancelled = 0 {purchase_filter} GROUP BY pi.supplier_id ORDER BY total DESC LIMIT 10
    """, purchase_params).fetchall()
    top_customers = con.execute(f"""
        SELECT COALESCE(c.name,'بدون عميل'), COUNT(inv.id) AS invoice_count, SUM(inv.total) AS total
        FROM sale_invoices inv LEFT JOIN customers c ON c.id = inv.customer_id
        WHERE inv.is_cancelled = 0 {sale_filter} GROUP BY inv.customer_id ORDER BY total DESC LIMIT 10
    """, sale_params).fetchall()

    debt_rows = con.execute("""
        SELECT 'عميل' AS debt_type, si.invoice_no, si.invoice_date, COALESCE(c.name,'بدون عميل') AS party_name,
               (si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id),0) - si.paid_amount) AS remaining
        FROM sale_invoices si LEFT JOIN customers c ON c.id=si.customer_id WHERE si.is_cancelled=0
        UNION ALL
        SELECT 'مورد', pi.invoice_no, pi.invoice_date, COALESCE(s.name,'بدون مورد'),
               (pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id),0) - pi.paid_amount)
        FROM purchase_invoices pi LEFT JOIN suppliers s ON s.id=pi.supplier_id WHERE pi.is_cancelled=0
    """).fetchall()
    aging = {"حديثة (0-30)": 0.0, "31-60 يوماً": 0.0, "61-90 يوماً": 0.0, "أكثر من 90 يوماً": 0.0}
    aging_rows = []
    today = date.today()
    for row in debt_rows:
        remaining = max(float(row["remaining"] or 0), 0)
        if remaining <= 0.001:
            continue
        try:
            age = max((today - date.fromisoformat(row["invoice_date"])).days, 0)
        except (TypeError, ValueError):
            age = 0
        bucket = "حديثة (0-30)" if age <= 30 else "31-60 يوماً" if age <= 60 else "61-90 يوماً" if age <= 90 else "أكثر من 90 يوماً"
        aging[bucket] += remaining
        aging_rows.append({"debt_type": row["debt_type"], "invoice_no": row["invoice_no"], "invoice_date": row["invoice_date"], "party_name": row["party_name"], "remaining": remaining, "age": age, "bucket": bucket})
    aging_summary = [{"bucket": k, "total": v} for k, v in aging.items()]
    aging_rows.sort(key=lambda x: x["age"], reverse=True)

    treasury_query = "SELECT transaction_type, category, amount, transaction_date, description FROM treasury WHERE 1=1"
    treasury_params = []
    if from_date: treasury_query += " AND transaction_date >= ?"; treasury_params.append(from_date)
    if to_date: treasury_query += " AND transaction_date <= ?"; treasury_params.append(to_date)
    treasury_rows = con.execute(treasury_query + " ORDER BY transaction_date DESC, id DESC", treasury_params).fetchall()
    def _treasury_total(transaction_type, reference_types=None, manual=False):
        query = "SELECT COALESCE(SUM(amount),0) AS total FROM treasury WHERE transaction_type=?"
        params = [transaction_type]
        if from_date:
            query += " AND transaction_date >= ?"; params.append(from_date)
        if to_date:
            query += " AND transaction_date <= ?"; params.append(to_date)
        if manual:
            query += " AND (reference_type IS NULL OR reference_type='')"
        elif reference_types:
            placeholders = ",".join("?" for _ in reference_types)
            query += f" AND reference_type IN ({placeholders})"; params.extend(reference_types)
        return float(con.execute(query, params).fetchone()["total"] or 0)

    collections = _treasury_total("دخول", ["sale_payment"])
    supplier_paid = _treasury_total("خروج", ["purchase_payment"])
    sale_cash_reversals = _treasury_total("خروج", ["sale_return", "sale_cancel"])
    purchase_cash_reversals = _treasury_total("دخول", ["purchase_cancel"])
    manual_in = _treasury_total("دخول", manual=True)
    manual_out = _treasury_total("خروج", manual=True)
    treasury_in = sum(float(r["amount"] or 0) for r in treasury_rows if r["transaction_type"] == "دخول")
    treasury_out = sum(float(r["amount"] or 0) for r in treasury_rows if r["transaction_type"] == "خروج")
    cash_flow_summary = [
        {"label": "تحصيلات العملاء", "inflow": collections, "outflow": 0},
        {"label": "سداد الموردين", "inflow": 0, "outflow": supplier_paid},
        {"label": "مرتجعات وعكس مبيعات", "inflow": 0, "outflow": sale_cash_reversals},
        {"label": "عكس سداد مشتريات", "inflow": purchase_cash_reversals, "outflow": 0},
        {"label": "حركات الخزانة اليدوية", "inflow": manual_in, "outflow": manual_out},
    ]
    cash_in_total = treasury_in
    cash_out_total = treasury_out

    stagnant_rows = con.execute("""
        SELECT p.name, p.sku, p.unit,
               COALESCE((SELECT SUM(ps.quantity) FROM product_stock ps WHERE ps.product_id=p.id),0) AS quantity,
               p.cost_price,
               MAX(CASE WHEN si.id IS NOT NULL AND inv.is_cancelled=0 THEN inv.invoice_date END) AS last_sale_date,
               COALESCE(SUM(CASE WHEN si.id IS NOT NULL AND inv.is_cancelled=0 THEN si.quantity ELSE 0 END),0) AS sold_qty
        FROM products p LEFT JOIN sale_items si ON si.product_id=p.id LEFT JOIN sale_invoices inv ON inv.id=si.invoice_id
        WHERE p.is_active=1 GROUP BY p.id HAVING quantity > 0
    """).fetchall()
    stagnant = []
    for row in stagnant_rows:
        try:
            days = (today - date.fromisoformat(row["last_sale_date"])).days if row["last_sale_date"] else 9999
        except (TypeError, ValueError):
            days = 9999
        if days >= stale_days:
            stagnant.append({"name": row["name"], "sku": row["sku"], "unit": row["unit"], "quantity": row["quantity"], "cost_price": row["cost_price"], "last_sale_date": row["last_sale_date"] or "لم يُبع", "days": days})
    stagnant.sort(key=lambda x: x["days"], reverse=True)

    underpriced = con.execute(f"""
        SELECT inv.invoice_no, inv.invoice_date, p.name, si.quantity, si.unit_price, si.cost_price,
               (si.unit_price - si.cost_price) * si.quantity AS loss
        FROM sale_items si JOIN sale_invoices inv ON inv.id=si.invoice_id JOIN products p ON p.id=si.product_id
        WHERE inv.is_cancelled=0 AND si.unit_price < si.cost_price {sale_filter}
        ORDER BY inv.invoice_date DESC LIMIT 30
    """, sale_params).fetchall()
    product_profitability = con.execute(f"""
        SELECT p.name, SUM(si.quantity) AS qty, SUM(si.total) AS sales,
               SUM(si.quantity * COALESCE(si.cost_price,0)) AS cost,
               SUM(si.total - si.quantity * COALESCE(si.cost_price,0)) AS profit
        FROM sale_items si JOIN products p ON p.id=si.product_id JOIN sale_invoices inv ON inv.id=si.invoice_id
        WHERE inv.is_cancelled=0 {sale_filter} GROUP BY si.product_id ORDER BY profit DESC
    """, sale_params).fetchall()
    customer_profitability = con.execute(f"""
        SELECT COALESCE(c.name,'بدون عميل') AS name, COUNT(DISTINCT inv.id) AS invoices,
               SUM(si.total) AS sales, SUM(si.quantity * COALESCE(si.cost_price,0)) AS cost,
               SUM(si.total - si.quantity * COALESCE(si.cost_price,0)) AS profit
        FROM sale_items si JOIN sale_invoices inv ON inv.id=si.invoice_id LEFT JOIN customers c ON c.id=inv.customer_id
        WHERE inv.is_cancelled=0 {sale_filter} GROUP BY inv.customer_id ORDER BY profit DESC
    """, sale_params).fetchall()
    con.close()
    return render_template("reports.html", title="التقارير", stock_report=stock_report, top_products=top_products,
                            product_profitability=product_profitability, customer_profitability=customer_profitability,
                            top_suppliers=top_suppliers, top_customers=top_customers, from_date=from_date, to_date=to_date,
                            stale_days=stale_days, aging_summary=aging_summary, aging_rows=aging_rows[:100],
                            cash_flow_summary=cash_flow_summary, cash_in_total=cash_in_total, cash_out_total=cash_out_total,
                            stagnant=stagnant[:100], underpriced=underpriced)


@app.route("/reports/cash-flow.csv")
@login_required
def report_cash_flow_csv():
    from_date, to_date = request.args.get("from_date", "").strip(), request.args.get("to_date", "").strip()
    con = db(); rows = []
    q = "SELECT transaction_date, transaction_type, category, amount, description, reference_type FROM treasury WHERE 1=1"; params = []
    if from_date: q += " AND transaction_date >= ?"; params.append(from_date)
    if to_date: q += " AND transaction_date <= ?"; params.append(to_date)
    for r in con.execute(q + " ORDER BY transaction_date, id", params).fetchall():
        source = "دفعة فاتورة" if (r["reference_type"] or "").endswith("_payment") else "الخزانة"
        rows.append([r["transaction_date"], source, r["transaction_type"], r["category"], r["amount"], r["description"]])
    con.close(); buf = io.StringIO(); writer = csv.writer(buf); writer.writerow(["التاريخ","المصدر","النوع","الفئة/الطريقة","القيمة","الوصف"]); writer.writerows(rows)
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=cash_flow_report.csv"})


@app.route("/reports/debts-aging.csv")
@login_required
def report_debts_aging_csv():
    con = db(); rows = con.execute("""
        SELECT 'عميل' AS debt_type, si.invoice_no, si.invoice_date, COALESCE(c.name,'بدون عميل') AS party_name,
               (si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id),0) - si.paid_amount) AS remaining
        FROM sale_invoices si LEFT JOIN customers c ON c.id=si.customer_id WHERE si.is_cancelled=0
        UNION ALL SELECT 'مورد', pi.invoice_no, pi.invoice_date, COALESCE(s.name,'بدون مورد'),
               (pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id),0) - pi.paid_amount)
        FROM purchase_invoices pi LEFT JOIN suppliers s ON s.id=pi.supplier_id WHERE pi.is_cancelled=0
        ORDER BY invoice_date
    """).fetchall(); con.close(); buf = io.StringIO(); writer = csv.writer(buf); writer.writerow(["النوع","الفاتورة","التاريخ","الطرف","المتبقي","العمر بالأيام"])
    today = date.today()
    for r in rows:
        remaining = max(float(r["remaining"] or 0), 0)
        if remaining <= 0.001: continue
        try: age = max((today - date.fromisoformat(r["invoice_date"])).days, 0)
        except (TypeError, ValueError): age = 0
        writer.writerow([r["debt_type"], r["invoice_no"], r["invoice_date"], r["party_name"], remaining, age])
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=debts_aging_report.csv"})


@app.route("/reports/stagnant.csv")
@login_required
def report_stagnant_csv():
    try: stale_days = max(1, int(request.args.get("stale_days", "60")))
    except ValueError: stale_days = 60
    con = db(); rows = con.execute("""
        SELECT p.name, p.sku, p.unit, COALESCE((SELECT SUM(ps.quantity) FROM product_stock ps WHERE ps.product_id=p.id),0) AS quantity,
               p.cost_price, MAX(CASE WHEN inv.is_cancelled=0 THEN inv.invoice_date END) AS last_sale_date
        FROM products p LEFT JOIN sale_items si ON si.product_id=p.id LEFT JOIN sale_invoices inv ON inv.id=si.invoice_id
        WHERE p.is_active=1 GROUP BY p.id HAVING quantity > 0
    """).fetchall(); con.close(); buf = io.StringIO(); writer = csv.writer(buf); writer.writerow(["الصنف","الكود","الوحدة","المخزون","سعر التكلفة","آخر بيع","أيام دون بيع"]); today = date.today()
    for r in rows:
        try: days = (today - date.fromisoformat(r["last_sale_date"])).days if r["last_sale_date"] else 9999
        except (TypeError, ValueError): days = 9999
        if days >= stale_days: writer.writerow([r["name"], r["sku"], r["unit"], r["quantity"], r["cost_price"], r["last_sale_date"] or "لم يُبع", days])
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=stagnant_stock_report.csv"})


@app.route("/reports/underpriced.csv")
@login_required
def report_underpriced_csv():
    con = db(); rows = con.execute("""
        SELECT inv.invoice_no, inv.invoice_date, p.name, si.quantity, si.unit_price, si.cost_price,
               (si.unit_price-si.cost_price)*si.quantity AS loss
        FROM sale_items si JOIN sale_invoices inv ON inv.id=si.invoice_id JOIN products p ON p.id=si.product_id
        WHERE inv.is_cancelled=0 AND si.unit_price < si.cost_price ORDER BY inv.invoice_date DESC
    """).fetchall(); con.close(); buf = io.StringIO(); writer = csv.writer(buf); writer.writerow(["الفاتورة","التاريخ","الصنف","الكمية","سعر البيع","التكلفة","الأثر"]); writer.writerows([[r["invoice_no"],r["invoice_date"],r["name"],r["quantity"],r["unit_price"],r["cost_price"],r["loss"]] for r in rows])
    return Response(buf.getvalue().encode("utf-8-sig"), mimetype="text/csv", headers={"Content-Disposition":"attachment;filename=underpriced_sales_report.csv"})


@app.route("/reports/profitability.xlsx")
@login_required
def report_profitability_xlsx():
    from openpyxl import Workbook
    from openpyxl.styles import Font, PatternFill, Alignment
    from openpyxl.utils import get_column_letter
    from_date, to_date = request.args.get("from_date", "").strip(), request.args.get("to_date", "").strip()
    filters = ""; params = []
    if from_date: filters += " AND inv.invoice_date >= ?"; params.append(from_date)
    if to_date: filters += " AND inv.invoice_date <= ?"; params.append(to_date)
    con = db()
    products = con.execute(f"""SELECT p.name, SUM(si.quantity) qty, SUM(si.total) sales, SUM(si.quantity*COALESCE(si.cost_price,0)) cost, SUM(si.total-si.quantity*COALESCE(si.cost_price,0)) profit
                               FROM sale_items si JOIN products p ON p.id=si.product_id JOIN sale_invoices inv ON inv.id=si.invoice_id
                               WHERE inv.is_cancelled=0 {filters} GROUP BY si.product_id ORDER BY profit DESC""", params).fetchall()
    customers = con.execute(f"""SELECT COALESCE(c.name,'بدون عميل') name, COUNT(DISTINCT inv.id) invoices, SUM(si.total) sales, SUM(si.quantity*COALESCE(si.cost_price,0)) cost, SUM(si.total-si.quantity*COALESCE(si.cost_price,0)) profit
                                FROM sale_items si JOIN sale_invoices inv ON inv.id=si.invoice_id LEFT JOIN customers c ON c.id=inv.customer_id
                                WHERE inv.is_cancelled=0 {filters} GROUP BY inv.customer_id ORDER BY profit DESC""", params).fetchall()
    con.close()
    wb = Workbook(); ws = wb.active; ws.title = "ربحية الأصناف"; headers = ["الصنف","الكمية","المبيعات","التكلفة","الربح"]
    ws.append(headers)
    for r in products: ws.append([r["name"], r["qty"], r["sales"], r["cost"], r["profit"]])
    wc = wb.create_sheet("ربحية العملاء"); wc.append(["العميل","الفواتير","المبيعات","التكلفة","الربح"])
    for r in customers: wc.append([r["name"], r["invoices"], r["sales"], r["cost"], r["profit"]])
    for sheet in wb.worksheets:
        sheet.freeze_panes = "A2"
        for cell in sheet[1]: cell.font = Font(bold=True, color="FFFFFF"); cell.fill = PatternFill("solid", fgColor="1D4ED8"); cell.alignment = Alignment(horizontal="center")
        for col in range(2, 6):
            for row in range(2, sheet.max_row + 1): sheet.cell(row, col).number_format = '#,##0.00'
        for col in range(1, sheet.max_column + 1): sheet.column_dimensions[get_column_letter(col)].width = 18
    output = io.BytesIO(); wb.save(output); output.seek(0)
    return send_file(output, as_attachment=True, download_name="profitability_report.xlsx", mimetype="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")


@app.route("/reports/stock.csv")
@login_required
def report_stock_csv():
    con = db()
    rows = con.execute("""
        SELECT p.sku, p.name, w.name AS warehouse, ps.quantity, p.unit, p.sale_price, p.cost_price
        FROM product_stock ps
        JOIN products p ON p.id = ps.product_id
        JOIN warehouses w ON w.id = ps.warehouse_id
        WHERE p.is_active = 1 ORDER BY p.name
    """).fetchall()
    con.close()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["SKU", "الصنف", "المخزن", "الكمية", "الوحدة", "سعر البيع", "سعر التكلفة"])
    for r in rows:
        writer.writerow([r["sku"], r["name"], r["warehouse"], r["quantity"], r["unit"], r["sale_price"], r["cost_price"]])
    output = buf.getvalue().encode("utf-8-sig")
    return Response(output, mimetype="text/csv",
                     headers={"Content-Disposition": "attachment;filename=stock_report.csv"})


# ---------------------------------------------------------------------------
# Users management (Admin only)
# ---------------------------------------------------------------------------
@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    con = db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        full_name = request.form.get("full_name", "").strip()
        role = request.form.get("role", "Employee")
        allowed_permissions = set(PERMISSION_LABELS)
        permissions = sorted(allowed_permissions.intersection(set(request.form.getlist("permissions[]"))))
        permissions_text = ",".join(permissions)
        if role == "Admin":
            permissions_text = ",".join(sorted(allowed_permissions))
        if username and password:
            try:
                con.execute("""INSERT INTO users(username,password,full_name,role,permissions,must_change_password)
                                VALUES(?,?,?,?,?,1)""",
                            (username, generate_password_hash(password), full_name, role, permissions_text))
                con.commit()
                audit(f"إضافة مستخدم: {username}")
                flash("تم إضافة المستخدم", "success")
            except sqlite3.IntegrityError:
                flash("اسم المستخدم موجود بالفعل", "danger")
        return redirect(url_for("users"))
    rows = con.execute("SELECT * FROM users ORDER BY id").fetchall()
    con.close()
    return render_template("users.html", title="المستخدمون", users=rows, permission_labels=PERMISSION_LABELS)


@app.route("/users/<int:uid>/permissions", methods=["POST"])
@admin_required
def user_permissions(uid):
    con = db()
    row = con.execute("SELECT role FROM users WHERE id=?", (uid,)).fetchone()
    if not row:
        con.close(); flash("المستخدم غير موجود", "danger"); return redirect(url_for("users"))
    permissions = sorted(set(PERMISSION_LABELS).intersection(set(request.form.getlist("permissions[]"))))
    if row["role"] == "Admin":
        permissions = sorted(PERMISSION_LABELS)
    con.execute("UPDATE users SET permissions=? WHERE id=?", (",".join(permissions), uid))
    con.commit(); con.close()
    audit(f"تحديث صلاحيات المستخدم #{uid}", document_type="user", document_id=uid)
    flash("تم تحديث الصلاحيات", "success")
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/toggle", methods=["POST"])
@admin_required
def user_toggle(uid):
    con = db()
    if uid == session.get("user_id"):
        flash("لا يمكنك تعطيل حسابك الحالي", "danger")
    else:
        row = con.execute("SELECT is_active FROM users WHERE id=?", (uid,)).fetchone()
        if row:
            con.execute("UPDATE users SET is_active=? WHERE id=?", (0 if row["is_active"] else 1, uid))
            con.commit()
            flash("تم تحديث حالة المستخدم", "success")
    con.close()
    return redirect(url_for("users"))


@app.route("/users/<int:uid>/delete", methods=["POST"])
@admin_required
def user_delete(uid):
    if uid == session.get("user_id"):
        flash("لا يمكنك حذف حسابك الحالي", "danger")
        return redirect(url_for("users"))
    con = db()
    con.execute("DELETE FROM users WHERE id=?", (uid,))
    con.commit()
    con.close()
    flash("تم حذف المستخدم", "success")
    return redirect(url_for("users"))


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------
@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    con = db()
    if request.method == "POST":
        company_name = request.form.get("company_name", "").strip() or APP_NAME
        currency = request.form.get("currency", "").strip() or "ج.م"
        closed_period_until = request.form.get("closed_period_until", "").strip()
        if closed_period_until:
            try:
                date.fromisoformat(closed_period_until)
            except ValueError:
                con.close()
                flash("تاريخ إغلاق الفترة غير صحيح", "danger")
                return redirect(url_for("settings"))
        con.execute("UPDATE settings SET value=? WHERE key='company_name'", (company_name,))
        con.execute("UPDATE settings SET value=? WHERE key='currency'", (currency,))
        con.execute("UPDATE settings SET value=? WHERE key='closed_period_until'", (closed_period_until,))
        con.commit()
        audit(f"تحديث إعدادات النظام - إغلاق الفترة حتى {closed_period_until or 'بدون إغلاق'}")
        flash("تم حفظ الإعدادات", "success")
        con.close()
        return redirect(url_for("settings"))
    company_name = get_setting("company_name", APP_NAME)
    currency = get_setting("currency", "ج.م")
    closed_period_until = get_setting("closed_period_until", "")
    con.close()
    return render_template("settings.html", title="الإعدادات", company_name=company_name, currency=currency,
                           closed_period_until=closed_period_until)


# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------
@app.route("/audit")
@admin_required
def audit_page():
    con = db()
    rows = con.execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 300").fetchall()
    con.close()
    return render_template("audit.html", title="سجل العمليات", logs=rows)


# ---------------------------------------------------------------------------
# Backup
# ---------------------------------------------------------------------------
@app.route("/backup")
@admin_required
def backup():
    return send_file(str(DB), as_attachment=True, download_name=f"almasrya_backup_{date.today().isoformat()}.db")


BACKUP_DIR = BASE_DIR / "backups"
BACKUP_KEEP_DAYS = 30


def run_auto_backup():
    """Take one backup per calendar day automatically, and prune old ones.
    Called once at app startup — cheap enough not to need a scheduler."""
    try:
        if not DB.exists():
            return
        BACKUP_DIR.mkdir(exist_ok=True)
        today_str = date.today().isoformat()
        target = BACKUP_DIR / f"almasrya_auto_{today_str}.db"
        if not target.exists():
            import shutil
            shutil.copy2(str(DB), str(target))
        cutoff = datetime.now().timestamp() - (BACKUP_KEEP_DAYS * 86400)
        for f in BACKUP_DIR.glob("almasrya_auto_*.db"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
            except Exception:
                pass
    except Exception:
        pass  # Backup failures must never block the app from starting.


@app.route("/backups")
@admin_required
def backups_list():
    files = []
    if BACKUP_DIR.exists():
        for f in sorted(BACKUP_DIR.glob("almasrya_auto_*.db"), reverse=True):
            files.append({
                "name": f.name,
                "size_kb": round(f.stat().st_size / 1024, 1),
                "date": datetime.fromtimestamp(f.stat().st_mtime).strftime("%Y-%m-%d %H:%M"),
            })
    return render_template("backups.html", title="النسخ الاحتياطية", files=files, keep_days=BACKUP_KEEP_DAYS)


@app.route("/backups/restore", methods=["POST"])
@admin_required
def backup_restore():
    """Restore a validated SQLite backup after preserving the current database."""
    upload = request.files.get("backup_file")
    if not upload or not upload.filename:
        flash("اختر ملف قاعدة بيانات بصيغة DB أولاً", "danger")
        return redirect(url_for("backups_list"))
    if not upload.filename.lower().endswith(".db"):
        flash("ملف الاستعادة يجب أن يكون بامتداد .db", "danger")
        return redirect(url_for("backups_list"))

    import shutil
    BACKUP_DIR.mkdir(exist_ok=True)
    candidate = BASE_DIR / f".restore_{secrets.token_hex(8)}.db"
    try:
        upload.save(str(candidate))
        check = sqlite3.connect(str(candidate))
        integrity = check.execute("PRAGMA integrity_check").fetchone()[0]
        tables = {row[0] for row in check.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        check.close()
        required_tables = {"users", "settings", "products", "sale_invoices", "purchase_invoices"}
        if integrity != "ok" or not required_tables.issubset(tables):
            raise ValueError("الملف ليس قاعدة بيانات صالحة للنظام")
        if DB.exists():
            safety_copy = BACKUP_DIR / f"almasrya_before_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
            shutil.copy2(str(DB), str(safety_copy))
        os.replace(str(candidate), str(DB))
        flash("تمت استعادة النسخة الاحتياطية بنجاح. حُفظت نسخة أمان من قاعدة البيانات السابقة.", "success")
    except Exception as exc:
        candidate.unlink(missing_ok=True)
        flash(f"تعذر استعادة النسخة الاحتياطية: {exc}", "danger")
    return redirect(url_for("backups_list"))


@app.route("/backups/<path:filename>")
@admin_required
def backup_download(filename):
    if "/" in filename or ".." in filename or not filename.startswith("almasrya_auto_"):
        flash("اسم ملف غير صالح", "danger")
        return redirect(url_for("backups_list"))
    fpath = BACKUP_DIR / filename
    if not fpath.exists():
        flash("الملف غير موجود", "danger")
        return redirect(url_for("backups_list"))
    return send_file(str(fpath), as_attachment=True, download_name=filename)


# ---------------------------------------------------------------------------
# TREASURY & CASH FLOW
# ---------------------------------------------------------------------------
@app.route("/treasury-income-details")
@login_required
def treasury_income_details():
    """عرض تفصيل الدخول حسب الفئات"""
    con = db()
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")
    
    # حساب الدخول حسب الفئة
    query = """
    SELECT 
        category,
        SUM(amount) as total,
        COUNT(*) as count
    FROM treasury
    WHERE transaction_type = 'دخول'
    """
    params = []
    
    if from_date:
        query += " AND transaction_date >= ?"
        params.append(from_date)
    if to_date:
        query += " AND transaction_date <= ?"
        params.append(to_date)
    
    query += " GROUP BY category ORDER BY total DESC"
    
    income_breakdown = con.execute(query, params).fetchall()
    
    # حساب المجموع الكلي
    total_income = sum(item["total"] for item in income_breakdown) if income_breakdown else 0
    
    con.close()
    
    return render_template("treasury_income_details.html",
                         title="تفاصيل دخل الخزانة",
                         income_breakdown=income_breakdown,
                         total_income=total_income,
                         from_date=from_date,
                         to_date=to_date)


@app.route("/treasury-expense-details")
@login_required
def treasury_expense_details():
    """عرض تفصيل الخروج حسب الفئات"""
    con = db()
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")
    
    # حساب الخروج حسب الفئة
    query = """
    SELECT 
        category,
        SUM(amount) as total,
        COUNT(*) as count
    FROM treasury
    WHERE transaction_type = 'خروج'
    """
    params = []
    
    if from_date:
        query += " AND transaction_date >= ?"
        params.append(from_date)
    if to_date:
        query += " AND transaction_date <= ?"
        params.append(to_date)
    
    query += " GROUP BY category ORDER BY total DESC"
    
    expense_breakdown = con.execute(query, params).fetchall()
    
    # حساب المجموع الكلي
    total_expenses = sum(item["total"] for item in expense_breakdown) if expense_breakdown else 0
    
    con.close()
    
    return render_template("treasury_expense_details.html",
                         title="تفاصيل مصاريف الخزانة",
                         expense_breakdown=expense_breakdown,
                         total_expenses=total_expenses,
                         from_date=from_date,
                         to_date=to_date)


@app.route("/treasury")
@login_required
def treasury():
    con = db()
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")
    
    query = "SELECT * FROM treasury WHERE 1=1"
    params = []
    
    if from_date:
        query += " AND transaction_date >= ?"
        params.append(from_date)
    if to_date:
        query += " AND transaction_date <= ?"
        params.append(to_date)
    
    query += " ORDER BY transaction_date DESC"
    
    try:
        transactions = con.execute(query, params).fetchall()
    except Exception as e:
        transactions = []
        print(f"Error fetching transactions: {e}")
    
    # Calculate totals
    total_income = sum(t["amount"] for t in transactions if t["transaction_type"] == "دخول") if transactions else 0
    total_expense = sum(t["amount"] for t in transactions if t["transaction_type"] == "خروج") if transactions else 0
    balance = total_income - total_expense
    
    con.close()
    
    now = datetime.now()
    
    return render_template("treasury.html", 
                         title="الخزانة",
                         transactions=transactions,
                         total_income=total_income,
                         total_expense=total_expense,
                         balance=balance,
                         from_date=from_date,
                         to_date=to_date,
                         now=now)


@app.route("/treasury/add", methods=["POST"])
@admin_required
def treasury_add():
    con = db()
    transaction_date = request.form.get("transaction_date")
    blocked = reject_if_period_closed(transaction_date, "treasury")
    if blocked:
        con.close()
        return blocked
    transaction_type = request.form.get("transaction_type")
    category = request.form.get("category")
    amount = float(request.form.get("amount", 0))
    description = request.form.get("description")
    affects_profit = 1 if request.form.get("affects_profit") == "1" else 0
    if amount <= 0:
        con.close()
        flash("يجب أن يكون المبلغ أكبر من صفر", "danger")
        return redirect(url_for("treasury"))
    if transaction_type not in {"دخول", "خروج"}:
        con.close()
        flash("نوع الحركة غير صحيح", "danger")
        return redirect(url_for("treasury"))
    
    con.execute("""INSERT INTO treasury(
        transaction_date, transaction_type, category, amount, affects_profit,
        description, created_by, created_at
    ) VALUES(?,?,?,?,?,?,?,?)""",
    (transaction_date, transaction_type, category, amount, affects_profit,
     description, session.get("username"), datetime.now().isoformat()))
    
    con.commit()
    con.close()
    
    flash("تم تسجيل الحركة بنجاح", "success")
    return redirect(url_for("treasury"))


@app.route("/treasury/<int:tid>/delete", methods=["POST"])
@admin_required
def treasury_delete(tid):
    con = db()
    row = con.execute("SELECT reference_type FROM treasury WHERE id=?", (tid,)).fetchone()
    if not row:
        con.close()
        flash("الحركة غير موجودة", "danger")
        return redirect(url_for("treasury"))
    if row["reference_type"]:
        con.close()
        flash("لا يمكن حذف حركة مرتبطة بفاتورة من الخزانة مباشرة؛ عدّل أو ألغِ المستند الأصلي للحفاظ على اتساق الرصيد.", "danger")
        return redirect(url_for("treasury"))
    con.execute("DELETE FROM treasury WHERE id=?", (tid,))
    con.commit()
    con.close()
    flash("تم حذف الحركة اليدوية بنجاح", "success")
    return redirect(url_for("treasury"))


# ---------------------------------------------------------------------------
# PROFIT & LOSS & ACCOUNTS
# ---------------------------------------------------------------------------
@app.route("/profit-loss")
@login_required
def profit_loss():
    con = db()
    from_date = request.args.get("from_date", "")
    to_date = request.args.get("to_date", "")

    def add_period_filter(query, params, column):
        if from_date:
            query += f" AND {column} >= ?"
            params.append(from_date)
        if to_date:
            query += f" AND {column} <= ?"
            params.append(to_date)
        return query

    # المبيعات = الإجمالي النهائي للفواتير غير الملغاة، بعد الخصم والضريبة.
    sale_query = "SELECT COALESCE(SUM(total), 0) AS total FROM sale_invoices WHERE is_cancelled=0"
    params_sale = []
    sale_query = add_period_filter(sale_query, params_sale, "invoice_date")
    total_sales = con.execute(sale_query, params_sale).fetchone()["total"] or 0

    return_filter = ""
    return_params = []
    if from_date:
        return_filter += " AND return_date >= ?"
        return_params.append(from_date)
    if to_date:
        return_filter += " AND return_date <= ?"
        return_params.append(to_date)
    sale_returns_query = "SELECT COALESCE(SUM(amount), 0) AS total FROM returns WHERE invoice_type='sale'"
    sale_returns_query += return_filter
    total_sales_returns = con.execute(sale_returns_query, return_params).fetchone()["total"] or 0
    total_sales -= total_sales_returns

    # المشتريات = إجمالي فواتير التوريد غير الملغاة، للعرض والتحليل فقط.
    purchase_query = "SELECT COALESCE(SUM(total), 0) AS total FROM purchase_invoices WHERE is_cancelled=0"
    params_purchase = []
    purchase_query = add_period_filter(purchase_query, params_purchase, "invoice_date")
    total_purchases = con.execute(purchase_query, params_purchase).fetchone()["total"] or 0
    purchase_returns_query = "SELECT COALESCE(SUM(amount), 0) AS total FROM returns WHERE invoice_type='purchase'"
    purchase_returns_query += return_filter
    total_purchase_returns = con.execute(purchase_returns_query, return_params).fetchone()["total"] or 0
    total_purchases -= total_purchase_returns

    # تكلفة المبيعات = تكلفة الأصناف التي بيعت فعلياً، وليس كل المشتريات.
    # نستخدم التكلفة المثبتة داخل بند البيع، مع الرجوع للتكلفة الحالية للبيانات القديمة.
    cost_query = """
        SELECT COALESCE(SUM(si.quantity * COALESCE(si.cost_price, p.cost_price, 0)), 0) AS total
        FROM sale_invoices s
        JOIN sale_items si ON si.invoice_id = s.id
        LEFT JOIN products p ON p.id = si.product_id
        WHERE s.is_cancelled=0
    """
    params_cost = []
    cost_query = add_period_filter(cost_query, params_cost, "s.invoice_date")
    total_cost_of_sales = con.execute(cost_query, params_cost).fetchone()["total"] or 0
    sale_return_cost_query = """
        SELECT COALESCE(SUM(ri.quantity * COALESCE(ri.cost_price, 0)), 0) AS total
        FROM return_items ri
        JOIN returns r ON r.id = ri.return_id
        WHERE r.invoice_type='sale'
    """
    sale_return_cost_query += return_filter.replace("return_date", "r.return_date")
    total_sales_return_cost = con.execute(sale_return_cost_query, return_params).fetchone()["total"] or 0
    total_cost_of_sales = max(total_cost_of_sales - total_sales_return_cost, 0)

    # المصاريف التشغيلية = حركات الخروج المصنفة بأنها تؤثر على الربح والخسارة.
    expense_query = "SELECT COALESCE(SUM(amount), 0) AS total FROM treasury WHERE transaction_type='خروج' AND affects_profit=1"
    params_expense = []
    expense_query = add_period_filter(expense_query, params_expense, "transaction_date")
    total_expenses = con.execute(expense_query, params_expense).fetchone()["total"] or 0

    # الدخل الإضافي = حركات الدخول المصنفة بأنها تؤثر على الربح والخسارة.
    income_query = "SELECT COALESCE(SUM(amount), 0) AS total FROM treasury WHERE transaction_type='دخول' AND affects_profit=1"
    params_income = []
    income_query = add_period_filter(income_query, params_income, "transaction_date")
    total_income = con.execute(income_query, params_income).fetchone()["total"] or 0

    # الحسابات المشتقة تلقائياً:
    # الربح الإجمالي = المبيعات - تكلفة البضاعة المباعة.
    # صافي النتيجة = الربح الإجمالي - المصاريف + الدخل الإضافي.
    zero_cost_query = """
        SELECT COALESCE(SUM(CASE WHEN COALESCE(si.cost_price, p.cost_price, 0) <= 0 THEN 1 ELSE 0 END), 0) AS count
        FROM sale_invoices s
        JOIN sale_items si ON si.invoice_id = s.id
        LEFT JOIN products p ON p.id = si.product_id
        WHERE s.is_cancelled=0
    """
    params_zero_cost = []
    zero_cost_query = add_period_filter(zero_cost_query, params_zero_cost, "s.invoice_date")
    zero_cost_items_count = con.execute(zero_cost_query, params_zero_cost).fetchone()["count"] or 0

    gross_profit = total_sales - total_cost_of_sales
    net_result = gross_profit - total_expenses + total_income
    net_profit = max(net_result, 0)
    net_loss = max(-net_result, 0)
    gross_margin = (gross_profit / total_sales * 100) if total_sales else 0
    net_margin = (net_result / total_sales * 100) if total_sales else 0

    # Compare a selected period with the immediately preceding period of equal length.
    comparison_period_start = None
    comparison_period_end = None
    previous_net_result = None
    net_change = None
    net_change_percent = None
    if from_date and to_date:
        try:
            period_start = date.fromisoformat(from_date)
            period_end = date.fromisoformat(to_date)
            if period_start <= period_end:
                period_days = (period_end - period_start).days + 1
                comparison_period_end = period_start - timedelta(days=1)
                comparison_period_start = comparison_period_end - timedelta(days=period_days - 1)
                ps = comparison_period_start.isoformat()
                pe = comparison_period_end.isoformat()
                prev_sales = con.execute("SELECT COALESCE(SUM(total),0) AS total FROM sale_invoices WHERE is_cancelled=0 AND invoice_date BETWEEN ? AND ?", (ps, pe)).fetchone()["total"] or 0
                prev_sales -= con.execute("SELECT COALESCE(SUM(amount),0) AS total FROM returns WHERE invoice_type='sale' AND return_date BETWEEN ? AND ?", (ps, pe)).fetchone()["total"] or 0
                prev_cost = con.execute("""SELECT COALESCE(SUM(si.quantity * COALESCE(si.cost_price, p.cost_price, 0)),0) AS total
                                           FROM sale_invoices s JOIN sale_items si ON si.invoice_id=s.id
                                           LEFT JOIN products p ON p.id=si.product_id
                                           WHERE s.is_cancelled=0 AND s.invoice_date BETWEEN ? AND ?""", (ps, pe)).fetchone()["total"] or 0
                prev_cost -= con.execute("""SELECT COALESCE(SUM(ri.quantity * COALESCE(ri.cost_price,0)),0) AS total
                                           FROM return_items ri JOIN returns r ON r.id=ri.return_id
                                           WHERE r.invoice_type='sale' AND r.return_date BETWEEN ? AND ?""", (ps, pe)).fetchone()["total"] or 0
                prev_expenses = con.execute("SELECT COALESCE(SUM(amount),0) AS total FROM treasury WHERE transaction_type='خروج' AND affects_profit=1 AND transaction_date BETWEEN ? AND ?", (ps, pe)).fetchone()["total"] or 0
                prev_income = con.execute("SELECT COALESCE(SUM(amount),0) AS total FROM treasury WHERE transaction_type='دخول' AND affects_profit=1 AND transaction_date BETWEEN ? AND ?", (ps, pe)).fetchone()["total"] or 0
                previous_net_result = prev_sales - max(prev_cost, 0) - prev_expenses + prev_income
                net_change = net_result - previous_net_result
                net_change_percent = (net_change / abs(previous_net_result) * 100) if previous_net_result else None
        except ValueError:
            comparison_period_start = comparison_period_end = None

    con.close()

    return render_template("profit_loss.html",
                         title="تقرير الربح والخسارة",
                         total_sales=total_sales,
                         total_purchases=total_purchases,
                         total_sales_returns=total_sales_returns,
                         total_purchase_returns=total_purchase_returns,
                         total_sales_return_cost=total_sales_return_cost,
                         total_cost_of_sales=total_cost_of_sales,
                         total_expenses=total_expenses,
                         total_income=total_income,
                         gross_profit=gross_profit,
                         net_result=net_result,
                         net_profit=net_profit,
                         net_loss=net_loss,
                         gross_margin=gross_margin,
                         net_margin=net_margin,
                         zero_cost_items_count=zero_cost_items_count,
                         comparison_period_start=comparison_period_start,
                         comparison_period_end=comparison_period_end,
                         previous_net_result=previous_net_result,
                         net_change=net_change,
                         net_change_percent=net_change_percent,
                         from_date=from_date,
                         to_date=to_date)


@app.route("/detailed-analysis")
@login_required
def detailed_analysis():
    con = db()
    
    try:
        # إجمالي التوريد يعتمد على إجمالي الفاتورة بعد الخصم والضريبة، مع خصم المرتجعات.
        purchase_data = con.execute("""
            SELECT
                p.invoice_no,
                p.invoice_date,
                s.name AS supplier_name,
                GROUP_CONCAT(prod.name, ' | ') AS products,
                MAX(p.total - COALESCE(pr.returned_amount, 0), 0) AS total_cost,
                p.created_by
            FROM purchase_invoices p
            LEFT JOIN suppliers s ON p.supplier_id = s.id
            LEFT JOIN purchase_items pi ON p.id = pi.invoice_id
            LEFT JOIN products prod ON pi.product_id = prod.id
            LEFT JOIN (
                SELECT invoice_id, SUM(amount) AS returned_amount
                FROM returns
                WHERE invoice_type = 'purchase'
                GROUP BY invoice_id
            ) pr ON pr.invoice_id = p.id
            WHERE p.is_cancelled = 0
            GROUP BY p.id, p.invoice_no, p.invoice_date, s.name, p.created_by, p.total, pr.returned_amount
            ORDER BY p.invoice_date DESC
        """).fetchall()
    except Exception as e:
        print(f"Error in purchase_data: {e}")
        purchase_data = []
    
    try:
        # صافي البيع يطابق تقرير الربح والخسارة: إجمالي الفاتورة بعد الخصم والضريبة ناقص المرتجع،
        # والتكلفة من cost_price المثبت في بند البيع ناقص تكلفة الكمية المرتجعة.
        sale_data = con.execute("""
            WITH sale_base AS (
                SELECT
                    s.id AS invoice_id,
                    s.invoice_no,
                    s.invoice_date,
                    c.name AS customer_name,
                    COALESCE(SUM(si.quantity), 0) AS gross_qty,
                    COALESCE(SUM(si.quantity * COALESCE(si.cost_price, prod.cost_price, 0)), 0) AS gross_cost,
                    s.total AS gross_sale,
                    s.created_by
                FROM sale_invoices s
                LEFT JOIN customers c ON s.customer_id = c.id
                LEFT JOIN sale_items si ON s.id = si.invoice_id
                LEFT JOIN products prod ON si.product_id = prod.id
                WHERE s.is_cancelled = 0
                GROUP BY s.id, s.invoice_no, s.invoice_date, c.name, s.total, s.created_by
            ), sale_returns AS (
                SELECT invoice_id, COALESCE(SUM(amount), 0) AS returned_amount
                FROM returns
                WHERE invoice_type = 'sale'
                GROUP BY invoice_id
            ), sale_return_items AS (
                SELECT
                    r.invoice_id,
                    COALESCE(SUM(ri.quantity), 0) AS returned_qty,
                    COALESCE(SUM(ri.quantity * COALESCE(ri.cost_price, 0)), 0) AS returned_cost
                FROM returns r
                JOIN return_items ri ON ri.return_id = r.id
                WHERE r.invoice_type = 'sale'
                GROUP BY r.invoice_id
            )
            SELECT
                sb.invoice_no,
                sb.invoice_date,
                sb.customer_name,
                MAX(sb.gross_qty - COALESCE(sri.returned_qty, 0), 0) AS total_qty,
                MAX(sb.gross_sale - COALESCE(sr.returned_amount, 0), 0) AS total_sale,
                MAX(sb.gross_cost - COALESCE(sri.returned_cost, 0), 0) AS total_cost,
                MAX(sb.gross_sale - COALESCE(sr.returned_amount, 0), 0)
                  - MAX(sb.gross_cost - COALESCE(sri.returned_cost, 0), 0) AS profit,
                CASE
                    WHEN MAX(sb.gross_sale - COALESCE(sr.returned_amount, 0), 0) = 0 THEN 0
                    ELSE (
                        MAX(sb.gross_sale - COALESCE(sr.returned_amount, 0), 0)
                        - MAX(sb.gross_cost - COALESCE(sri.returned_cost, 0), 0)
                    ) * 100.0 / MAX(sb.gross_sale - COALESCE(sr.returned_amount, 0), 0)
                END AS margin_percent,
                sb.created_by
            FROM sale_base sb
            LEFT JOIN sale_returns sr ON sr.invoice_id = sb.invoice_id
            LEFT JOIN sale_return_items sri ON sri.invoice_id = sb.invoice_id
            GROUP BY sb.invoice_id, sb.invoice_no, sb.invoice_date, sb.customer_name,
                     sb.gross_qty, sb.gross_cost, sb.gross_sale, sb.created_by,
                     sr.returned_amount, sri.returned_qty, sri.returned_cost
            ORDER BY sb.invoice_date DESC
        """).fetchall()
    except Exception as e:
        print(f"Error in sale_data: {e}")
        sale_data = []
    
    # Summary
    total_purchases = sum(p["total_cost"] for p in purchase_data if p and p["total_cost"]) if purchase_data else 0
    total_sales = sum(s["total_sale"] for s in sale_data if s and s["total_sale"]) if sale_data else 0
    total_profit = sum(s["profit"] for s in sale_data if s and s["profit"]) if sale_data else 0
    loss_sales_count = sum(1 for s in sale_data if s and (s["profit"] or 0) < 0) if sale_data else 0
    
    con.close()
    
    return render_template("detailed_analysis.html",
                         title="التحليل التفصيلي",
                         purchase_data=purchase_data,
                         sale_data=sale_data,
                         total_purchases=total_purchases,
                         total_sales=total_sales,
                         total_profit=total_profit,
                         loss_sales_count=loss_sales_count)


@app.route("/accounts")
@login_required
def accounts():
    con = db()

    # Aggregate named receivables and payables for the detailed tables.
    customer_receivables = con.execute("""
        SELECT c.id, c.name,
               SUM(CASE WHEN si.is_cancelled=0 THEN si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0) ELSE 0 END) AS total,
               SUM(CASE WHEN si.is_cancelled=0 THEN si.paid_amount ELSE 0 END) AS paid,
               SUM(CASE WHEN si.is_cancelled=0 THEN si.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0) - si.paid_amount ELSE 0 END) AS remaining
        FROM customers c
        LEFT JOIN sale_invoices si ON c.id = si.customer_id
        GROUP BY c.id, c.name
        HAVING remaining > 0.001
        ORDER BY remaining DESC
    """).fetchall()
    supplier_payables = con.execute("""
        SELECT s.id, s.name,
               SUM(CASE WHEN pi.is_cancelled=0 THEN pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0) ELSE 0 END) AS total,
               SUM(CASE WHEN pi.is_cancelled=0 THEN pi.paid_amount ELSE 0 END) AS paid,
               SUM(CASE WHEN pi.is_cancelled=0 THEN pi.total - COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0) - pi.paid_amount ELSE 0 END) AS remaining
        FROM suppliers s
        LEFT JOIN purchase_invoices pi ON s.id = pi.supplier_id
        GROUP BY s.id, s.name
        HAVING remaining > 0.001
        ORDER BY remaining DESC
    """).fetchall()

    # Calculate invoice-level balances so walk-in invoices with no linked party are included.
    sale_balance_rows = con.execute("""
        SELECT si.total, si.paid_amount,
               COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='sale' AND r.invoice_id=si.id), 0) AS returned
        FROM sale_invoices si WHERE si.is_cancelled=0
    """).fetchall()
    purchase_balance_rows = con.execute("""
        SELECT pi.total, pi.paid_amount,
               COALESCE((SELECT SUM(r.amount) FROM returns r WHERE r.invoice_type='purchase' AND r.invoice_id=pi.id), 0) AS returned
        FROM purchase_invoices pi WHERE pi.is_cancelled=0
    """).fetchall()
    total_receivables = sum(max(float(row["total"] or 0) - float(row["returned"] or 0) - float(row["paid_amount"] or 0), 0) for row in sale_balance_rows)
    total_payables = sum(max(float(row["total"] or 0) - float(row["returned"] or 0) - float(row["paid_amount"] or 0), 0) for row in purchase_balance_rows)
    total_receivables_billed = sum(max(float(row["total"] or 0) - float(row["returned"] or 0), 0) for row in sale_balance_rows)
    total_payables_billed = sum(max(float(row["total"] or 0) - float(row["returned"] or 0), 0) for row in purchase_balance_rows)
    total_receivables_paid = sum(float(row["paid_amount"] or 0) for row in sale_balance_rows)
    total_payables_paid = sum(float(row["paid_amount"] or 0) for row in purchase_balance_rows)
    receivables_collection_rate = (total_receivables_paid / total_receivables_billed * 100) if total_receivables_billed else 0
    payables_payment_rate = (total_payables_paid / total_payables_billed * 100) if total_payables_billed else 0

    treasury_totals = con.execute("""
        SELECT
          COALESCE(SUM(CASE WHEN transaction_type='دخول' THEN amount ELSE 0 END),0) AS income,
          COALESCE(SUM(CASE WHEN transaction_type='خروج' THEN amount ELSE 0 END),0) AS expense
        FROM treasury
    """).fetchone()
    sale_collections = con.execute("""
        SELECT COALESCE(SUM(amount),0) AS total FROM treasury
        WHERE transaction_type='دخول' AND reference_type='sale_payment'
    """).fetchone()["total"] or 0
    supplier_settlements = con.execute("""
        SELECT COALESCE(SUM(amount),0) AS total FROM treasury
        WHERE transaction_type='خروج' AND reference_type='purchase_payment'
    """).fetchone()["total"] or 0
    cash_income = float(treasury_totals["income"] or 0)
    cash_expense = float(treasury_totals["expense"] or 0)
    cash_balance = cash_income - cash_expense
    inventory_value = con.execute("""
        SELECT COALESCE(SUM(ps.quantity * COALESCE(p.cost_price,0)),0) AS value
        FROM product_stock ps JOIN products p ON p.id=ps.product_id
    """).fetchone()["value"] or 0
    net_working_position = cash_balance + total_receivables + float(inventory_value) - total_payables

    account_activity = []
    for row in con.execute("SELECT transaction_date, transaction_type, category, amount, description, created_by FROM treasury ORDER BY transaction_date DESC, id DESC LIMIT 30").fetchall():
        is_income = row["transaction_type"] == "دخول"
        account_activity.append({
            "date": row["transaction_date"],
            "type": "دخل الخزانة" if is_income else "خروج الخزانة",
            "category": row["category"] or "-",
            "amount": float(row["amount"] or 0) if is_income else -float(row["amount"] or 0),
            "description": row["description"] or "-",
            "created_by": row["created_by"] or "-"
        })
    account_activity.sort(key=lambda item: item["date"], reverse=True)
    account_activity = account_activity[:30]
    customer_count = sum(1 for row in customer_receivables if (row["remaining"] or 0) > 0.001)
    supplier_count = sum(1 for row in supplier_payables if (row["remaining"] or 0) > 0.001)

    con.close()
    return render_template("accounts.html",
                         title="الحسابات والمركز المالي",
                         customer_receivables=customer_receivables,
                         supplier_payables=supplier_payables,
                         total_receivables=total_receivables,
                         total_payables=total_payables,
                         total_receivables_billed=total_receivables_billed,
                         total_payables_billed=total_payables_billed,
                         total_receivables_paid=total_receivables_paid,
                         total_payables_paid=total_payables_paid,
                         receivables_collection_rate=receivables_collection_rate,
                         payables_payment_rate=payables_payment_rate,
                         cash_income=cash_income,
                         cash_expense=cash_expense,
                         sale_collections=float(sale_collections),
                         supplier_settlements=float(supplier_settlements),
                         cash_balance=cash_balance,
                         inventory_value=float(inventory_value),
                         net_working_position=net_working_position,
                         account_activity=account_activity,
                         customer_count=customer_count,
                         supplier_count=supplier_count)


# ---------------------------------------------------------------------------
if __name__ == "__main__":
    init_db()
    run_auto_backup()
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("ALMASRYA_DEBUG", "0") == "1"
    app.run(host="127.0.0.1", port=port, debug=debug)
else:
    init_db()
    run_auto_backup()
