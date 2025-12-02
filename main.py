import os
import time
import hmac
import hashlib
import json
import re
from datetime import datetime, timedelta

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import databases
import sqlalchemy
from dotenv import load_dotenv

# تحميل متغيرات البيئة من ملف .env
load_dotenv()

# ===== إعدادات الاتصال وقيم عامة =====
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql:postgresql://neondb_owner:HWpoOYunK1l7@ep-twilight-river-xxxxx.neon.tech/neondb?sslmode=require"
)
API_KEY = os.getenv("API_KEY", "your_api_key_hereasdasdasd")
HMAC_SECRET = os.getenv("HMAC_SECRET", "your_hmac_secret_hereasdasdasdasd")

DB_MAX_BYTES = int(os.getenv("DB_MAX_BYTES", "1000000000"))

ALLOWED_PUBLIC_ORIGINS = [
    "https://fimonova-kosmetik.de",
    "https://www.fimonova-kosmetik.de",
]

# إعدادات نظام كلمة السر للتطبيق
MAX_LOGIN_ATTEMPTS = 3
LOCK_SECONDS = 15 * 60   # ربع ساعة
DEFAULT_APP_ID = "desktop_manager"

# ===== إعداد قاعدة البيانات =====
database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()
engine = sqlalchemy.create_engine(DATABASE_URL)

# جدول الطلاب بالشهادات مباشرة
students = sqlalchemy.Table(
    "students", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("firstname", sqlalchemy.Text),
    sqlalchemy.Column("lastname", sqlalchemy.Text),
    sqlalchemy.Column("birthdate", sqlalchemy.Text),
    sqlalchemy.Column("gender", sqlalchemy.Text),
    sqlalchemy.Column("cert_name", sqlalchemy.Text),
    sqlalchemy.Column("cert_serial_sn", sqlalchemy.Text),
    sqlalchemy.Column("cert_random_code", sqlalchemy.Text),
)

# جدول كلمة السر للتطبيق مع عداد المحاولات والقفل
app_password_table = sqlalchemy.Table(
    "app_password", metadata,
    sqlalchemy.Column("id", sqlalchemy.Integer, primary_key=True),
    sqlalchemy.Column("app_id", sqlalchemy.Text, unique=True, nullable=False),
    sqlalchemy.Column("password_hash", sqlalchemy.Text, nullable=False),
    sqlalchemy.Column("failed_attempts", sqlalchemy.Integer, nullable=False, server_default="0"),
    sqlalchemy.Column("locked_until", sqlalchemy.DateTime),
)

# ===== تطبيق FastAPI =====
app = FastAPI(title="Fimonova Remote API")

# --- CORS للصفحة العامة للتحقق ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_PUBLIC_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---- Pydantic models ----

class SearchPayload(BaseModel):
    firstname: str
    lastname: str
    birthdate: str


class StudentPayload(BaseModel):
    firstname: str
    lastname: str
    birthdate: str
    gender: str
    cert_name: str
    cert_serial_sn: str
    cert_random_code: str


class PasswordCheckPayload(BaseModel):
    password: str
    app_id: str | None = DEFAULT_APP_ID


class PasswordSetPayload(BaseModel):
    old_password: str
    new_password: str
    app_id: str | None = DEFAULT_APP_ID


# ---- Utilities ----

def canonical_json(obj):
    return json.dumps(obj, separators=(",", ":"), sort_keys=True, ensure_ascii=False)


def verify_request_signature(body_obj, x_signature: str, x_timestamp: str, authorization: str):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Missing Authorization")
    token = authorization.split(" ", 1)[1]
    if token != API_KEY:
        raise HTTPException(401, "Invalid API Key")

    try:
        ts = int(x_timestamp)
    except Exception:
        raise HTTPException(400, "Invalid timestamp")
    if abs(int(time.time()) - ts) > 300:
        raise HTTPException(400, "Timestamp out of range")

    message = f"{x_timestamp}.{canonical_json(body_obj)}"
    expected = hmac.new(
        HMAC_SECRET.encode("utf-8"),
        message.encode("utf-8"),
        hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(401, "Invalid signature")


def hash_password(raw: str) -> str:
    """تجزئة كلمة السر قبل التخزين أو المقارنة."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


async def get_or_create_app_password(app_id: str = DEFAULT_APP_ID):
    """
    ترجع صف كلمة السر للتطبيق.
    لو ما فيه صف، تنشئ واحد بكلمة سر افتراضية '0000'.
    """
    row = await database.fetch_one(
        "SELECT * FROM app_password WHERE app_id = :app_id",
        {"app_id": app_id},
    )
    if row:
        return row

    # كلمة السر الافتراضية: 0000
    default_hash = hash_password("0000")
    await database.execute(
        """
        INSERT INTO app_password (app_id, password_hash, failed_attempts, locked_until)
        VALUES (:app_id, :password_hash, 0, NULL)
        ON CONFLICT (app_id) DO NOTHING
        """,
        {"app_id": app_id, "password_hash": default_hash},
    )
    row = await database.fetch_one(
        "SELECT * FROM app_password WHERE app_id = :app_id",
        {"app_id": app_id},
    )
    return row


# ---- DB helpers ----

async def upsert_student(payload: dict):
    """
    /update و /add:
      - نبحث عن صف يطابق ٥ عناصر:
          firstname, lastname, birthdate, cert_name, cert_serial_sn
      - إذا وجدناه => نحدّث (gender, cert_random_code) لنفس الصف فقط.
      - إذا لم نجده => نضيف صف جديد (شهادة جديدة).
      - الـ cert_random_code لا يدخل في شرط التطابق.
    """
    row = await database.fetch_one(
        """
        SELECT id FROM students
         WHERE firstname      = :firstname
           AND lastname       = :lastname
           AND birthdate      = :birthdate
           AND cert_name      = :cert_name
           AND cert_serial_sn = :cert_serial_sn
        """,
        values={
            "firstname":      payload["firstname"],
            "lastname":       payload["lastname"],
            "birthdate":      payload["birthdate"],
            "cert_name":      payload["cert_name"],
            "cert_serial_sn": payload["cert_serial_sn"],
        }
    )

    if row:
        update_values = {
            "id": row["id"],
            "gender":           payload["gender"],
            "cert_random_code": payload["cert_random_code"],
        }

        await database.execute(
            """
            UPDATE students
               SET gender           = :gender,
                   cert_random_code = :cert_random_code
             WHERE id = :id
            """,
            values=update_values
        )
        return {
            "status": "updated",
            "student_id": row["id"],
        }

    insert_values = {
        "firstname":        payload["firstname"],
        "lastname":         payload["lastname"],
        "birthdate":        payload["birthdate"],
        "gender":           payload["gender"],
        "cert_name":        payload["cert_name"],
        "cert_serial_sn":   payload["cert_serial_sn"],
        "cert_random_code": payload["cert_random_code"],
    }

    student_id = await database.execute(
        """
        INSERT INTO students
            (firstname, lastname, birthdate, gender,
             cert_name, cert_serial_sn, cert_random_code)
        VALUES
            (:firstname, :lastname, :birthdate, :gender,
             :cert_name, :cert_serial_sn, :cert_random_code)
        RETURNING id
        """,
        values=insert_values
    )

    return {
        "status": "inserted",
        "student_id": student_id,
    }


# ---- أحداث بدء/إيقاف السيرفر ----

@app.on_event("startup")
async def startup():
    await database.connect()
    metadata.create_all(engine)


@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()


# ---- Endpoints أساسية لإدارة الطلاب ----

@app.post("/add")
async def add_student(
    payload: StudentPayload,
    request: Request,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    res = await upsert_student(body)
    return {"result": "added", **res}


@app.post("/update")
async def update_student(
    payload: StudentPayload,
    request: Request,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    res = await upsert_student(body)
    return {"result": "updated", **res}


@app.post("/delete")
async def delete_student(
    payload: StudentPayload,
    request: Request,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    await database.execute(
        """
        DELETE FROM students
         WHERE firstname = :firstname
           AND lastname  = :lastname
           AND birthdate = :birthdate
        """,
        values={
            "firstname": body["firstname"],
            "lastname":  body["lastname"],
            "birthdate": body["birthdate"],
        }
    )
    return {"result": "deleted"}


@app.post("/search")
async def search_student(
    payload: SearchPayload,
    request: Request,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)

    row = await database.fetch_one(
        """
        SELECT * FROM students
         WHERE firstname = :firstname
           AND lastname  = :lastname
           AND birthdate = :birthdate
        """,
        values=body
    )
    if not row:
        return {"found": False}
    return {"found": True, "student": dict(row)}


# ---- secured verification page (للاستخدام الداخلي) ----

@app.get("/verify")
async def verify_page(
    firstname: str,
    lastname: str,
    birthdate: str,
    x_abi_key: str = Header(None),
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
):
    if x_abi_key != API_KEY:
        raise HTTPException(401, "Unauthorized")

    body = {"firstname": firstname, "lastname": lastname, "birthdate": birthdate}
    verify_request_signature(body, x_signature, x_timestamp, f"Bearer {API_KEY}")

    row = await database.fetch_one(
        """
        SELECT * FROM students
         WHERE firstname = :firstname
           AND lastname  = :lastname
           AND birthdate = :birthdate
        """,
        values={
            "firstname": firstname,
            "lastname":  lastname,
            "birthdate": birthdate,
        }
    )
    if not row:
        return {"found": False}
    return {"found": True, "student": dict(row)}


@app.get("/")
async def root():
    return {"status": "ok", "service": "fimonova_api"}


# ---- حجم قاعدة البيانات ----

@app.get("/db_size")
async def get_db_size():
    """
    يرجّع حجم قاعدة البيانات الحالية بصيغة جميلة + النسبة من الحد الأقصى التقريبي.
    """
    row = await database.fetch_one(
        """
        SELECT 
            pg_database_size(current_database()) AS size_bytes,
            pg_size_pretty(pg_database_size(current_database())) AS size_pretty
        """
    )

    if not row:
        raise HTTPException(500, "Cannot get database size")

    size_bytes = int(row["size_bytes"])
    size_pretty = row["size_pretty"]

    used_percent = None
    if DB_MAX_BYTES > 0:
        used_percent = round((size_bytes / DB_MAX_BYTES) * 100, 2)

    return {
        "size_bytes": size_bytes,
        "size_pretty": size_pretty,
        "used_percent": used_percent,
        "max_bytes": DB_MAX_BYTES,
    }


@app.get("/wake")
async def wake():
    # فقط لإيقاظ السيرفر على Render
    return {"status": "awake"}


# ---- واجهة التحقق العامة (لصفحة HTML) ----

@app.post("/verify_public")
async def verify_public(
    request: Request,
    payload: dict,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    # 1) التحقق من الـ Origin (زيادة أمان فوق التوقيع)
    origin = request.headers.get("origin")
    if origin not in ALLOWED_PUBLIC_ORIGINS:
        raise HTTPException(403, "Forbidden origin")

    # 2) التحقق من الـ API_KEY + HMAC (مثل /add و /search ...)
    # body_obj هنا هو نفس الـ payload القادم من البروكسي (serial_number, random_code)
    verify_request_signature(payload, x_signature, x_timestamp, authorization)

    # 3) تنظيف المدخلات
    serial = payload.get("serial_number", "").strip()
    random_code = payload.get("random_code", "").strip()

    # 4) فحص Regex لمنع الحقن
    allowed = re.compile(r"^[A-Za-z0-9\-\_]+$")
    if not allowed.fullmatch(serial) or not allowed.fullmatch(random_code):
        raise HTTPException(400, "Ungültige Eingabe")

    # 5) الاستعلام من قاعدة البيانات
    row = await database.fetch_one(
        """
        SELECT firstname, lastname, cert_name, birthdate
        FROM students
        WHERE cert_serial_sn   = :sn
          AND cert_random_code = :rc
        """,
        values={"sn": serial, "rc": random_code}
    )

    if not row:
        return {"found": False}

    return {
        "found": True,
        "student": {
            "firstname": row["firstname"],
            "lastname":  row["lastname"],
            "cert_name": row["cert_name"],
            "birthdate": row["birthdate"],
        },
    }



from typing import Optional

@app.post("/wake_public")
async def wake_public(
    request: Request,
    payload: dict,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    # السماح فقط من الموقع الحقيقي (زيادة أمان)
    origin = request.headers.get("origin")
    if origin not in ALLOWED_PUBLIC_ORIGINS:
        raise HTTPException(403, "Forbidden origin")

    # توقيع HMAC + API KEY
    verify_request_signature(payload, x_signature, x_timestamp, authorization)

    return {"status": "awake"}




# ---- نظام كلمة السر مع محاولات وقفل ----

@app.post("/check_password")
async def check_password(
    payload: PasswordCheckPayload,
    request: Request,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    """
    يتحقق من كلمة السر مع:
    - توقيع HMAC + API_KEY (verify_request_signature)
    - عداد محاولات فاشلة
    - قفل ربع ساعة بعد 3 محاولات خاطئة
    """
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)

    app_id = body.get("app_id") or DEFAULT_APP_ID
    row = await get_or_create_app_password(app_id)

    now = datetime.utcnow()
    locked_until = row["locked_until"]
    failed_attempts = row["failed_attemptments"] if "failed_attemptments" in row.keys() else row["failed_attempts"] or 0

    # لو مقفول حالياً
    if locked_until and locked_until > now:
        retry_after = int((locked_until - now).total_seconds())
        return {
            "ok": False,
            "reason": "locked",
            "retry_after": retry_after,
        }

    # مقارنة كلمة السر
    if hash_password(body["password"]) == row["password_hash"]:
        # نرجّع العداد إلى الصفر
        await database.execute(
            """
            UPDATE app_password
               SET failed_attempts = 0,
                   locked_until    = NULL
             WHERE app_id = :app_id
            """,
            {"app_id": app_id},
        )
        return {"ok": True}

    # كلمة سر خاطئة
    failed_attempts += 1
    locked_until_value = None
    resp = {"ok": False, "reason": "invalid_password"}

    if failed_attempts >= MAX_LOGIN_ATTEMPTS:
        locked_until_value = now + timedelta(seconds=LOCK_SECONDS)
        failed_attempts = 0
        resp["locked"] = True
        resp["retry_after"] = LOCK_SECONDS

    await database.execute(
        """
        UPDATE app_password
           SET failed_attempts = :failed_attempts,
               locked_until    = :locked_until
         WHERE app_id = :app_id
        """,
        {
            "failed_attempts": failed_attempts,
            "locked_until":    locked_until_value,
            "app_id":          app_id,
        },
    )

    return resp


@app.post("/set_password")
async def set_password(
    payload: PasswordSetPayload,
    request: Request,
    x_signature: str = Header(None),
    x_timestamp: str = Header(None),
    authorization: str = Header(None),
):
    """
    تغيير كلمة السر:
    - محمي بتوقيع HMAC + API_KEY
    - يتحقق من كلمة السر القديمة
    - يحترم حالة القفل (لو مقفول لا يسمح بالتغيير)
    """
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)

    app_id = body.get("app_id") or DEFAULT_APP_ID
    row = await get_or_create_app_password(app_id)

    now = datetime.utcnow()
    locked_until = row["locked_until"]

    if locked_until and locked_until > now:
        retry_after = int((locked_until - now).total_seconds())
        return {
            "ok": False,
            "reason": "locked",
            "retry_after": retry_after,
        }

    # تحقق من old_password
    if hash_password(body["old_password"]) != row["password_hash"]:
        return {
            "ok": False,
            "reason": "old_password_wrong",
        }

    new_hash = hash_password(body["new_password"])
    await database.execute(
        """
        UPDATE app_password
           SET password_hash   = :password_hash,
               failed_attempts = 0,
               locked_until    = NULL
         WHERE app_id = :app_id
        """,
        {"password_hash": new_hash, "app_id": app_id},
    )

    return {"ok": True}

