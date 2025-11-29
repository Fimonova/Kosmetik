# main.py
import os, time, hmac, hashlib, json
from fastapi import FastAPI, Request, HTTPException, Header
from pydantic import BaseModel
import databases
import sqlalchemy
from dotenv import load_dotenv  
load_dotenv()  # تحميل متغيرات البيئة من ملف .env
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://fimodb_user:o4gHKsxV262NQAVzH7A7DsUebFS6a7F3@dpg-d4ku7didbo4c73e78720-a.oregon-postgres.render.com/fimodb")
API_KEY = os.getenv("API_KEY", "your_api_key_hereasdasdasd")
HMAC_SECRET = os.getenv("HMAC_SECRET", "your_hmac_secret_hereasdasdasdasd")

database = databases.Database(DATABASE_URL)
metadata = sqlalchemy.MetaData()

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
    sqlalchemy.Column("cert_random_code", sqlalchemy.Text)
)

app = FastAPI(title="Fimonova Remote API")


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
    except:
        raise HTTPException(400, "Invalid timestamp")
    if abs(int(time.time()) - ts) > 300:
        raise HTTPException(400, "Timestamp out of range")

    message = f"{x_timestamp}.{canonical_json(body_obj)}"
    expected = hmac.new(HMAC_SECRET.encode("utf-8"), message.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, x_signature):
        raise HTTPException(401, "Invalid signature")

# ---- DB helpers ----
async def upsert_student(payload: dict):
    """
    /update:
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
        # ✅ نفس الشهادة (٥ عناصر متطابقة) → نحدّث فقط
        update_values = {
            "id": row["id"],
            "gender":          payload["gender"],
            "cert_random_code": payload["cert_random_code"],
        }

        await database.execute(
            """
            UPDATE students
               SET gender          = :gender,
                   cert_random_code = :cert_random_code
             WHERE id = :id
            """,
            values=update_values
        )
        return {
            "status": "updated",
            "student_id": row["id"],
        }

    # ❌ لم نجد صف يطابق الخمسة عناصر → شهادة جديدة تماماً → نضيف صف جديد
    insert_values = {
        "firstname":       payload["firstname"],
        "lastname":        payload["lastname"],
        "birthdate":       payload["birthdate"],
        "gender":          payload["gender"],
        "cert_name":       payload["cert_name"],
        "cert_serial_sn":  payload["cert_serial_sn"],
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



# ---- Endpoints ----
@app.on_event("startup")
async def startup():
    await database.connect()
    # إنشاء الجدول إذا لم يكن موجود
    engine = sqlalchemy.create_engine(DATABASE_URL)
    metadata.create_all(engine)

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

@app.post("/add")
async def add_student(payload: StudentPayload, request: Request,
                      x_signature: str = Header(None), x_timestamp: str = Header(None), authorization: str = Header(None)):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    res = await upsert_student(body)
    return {"result": "added", **res}

@app.post("/update")
async def update_student(payload: StudentPayload, request: Request,
                      x_signature: str = Header(None), x_timestamp: str = Header(None), authorization: str = Header(None)):
    body = payload.dict()
    verify_request_signature(body, x_signature, x_timestamp, authorization)
    res = await upsert_student(body)
    return {"result": "updated", **res}


@app.post("/delete")
async def delete_student(payload: StudentPayload, request: Request,
                      x_signature: str = Header(None), x_timestamp: str = Header(None), authorization: str = Header(None)):
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
            "lastname": body["lastname"],
            "birthdate": body["birthdate"],
        }
    )
    return {"result": "deleted"}

@app.post("/search")
async def search_student(payload: SearchPayload, request: Request,
                      x_signature: str = Header(None),
                      x_timestamp: str = Header(None),
                      authorization: str = Header(None)):
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


# ---- secured verification page ----
@app.get("/verify")
async def verify_page(firstname: str, lastname: str, birthdate: str,
                      x_abi_key: str = Header(None), x_signature: str = Header(None), x_timestamp: str = Header(None)):
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
            "lastname": lastname,
            "birthdate": birthdate,
        }
    )
    if not row:
        return {"found": False}
    return {"found": True, "student": dict(row)}


@app.get("/")
async def root():
    return {"status": "ok", "service": "fimonova_api"}


@app.get("/wake")
async def wake():
    # ما في منطق، المهم يرجع بسرعة ويصحّي السيرفر
    return {"status": "awake"}