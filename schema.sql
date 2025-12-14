-- schema.sql الجديد (متوافق مع main.py)

CREATE TABLE IF NOT EXISTS students (
  id SERIAL PRIMARY KEY,
  firstname TEXT NOT NULL,
  lastname TEXT NOT NULL,
  birthdate TEXT NOT NULL,
  gender TEXT,
  cert_name TEXT,
  cert_serial_sn TEXT,
  cert_random_code TEXT
);

-- جدول بسيط لتخزين كلمة سر تطبيق التجنر (بشكل مُشفّر)
CREATE TABLE IF NOT EXISTS app_password (
  id SERIAL PRIMARY KEY,
  password_hash TEXT NOT NULL,
  updated_at   TEXT
);

CREATE TABLE IF NOT EXISTS app_password (
  id SERIAL PRIMARY KEY,
  app_id TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ
);


CREATE INDEX IF NOT EXISTS idx_students_name_birth
ON students (firstname, lastname, birthdate);
