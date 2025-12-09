-- جدول الطلاب
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

-- جدول كلمة السر للتطبيق مع العدّاد والقفل
CREATE TABLE IF NOT EXISTS app_password (
  id SERIAL PRIMARY KEY,
  app_id TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until TIMESTAMPTZ
);

-- جدول طلبات إعادة تعيين كلمة السر
CREATE TABLE IF NOT EXISTS app_password_reset (
  id SERIAL PRIMARY KEY,
  app_id TEXT NOT NULL,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at TIMESTAMPTZ NOT NULL,
  used BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_students_name_birth
ON students (firstname, lastname, birthdate);
