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

CREATE INDEX IF NOT EXISTS idx_students_name_birth
ON students (firstname, lastname, birthdate);
