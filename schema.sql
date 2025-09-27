-- The 'users' table is now purely for login/authentication.
DROP TABLE IF EXISTS users;
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name TEXT NOT NULL, -- The name of the account manager
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- The new 'profiles' table holds info for each individual person.
DROP TABLE IF EXISTS profiles;
CREATE TABLE profiles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    manager_user_id INTEGER NOT NULL, -- Links to the managing user account
    profile_name TEXT NOT NULL,       -- e.g., "Self", "Dad", "Alice"
    date_of_birth DATE,
    gender TEXT,
    profile_picture TEXT,
    is_manager INTEGER DEFAULT 0,     -- Flag to identify the manager's own profile
    FOREIGN KEY (manager_user_id) REFERENCES users (id) ON DELETE CASCADE
);

-- All subsequent tables are now linked to a 'profile_id'.
DROP TABLE IF EXISTS medicines;
CREATE TABLE medicines (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    current_stock INTEGER DEFAULT 0,
    meal_timing TEXT,
    meal_type TEXT,
    days_to_take TEXT,
    reason TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS reminders;
CREATE TABLE reminders (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    medicine_id INTEGER NOT NULL,
    time TEXT NOT NULL,
    days TEXT,
    note TEXT,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE,
    FOREIGN KEY (medicine_id) REFERENCES medicines (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS medical_history;
CREATE TABLE medical_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    `condition` TEXT NOT NULL,
    description TEXT,
    report_file TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS appointments;
CREATE TABLE appointments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    doctor_name TEXT,
    hospital TEXT,
    date_time DATETIME,
    purpose TEXT,
    notes TEXT,
    reminder_minutes_before INTEGER,
    reminder_sent INTEGER DEFAULT 0,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS emergency_contacts;
CREATE TABLE emergency_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    relationship TEXT,
    phone TEXT NOT NULL,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS medicine_intake;
CREATE TABLE medicine_intake (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    medicine_id INTEGER NOT NULL,
    taken_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE,
    FOREIGN KEY (medicine_id) REFERENCES medicines (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS stock_updates;
CREATE TABLE stock_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    medicine_id INTEGER NOT NULL,
    change INTEGER NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE,
    FOREIGN KEY (medicine_id) REFERENCES medicines (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS recent_activities;
CREATE TABLE recent_activities (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL, -- Activities are also per-profile
    activity_type TEXT NOT NULL,
    description TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE
);

DROP TABLE IF EXISTS adherence;
CREATE TABLE adherence (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL,
    date TEXT NOT NULL,
    percentage INTEGER NOT NULL,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE,
    UNIQUE(profile_id, date)
);

DROP TABLE IF EXISTS share_tokens;
CREATE TABLE share_tokens (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id INTEGER NOT NULL, -- Sharing is per-profile
    token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (profile_id) REFERENCES profiles (id) ON DELETE CASCADE
);