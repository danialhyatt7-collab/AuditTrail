const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');

const file = process.env.DB_FILE || path.join(__dirname, 'data', 'audittrail.db');
fs.mkdirSync(path.dirname(file), { recursive: true });
const db = new DatabaseSync(file);
db.exec('PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;');

db.exec(`
CREATE TABLE IF NOT EXISTS branches (
  id INTEGER PRIMARY KEY, name TEXT NOT NULL, business TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, name TEXT NOT NULL,
  password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK (role IN ('owner','cashier')),
  branch_id INTEGER REFERENCES branches(id), active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS categories (
  id INTEGER PRIMARY KEY, branch_id INTEGER REFERENCES branches(id),
  type TEXT NOT NULL CHECK (type IN ('income','expense')), name TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS entries (
  id INTEGER PRIMARY KEY, branch_id INTEGER NOT NULL REFERENCES branches(id),
  date TEXT NOT NULL, type TEXT NOT NULL CHECK (type IN ('income','expense')),
  category TEXT NOT NULL, amount INTEGER NOT NULL CHECK (amount > 0),
  method TEXT NOT NULL, note TEXT, created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL, updated_at TEXT, voided INTEGER NOT NULL DEFAULT 0, void_reason TEXT
);
CREATE TABLE IF NOT EXISTS days (
  branch_id INTEGER NOT NULL REFERENCES branches(id), date TEXT NOT NULL,
  opening_cash INTEGER NOT NULL DEFAULT 0, counted_cash INTEGER, expected_cash INTEGER,
  status TEXT NOT NULL DEFAULT 'open', close_note TEXT, closed_by INTEGER, closed_at TEXT,
  PRIMARY KEY (branch_id, date)
);
-- Append-only audit log: every change in the system is recorded here.
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY, at TEXT NOT NULL, user_id INTEGER, user_name TEXT,
  branch_id INTEGER, action TEXT NOT NULL, entity TEXT, entity_id TEXT,
  details TEXT, reason TEXT
);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit
BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS entries_no_delete BEFORE DELETE ON entries
BEGIN SELECT RAISE(ABORT, 'entries cannot be deleted, void them instead'); END;
CREATE INDEX IF NOT EXISTS idx_entries_branch_date ON entries(branch_id, date);
CREATE INDEX IF NOT EXISTS idx_audit_at ON audit(at);
`);

function seed() {
  if (db.prepare('SELECT COUNT(*) c FROM branches').get().c > 0) return;
  const addBranch = db.prepare('INSERT INTO branches (name, business) VALUES (?, ?)');
  const g10 = addBranch.run('G-10/4 (near IBCC)', 'Print Shop').lastInsertRowid;
  const h8 = addBranch.run('H-8 (near Excise & Taxation)', 'Car Setup').lastInsertRowid;

  const addUser = db.prepare('INSERT INTO users (username, name, password_hash, role, branch_id) VALUES (?, ?, ?, ?, ?)');
  const hash = (p) => bcrypt.hashSync(p, 10);
  addUser.run('owner', 'Owner', hash(process.env.OWNER_PASSWORD || 'owner123'), 'owner', null);
  addUser.run('zeeshan', 'Zeeshan', hash(process.env.ZEESHAN_PASSWORD || 'zeeshan123'), 'cashier', g10);
  addUser.run('awais', 'Awais', hash(process.env.AWAIS_PASSWORD || 'awais123'), 'cashier', h8);

  const addCat = db.prepare('INSERT INTO categories (branch_id, type, name) VALUES (?, ?, ?)');
  ['Photocopy', 'Printing (B/W)', 'Printing (Colour)', 'Lamination', 'Binding', 'Scanning',
   'Document / Attestation work', 'Stationery', 'Other income'].forEach((n) => addCat.run(g10, 'income', n));
  ['Number plates', 'Registration / Transfer file', 'Token tax help', 'Car accessories / setup',
   'Other income'].forEach((n) => addCat.run(h8, 'income', n));
  ['Paper', 'Toner / Ink', 'Machine repair'].forEach((n) => addCat.run(g10, 'expense', n));
  ['Plate material', 'Accessories stock'].forEach((n) => addCat.run(h8, 'expense', n));
  ['Rent', 'Electricity / Bills', 'Salary / Daily wage', 'Chai / Food', 'Transport',
   'Miscellaneous'].forEach((n) => addCat.run(null, 'expense', n));
}
seed();

module.exports = db;
