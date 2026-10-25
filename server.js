const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const TZ = 'Asia/Karachi';
const BIG_EXPENSE = Number(process.env.BIG_EXPENSE || 10000);
const METHODS = ['Cash', 'JazzCash', 'EasyPaisa', 'Bank transfer', 'Card'];

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 12 * 3600 * 1000 },
}));

// ---------- helpers ----------
const today = () => new Date().toLocaleDateString('en-CA', { timeZone: TZ });
const nowIso = () => new Date().toISOString();
const rs = (n) => 'Rs ' + Number(n || 0).toLocaleString('en-PK');
const fmtTime = (iso) => iso ? new Date(iso).toLocaleString('en-PK', { timeZone: TZ, dateStyle: 'medium', timeStyle: 'short' }) : '';
const toAmount = (v) => { const n = Math.round(Number(String(v).replace(/,/g, ''))); return Number.isFinite(n) ? n : NaN; };

function audit(user, action, { branchId = null, entity = null, entityId = null, details = null, reason = null } = {}) {
  db.prepare(`INSERT INTO audit (at, user_id, user_name, branch_id, action, entity, entity_id, details, reason)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(nowIso(), user ? user.id : null, user ? user.name : null, branchId, action, entity,
      entityId == null ? null : String(entityId), details ? JSON.stringify(details) : null, reason);
}

const branches = () => db.prepare('SELECT * FROM branches ORDER BY id').all();
const branchById = (id) => db.prepare('SELECT * FROM branches WHERE id = ?').get(id);
const categories = (branchId) => db.prepare(
  'SELECT * FROM categories WHERE branch_id IS NULL OR branch_id = ? ORDER BY type, branch_id IS NULL, name').all(branchId);
const getDay = (branchId, date) => db.prepare('SELECT * FROM days WHERE branch_id = ? AND date = ?').get(branchId, date);
const dayEntries = (branchId, date) => db.prepare(`
  SELECT e.*, u.name AS created_by_name FROM entries e JOIN users u ON u.id = e.created_by
  WHERE e.branch_id = ? AND e.date = ? ORDER BY e.created_at`).all(branchId, date);

function totals(entries, opening = 0) {
  const t = { income: 0, expense: 0, cashIn: 0, cashOut: 0 };
  for (const e of entries) {
    if (e.voided) continue;
    t[e.type] += e.amount;
    if (e.method === 'Cash') e.type === 'income' ? (t.cashIn += e.amount) : (t.cashOut += e.amount);
  }
  t.net = t.income - t.expense;
  t.expectedCash = opening + t.cashIn - t.cashOut;
  return t;
}

app.use((req, res, next) => {
  res.locals.user = req.session.user || null; res.locals.path = req.path;
  res.locals.rs = rs; res.locals.fmtTime = fmtTime; res.locals.today = today();
  res.locals.flash = req.session.flash; delete req.session.flash;
  if (!req.session.csrf) req.session.csrf = crypto.randomBytes(16).toString('hex');
  res.locals.csrf = req.session.csrf;
  if (req.method === 'POST' && req.path !== '/login' && req.body._csrf !== req.session.csrf) {
    return res.status(403).send('Invalid form token. Go back and refresh the page.');
  }
  next();
});
const flash = (req, type, msg) => { req.session.flash = { type, msg }; };
const back = (req, res, fallback = '/') => res.redirect(req.get('Referer') || fallback);

function requireLogin(req, res, next) {
  if (!req.session.user) return res.redirect('/login');
  const u = db.prepare('SELECT id, username, name, role, branch_id, active FROM users WHERE id = ?').get(req.session.user.id);
  if (!u || !u.active) { req.session.destroy(() => {}); return res.redirect('/login'); }
  req.user = u; res.locals.user = u; next();
}
const requireOwner = (req, res, next) => req.user.role === 'owner' ? next() : res.status(403).send('Owner only');

// Can this user change data for (branch, date)?
function canEdit(user, branchId, date) {
  if (user.role === 'owner') return true;
  if (user.branch_id !== branchId || date !== today()) return false;
  const d = getDay(branchId, date);
  return !d || d.status === 'open';
}

// ---------- auth ----------
app.get('/login', (req, res) => res.render('login', { error: null }));
app.post('/login', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username = ? AND active = 1').get(String(req.body.username || '').trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(req.body.password || ''), u.password_hash)) {
    audit(null, 'login_failed', { details: { username: req.body.username } });
    return res.render('login', { error: 'Wrong username or password' });
  }
  req.session.regenerate(() => {
    req.session.user = { id: u.id, name: u.name, role: u.role };
    audit(u, 'login', { branchId: u.branch_id });
    res.redirect('/');
  });
});
app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

app.use(requireLogin);
app.get('/', (req, res) => res.redirect(req.user.role === 'owner' ? '/owner' : `/day/${req.user.branch_id}/${today()}`));

app.get('/password', (req, res) => res.render('password'));
app.post('/password', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!bcrypt.compareSync(req.body.current || '', u.password_hash)) { flash(req, 'error', 'Current password is wrong'); return res.redirect('/password'); }
  if ((req.body.next || '').length < 6) { flash(req, 'error', 'New password must be at least 6 characters'); return res.redirect('/password'); }
  db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(req.body.next, 10), u.id);
  audit(req.user, 'password_changed', { entity: 'user', entityId: u.id });
  flash(req, 'ok', 'Password changed'); res.redirect('/');
});

// ---------- day page (cashier + owner) ----------
app.get('/day/:branch/:date', (req, res) => {
  const branchId = Number(req.params.branch), date = req.params.date;
  if (req.user.role !== 'owner' && req.user.branch_id !== branchId) return res.status(403).send('Not your branch');
  const branch = branchById(branchId);
  if (!branch || !/^\d{4}-\d{2}-\d{2}$/.test(date)) return res.status(404).send('Not found');
  const day = getDay(branchId, date);
  const entries = dayEntries(branchId, date);
  const history = db.prepare(`SELECT * FROM audit WHERE branch_id = ? AND (entity = 'entry' AND entity_id IN (SELECT CAST(id AS TEXT) FROM entries WHERE branch_id = ? AND date = ?)
                              OR (entity = 'day' AND entity_id = ?)) ORDER BY id DESC`).all(branchId, branchId, date, date);
  res.render('day', {
    branch, date, day, entries, history, cats: categories(branchId), methods: METHODS,
    t: totals(entries, day ? day.opening_cash : 0), editable: canEdit(req.user, branchId, date),
  });
});

app.post('/day/:branch/:date/open', (req, res) => {
  const branchId = Number(req.params.branch), date = req.params.date;
  if (!canEdit(req.user, branchId, date)) { flash(req, 'error', 'You cannot change this day'); return back(req, res); }
  const amt = toAmount(req.body.opening_cash || 0);
  if (!(amt >= 0)) { flash(req, 'error', 'Enter a valid amount'); return back(req, res); }
  const prev = getDay(branchId, date);
  db.prepare(`INSERT INTO days (branch_id, date, opening_cash) VALUES (?, ?, ?)
              ON CONFLICT (branch_id, date) DO UPDATE SET opening_cash = excluded.opening_cash`).run(branchId, date, amt);
  audit(req.user, prev ? 'opening_cash_changed' : 'day_opened', { branchId, entity: 'day', entityId: date,
    details: prev ? { opening_cash: [prev.opening_cash, amt] } : { opening_cash: amt } });
  flash(req, 'ok', 'Opening cash saved'); back(req, res);
});

function validEntry(body, branchId) {
  const amount = toAmount(body.amount);
  const type = body.type === 'expense' ? 'expense' : 'income';
  const cat = categories(branchId).find((c) => c.name === body.category && c.type === type);
  if (!(amount > 0)) return { error: 'Amount must be more than 0' };
  if (!cat) return { error: 'Pick a category that matches income/expense' };
  if (!METHODS.includes(body.method)) return { error: 'Pick a payment method' };
  return { amount, type, category: cat.name, method: body.method, note: String(body.note || '').trim().slice(0, 300) || null };
}

app.post('/day/:branch/:date/entries', (req, res) => {
  const branchId = Number(req.params.branch), date = req.params.date;
  if (!canEdit(req.user, branchId, date)) { flash(req, 'error', 'This day is closed or not yours'); return back(req, res); }
  const v = validEntry(req.body, branchId);
  if (v.error) { flash(req, 'error', v.error); return back(req, res); }
  if (!getDay(branchId, date)) db.prepare('INSERT INTO days (branch_id, date) VALUES (?, ?)').run(branchId, date);
  const id = db.prepare(`INSERT INTO entries (branch_id, date, type, category, amount, method, note, created_by, created_at)
                         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`)
    .run(branchId, date, v.type, v.category, v.amount, v.method, v.note, req.user.id, nowIso()).lastInsertRowid;
  audit(req.user, 'entry_added', { branchId, entity: 'entry', entityId: id, details: { date, ...Object.fromEntries(Object.entries(v).filter(([, x]) => x != null)) } });
  flash(req, 'ok', `${v.type === 'income' ? 'Income' : 'Expense'} of ${rs(v.amount)} added`); back(req, res);
});

app.post('/entries/:id/edit', (req, res) => {
  const e = db.prepare('SELECT * FROM entries WHERE id = ?').get(req.params.id);
  if (!e || e.voided || !canEdit(req.user, e.branch_id, e.date)) { flash(req, 'error', 'You cannot edit this entry'); return back(req, res); }
  const reason = String(req.body.reason || '').trim();
  if (!reason) { flash(req, 'error', 'A reason is required to edit'); return back(req, res); }
  const v = validEntry(req.body, e.branch_id);
  if (v.error) { flash(req, 'error', v.error); return back(req, res); }
  const changes = {};
  for (const k of ['type', 'category', 'amount', 'method', 'note']) if ((e[k] ?? null) !== (v[k] ?? null)) changes[k] = [e[k], v[k]];
  if (!Object.keys(changes).length) { flash(req, 'error', 'Nothing changed'); return back(req, res); }
  db.prepare('UPDATE entries SET type=?, category=?, amount=?, method=?, note=?, updated_at=? WHERE id=?')
    .run(v.type, v.category, v.amount, v.method, v.note, nowIso(), e.id);
  const closed = (getDay(e.branch_id, e.date) || {}).status === 'closed';
  audit(req.user, closed ? 'entry_edited_after_close' : 'entry_edited', { branchId: e.branch_id, entity: 'entry', entityId: e.id, details: changes, reason });
  flash(req, 'ok', 'Entry updated'); back(req, res);
});

app.post('/entries/:id/void', (req, res) => {
  const e = db.prepare('SELECT * FROM entries WHERE id = ?').get(req.params.id);
  if (!e || e.voided || !canEdit(req.user, e.branch_id, e.date)) { flash(req, 'error', 'You cannot void this entry'); return back(req, res); }
  const reason = String(req.body.reason || '').trim();
  if (!reason) { flash(req, 'error', 'A reason is required to void'); return back(req, res); }
  db.prepare('UPDATE entries SET voided = 1, void_reason = ?, updated_at = ? WHERE id = ?').run(reason, nowIso(), e.id);
  audit(req.user, 'entry_voided', { branchId: e.branch_id, entity: 'entry', entityId: e.id,
    details: { type: e.type, category: e.category, amount: e.amount, method: e.method }, reason });
  flash(req, 'ok', 'Entry voided (kept in history)'); back(req, res);
});

app.post('/day/:branch/:date/close', (req, res) => {
  const branchId = Number(req.params.branch), date = req.params.date;
  if (!canEdit(req.user, branchId, date)) { flash(req, 'error', 'You cannot close this day'); return back(req, res); }
  const counted = toAmount(req.body.counted_cash);
  if (!(counted >= 0)) { flash(req, 'error', 'Enter the cash you counted'); return back(req, res); }
  let day = getDay(branchId, date);
  if (!day) { db.prepare('INSERT INTO days (branch_id, date) VALUES (?, ?)').run(branchId, date); day = getDay(branchId, date); }
  const t = totals(dayEntries(branchId, date), day.opening_cash);
  const note = String(req.body.note || '').trim() || null;
  db.prepare(`UPDATE days SET counted_cash=?, expected_cash=?, status='closed', close_note=?, closed_by=?, closed_at=?
              WHERE branch_id=? AND date=?`).run(counted, t.expectedCash, note, req.user.id, nowIso(), branchId, date);
  const diff = counted - t.expectedCash;
  audit(req.user, 'day_closed', { branchId, entity: 'day', entityId: date, reason: note,
    details: { income: t.income, expense: t.expense, expected_cash: t.expectedCash, counted_cash: counted, difference: diff } });
  flash(req, diff === 0 ? 'ok' : 'error', diff === 0 ? 'Day closed. Cash matches.' : `Day closed. Cash is ${diff < 0 ? 'SHORT' : 'EXCESS'} by ${rs(Math.abs(diff))}`);
  back(req, res);
});

app.post('/day/:branch/:date/reopen', requireOwner, (req, res) => {
  const branchId = Number(req.params.branch), date = req.params.date;
  const reason = String(req.body.reason || '').trim();
  if (!reason) { flash(req, 'error', 'A reason is required to reopen'); return back(req, res); }
  db.prepare(`UPDATE days SET status='open' WHERE branch_id=? AND date=?`).run(branchId, date);
  audit(req.user, 'day_reopened', { branchId, entity: 'day', entityId: date, reason });
  flash(req, 'ok', 'Day reopened'); back(req, res);
});

// ---------- owner ----------
app.get('/owner', requireOwner, (req, res) => {
  const t0 = today();
  const from = new Date(Date.now() - 29 * 864e5).toLocaleDateString('en-CA', { timeZone: TZ });
  const month = t0.slice(0, 7);
  const sum = (where, ...args) => db.prepare(`SELECT branch_id,
      SUM(CASE WHEN type='income' THEN amount ELSE 0 END) income,
      SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense
      FROM entries WHERE voided = 0 AND ${where} GROUP BY branch_id`).all(...args);
  const byBranch = (rows) => Object.fromEntries(rows.map((r) => [r.branch_id, r]));
  const todayRows = byBranch(sum('date = ?', t0));
  const monthRows = byBranch(sum("substr(date,1,7) = ?", month));
  const daily = db.prepare(`SELECT date, branch_id,
      SUM(CASE WHEN type='income' THEN amount ELSE 0 END) income,
      SUM(CASE WHEN type='expense' THEN amount ELSE 0 END) expense
      FROM entries WHERE voided = 0 AND date >= ? GROUP BY date, branch_id ORDER BY date`).all(from);
  const days = db.prepare('SELECT * FROM days WHERE date >= ?').all(from);
  const topCats = db.prepare(`SELECT branch_id, type, category, SUM(amount) total FROM entries
      WHERE voided = 0 AND substr(date,1,7) = ? GROUP BY branch_id, type, category ORDER BY total DESC`).all(month);
  const alerts = db.prepare(`SELECT * FROM audit WHERE at >= ? AND action IN
      ('entry_edited_after_close','day_reopened','entry_voided','login_failed') ORDER BY id DESC LIMIT 20`)
    .all(new Date(Date.now() - 7 * 864e5).toISOString());
  const mismatches = db.prepare(`SELECT * FROM days WHERE status='closed' AND counted_cash != expected_cash AND date >= ? ORDER BY date DESC`).all(from);
  const bigExpenses = db.prepare(`SELECT * FROM entries WHERE voided=0 AND type='expense' AND amount >= ? AND date >= ? ORDER BY date DESC LIMIT 10`).all(BIG_EXPENSE, from);
  const feed = db.prepare('SELECT * FROM audit ORDER BY id DESC LIMIT 15').all();
  res.render('owner', { branches: branches(), todayRows, monthRows, daily, days, topCats, alerts, mismatches, bigExpenses, feed, from, month, BIG_EXPENSE });
});

app.get('/owner/audit', requireOwner, (req, res) => {
  const q = { branch: req.query.branch || '', action: req.query.action || '', from: req.query.from || '', to: req.query.to || '' };
  const where = ['1=1'], args = [];
  if (q.branch) { where.push('branch_id = ?'); args.push(Number(q.branch)); }
  if (q.action) { where.push('action = ?'); args.push(q.action); }
  if (q.from) { where.push('at >= ?'); args.push(new Date(q.from + 'T00:00:00+05:00').toISOString()); }
  if (q.to) { where.push('at < ?'); args.push(new Date(new Date(q.to + 'T00:00:00+05:00').getTime() + 864e5).toISOString()); }
  const rows = db.prepare(`SELECT * FROM audit WHERE ${where.join(' AND ')} ORDER BY id DESC LIMIT 500`).all(...args);
  const actions = db.prepare('SELECT DISTINCT action FROM audit ORDER BY action').all().map((r) => r.action);
  res.render('audit', { rows, q, actions, branches: branches() });
});

function entryQuery(q) {
  const where = ['1=1'], args = [];
  if (q.branch) { where.push('e.branch_id = ?'); args.push(Number(q.branch)); }
  if (q.from) { where.push('e.date >= ?'); args.push(q.from); }
  if (q.to) { where.push('e.date <= ?'); args.push(q.to); }
  if (q.type) { where.push('e.type = ?'); args.push(q.type); }
  return db.prepare(`SELECT e.*, u.name created_by_name, b.name branch_name FROM entries e
    JOIN users u ON u.id = e.created_by JOIN branches b ON b.id = e.branch_id
    WHERE ${where.join(' AND ')} ORDER BY e.date DESC, e.created_at DESC LIMIT 2000`).all(...args);
}
app.get('/owner/entries', requireOwner, (req, res) => {
  const q = { branch: req.query.branch || '', from: req.query.from || today().slice(0, 8) + '01', to: req.query.to || today(), type: req.query.type || '' };
  const rows = entryQuery(q);
  res.render('entries', { rows, q, branches: branches(), t: totals(rows) });
});
app.get('/owner/export.csv', requireOwner, (req, res) => {
  const rows = entryQuery(req.query);
  const esc = (v) => `"${String(v ?? '').replace(/"/g, '""')}"`;
  const lines = [['ID', 'Date', 'Branch', 'Type', 'Category', 'Amount', 'Method', 'Note', 'Entered by', 'Created', 'Last edited', 'Voided', 'Void reason'].join(',')];
  for (const r of rows) lines.push([r.id, r.date, r.branch_name, r.type, r.category, r.amount, r.method, r.note, r.created_by_name,
    fmtTime(r.created_at), fmtTime(r.updated_at), r.voided ? 'yes' : '', r.void_reason].map(esc).join(','));
  audit(req.user, 'export_csv', { details: req.query });
  res.set('Content-Type', 'text/csv').set('Content-Disposition', `attachment; filename="entries-${today()}.csv"`).send('﻿' + lines.join('\n'));
});

app.get('/owner/users', requireOwner, (req, res) => {
  const users = db.prepare('SELECT u.*, b.name branch_name FROM users u LEFT JOIN branches b ON b.id = u.branch_id ORDER BY u.role DESC, u.name').all();
  res.render('users', { users, branches: branches() });
});
app.post('/owner/users', requireOwner, (req, res) => {
  const username = String(req.body.username || '').trim().toLowerCase(), name = String(req.body.name || '').trim();
  const branchId = Number(req.body.branch_id);
  if (!/^[a-z0-9_.]{3,30}$/.test(username) || !name || !branchById(branchId) || (req.body.password || '').length < 6) {
    flash(req, 'error', 'Fill all fields (username: letters/numbers, password 6+ chars)'); return res.redirect('/owner/users');
  }
  try {
    const id = db.prepare("INSERT INTO users (username, name, password_hash, role, branch_id) VALUES (?, ?, ?, 'cashier', ?)")
      .run(username, name, bcrypt.hashSync(req.body.password, 10), branchId).lastInsertRowid;
    audit(req.user, 'user_added', { branchId, entity: 'user', entityId: id, details: { username, name } });
    flash(req, 'ok', `Cashier ${name} added`);
  } catch { flash(req, 'error', 'That username already exists'); }
  res.redirect('/owner/users');
});
app.post('/owner/users/:id', requireOwner, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u || u.role === 'owner') { flash(req, 'error', 'Cannot change this user'); return res.redirect('/owner/users'); }
  if (req.body.do === 'toggle') {
    db.prepare('UPDATE users SET active = ? WHERE id = ?').run(u.active ? 0 : 1, u.id);
    audit(req.user, u.active ? 'user_disabled' : 'user_enabled', { branchId: u.branch_id, entity: 'user', entityId: u.id, details: { username: u.username } });
  } else if (req.body.do === 'password' && (req.body.password || '').length >= 6) {
    db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(bcrypt.hashSync(req.body.password, 10), u.id);
    audit(req.user, 'password_reset', { branchId: u.branch_id, entity: 'user', entityId: u.id, details: { username: u.username } });
  } else if (req.body.do === 'branch' && branchById(Number(req.body.branch_id))) {
    db.prepare('UPDATE users SET branch_id = ? WHERE id = ?').run(Number(req.body.branch_id), u.id);
    audit(req.user, 'user_branch_changed', { branchId: Number(req.body.branch_id), entity: 'user', entityId: u.id, details: { branch_id: [u.branch_id, Number(req.body.branch_id)] } });
  } else { flash(req, 'error', 'Invalid request (password needs 6+ chars)'); return res.redirect('/owner/users'); }
  flash(req, 'ok', 'Saved'); res.redirect('/owner/users');
});

// Dial gauge: a ring of ticks, the filled share ends in pale dots
app.locals.gaugeSvg = (v) => {
  v = Math.max(0, Math.min(100, v || 0));
  const c = 130, R1 = 78, R2 = 104, n = 60; let t = '';
  for (let i = 0; i < n; i++) {
    const a = -Math.PI / 2 + i / n * 2 * Math.PI, on = i / n < v / 100;
    t += `<line x1="${c + R1 * Math.cos(a)}" y1="${c + R1 * Math.sin(a)}" x2="${c + R2 * Math.cos(a)}" y2="${c + R2 * Math.sin(a)}" stroke="rgba(244,243,234,${on ? .85 : .25})" stroke-width="1.2"/>`;
    if (on && i >= Math.floor(v / 100 * n) - 14) t += `<circle cx="${c + (R2 + 7) * Math.cos(a)}" cy="${c + (R2 + 7) * Math.sin(a)}" r="3" fill="#f2ecaa"/>`;
  }
  return `<svg viewBox="0 0 260 260" width="100%" role="img" aria-label="${v.toFixed(1)} percent">${t}<circle cx="${c}" cy="${c}" r="60" fill="none" stroke="rgba(244,243,234,.12)"/></svg>`;
};
const short = (n) => n >= 1e5 ? (n / 1e5).toFixed(2) + ' lac' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'k' : String(n);
app.locals.short = short;
// Column chart of daily totals; the top 3 days are highlighted and labelled
app.locals.columnsSvg = (vals, labels) => {
  if (!vals.length) return '<p class="muted">No data yet.</p>';
  const W = 640, H = 230, T = 26, Bm = 26, max = Math.max(1, ...vals), top = [...vals].sort((a, b) => b - a).slice(0, 3).filter((x) => x > 0), bw = (W - 20) / Math.max(vals.length, 8);
  return `<svg viewBox="0 0 ${W} ${H}" width="100%" role="img" aria-label="Daily income">` + vals.map((x, i) => {
    const h = Math.max(2, (H - T - Bm) * x / max), X = 10 + i * bw + bw * .22, hot = top.includes(x);
    return `<rect x="${X}" y="${H - Bm - h}" width="${bw * .56}" height="${h}" rx="${Math.min(bw * .28, 6)}" fill="${hot ? '#f2ecaa' : 'rgba(244,243,234,.28)'}"><title>${labels[i]}: ${rs(x)}</title></rect>`
      + (hot ? `<text x="${X + bw * .28}" y="${H - Bm - h - 8}" text-anchor="middle" font-size="11" style="fill:#f4f3ea">${short(x)}</text>` : '')
      + (i % 5 === 0 || i === vals.length - 1 ? `<text x="${X + bw * .28}" y="${H - 8}" text-anchor="middle" font-size="10">${+labels[i].slice(8)}</text>` : '');
  }).join('') + '</svg>';
};
app.locals.branchName = (id) => (branchById(id) || {}).name || '';
app.listen(PORT, () => console.log(`AuditTrail running on http://localhost:${PORT}`));
