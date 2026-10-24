# AuditTrail

Daily cash, income and expense tracking for two branches, with a full activity log of every change.

- **G-10/4 (near IBCC)**: Print Shop, cashier **Zeeshan**
- **H-8 (near Excise & Taxation)**: Car Setup, cashier **Awais**

## Features
- **Cashiers** add income and expenses (category, amount, Cash/JazzCash/EasyPaisa/Bank/Card, note), set opening cash, and close the day by counting the drawer. The site shows any cash **short / excess**.
- Cashiers can only change **today's** entries for **their own branch**, and only until the day is closed. Every edit or void needs a reason.
- **Nothing is deleted.** Voided entries stay visible, crossed out. The database blocks deleting entries and blocks changing or deleting the activity log.
- **Owner dashboard**: today and month totals per branch and combined, 30-day chart, daily summary with cash differences, top categories, alerts (cash mismatches, big expenses, voids, edits after close, failed logins).
- **Activity log**: who did what and when, with old → new values and the reason, filterable by branch, action and date.
- Entries list with filters and **Excel (CSV) export**. Team page to add or disable cashiers, reset passwords and move them between branches. The owner can reopen a closed day (with a reason).

## Run it
Requires Node.js 22.13 or newer.

```bash
npm install
npm start          # http://localhost:3000
```

Default logins (change them right away from the **Password** page):

| User | Password |
|---|---|
| owner | owner123 |
| zeeshan | zeeshan123 |
| awais | awais123 |

Settings (environment variables): `PORT`, `SESSION_SECRET` (set this in production), `DB_FILE` (default `data/audittrail.db`), `BIG_EXPENSE` (alert threshold, default 10000), and `OWNER_PASSWORD`, `ZEESHAN_PASSWORD`, `AWAIS_PASSWORD` (used only on first start).

Data is stored in a single SQLite file. Back up `data/audittrail.db` regularly.
