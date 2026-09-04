const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const { createClient } = require('@libsql/client');

let tursoClient = null;
if (process.env.TURSO_DATABASE_URL) {
  console.log('Connecting to Turso Cloud SQLite Database:', process.env.TURSO_DATABASE_URL);
  tursoClient = createClient({
    url: process.env.TURSO_DATABASE_URL,
    authToken: process.env.TURSO_AUTH_TOKEN || ''
  });
}

const dbPath = path.resolve(__dirname, 'gatepass.db');
const localDb = new sqlite3.Database(dbPath);

// Unified Database Adapter (Works seamlessly with Local SQLite3 or Turso Cloud DB)
const db = {
  get(sql, params = [], cb) {
    if (tursoClient) {
      tursoClient.execute({ sql, args: params })
        .then(res => cb(null, res.rows.length > 0 ? res.rows[0] : null))
        .catch(err => cb(err, null));
    } else {
      localDb.get(sql, params, cb);
    }
  },

  all(sql, params = [], cb) {
    if (tursoClient) {
      tursoClient.execute({ sql, args: params })
        .then(res => cb(null, res.rows))
        .catch(err => cb(err, null));
    } else {
      localDb.all(sql, params, cb);
    }
  },

  run(sql, params = [], cb) {
    if (tursoClient) {
      tursoClient.execute({ sql, args: params })
        .then(res => {
          const fakeThis = {
            lastID: res.lastInsertRowid ? Number(res.lastInsertRowid) : 0,
            changes: Number(res.rowsAffected)
          };
          if (cb) cb.call(fakeThis, null);
        })
        .catch(err => {
          if (cb) cb(err);
        });
    } else {
      localDb.run(sql, params, function(err) {
        if (cb) cb.call(this, err);
      });
    }
  },

  serialize(cb) {
    if (tursoClient) {
      cb();
    } else {
      localDb.serialize(cb);
    }
  }
};

function initDatabase() {
  db.serialize(() => {
    // 1. Users Table
    db.run(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        branch_name TEXT NOT NULL,
        display_name TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 2. Passes Table
    db.run(`
      CREATE TABLE IF NOT EXISTS passes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        daily_no INTEGER DEFAULT 1,
        pass_code TEXT UNIQUE NOT NULL,
        category TEXT NOT NULL,
        person_name TEXT NOT NULL,
        nic_number TEXT NOT NULL,
        mobile_number TEXT,
        vehicle_number TEXT,
        branch_name TEXT NOT NULL,
        purpose TEXT,
        access_zones TEXT DEFAULT 'GENERAL',
        valid_from DATETIME DEFAULT CURRENT_TIMESTAMP,
        valid_to DATETIME,
        status TEXT DEFAULT 'PENDING_VERIFICATION',
        created_by TEXT DEFAULT 'SELF_REGISTRATION',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 3. Gate Logs Table
    db.run(`
      CREATE TABLE IF NOT EXISTS gate_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pass_code TEXT NOT NULL,
        person_name TEXT NOT NULL,
        nic_number TEXT NOT NULL,
        category TEXT NOT NULL,
        branch_name TEXT NOT NULL,
        action_type TEXT NOT NULL,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        security_officer_name TEXT DEFAULT 'Security Gate'
      )
    `);

    // 4. Dynamic Branches Table
    db.run(`
      CREATE TABLE IF NOT EXISTS branches (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name_en TEXT NOT NULL,
        name_si TEXT NOT NULL,
        name_ta TEXT NOT NULL,
        icon TEXT DEFAULT 'fa-building',
        is_active INTEGER DEFAULT 1
      )
    `);

    // 5. Dynamic Branch-Linked Visit Purposes Table
    db.run(`
      CREATE TABLE IF NOT EXISTS visit_purposes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        branch_id INTEGER DEFAULT 0,
        purpose_en TEXT NOT NULL,
        purpose_si TEXT NOT NULL,
        purpose_ta TEXT NOT NULL,
        icon TEXT DEFAULT 'fa-file-lines',
        is_active INTEGER DEFAULT 1
      )
    `);

    // 30-Day Public Visitor Pass Auto-Purge Cleanup (Keeps Database Light)
    if (tursoClient) {
      tursoClient.execute("DELETE FROM passes WHERE category = 'VISITOR' AND created_at < datetime('now', '-30 days')")
        .then(r => console.log(`[Auto-Cleanup] Turso DB purged ${r.rowsAffected} public visitor passes older than 30 days.`))
        .catch(e => console.log('Auto cleanup error:', e));
    } else {
      localDb.run("DELETE FROM passes WHERE category = 'VISITOR' AND created_at < datetime('now', '-30 days')", [], function(err) {
        if (!err && this.changes > 0) console.log(`[Auto-Cleanup] Local DB purged ${this.changes} public visitor passes older than 30 days.`);
      });
    }

    // Seed default users if empty
    db.get('SELECT COUNT(*) as count FROM users', [], async (err, row) => {
      if (err) return;
      const count = row ? Number(row.count) : 0;
      if (count === 0) {
        console.log('Seeding initial system users...');
        const salt = await bcrypt.genSalt(10);
        
        const accounts = [
          { username: 'admin', password: 'admin123', role: 'SUPER_ADMIN', branch_name: 'Main Administration', display_name: 'Super Admin' },
          { username: 'confidential', password: 'secret123', role: 'CONFIDENTIAL_ADMIN', branch_name: 'Confidential Branch', display_name: 'Confidential Branch Officer' },
          { username: 'evaluation', password: 'eval123', role: 'EVALUATION_ADMIN', branch_name: 'Evaluation Branch', display_name: 'Evaluation Branch Officer' },
          { username: 'hr_admin', password: 'staff123', role: 'HR_ADMIN', branch_name: 'Establishment HR', display_name: 'Establishment HR Officer' },
          { username: 'security', password: 'gate123', role: 'SECURITY_OFFICER', branch_name: 'Main Gate Security', display_name: 'Main Gate Security Officer' }
        ];

        for (const acc of accounts) {
          const hash = await bcrypt.hash(acc.password, salt);
          db.run(`INSERT INTO users (username, password_hash, role, branch_name, display_name) VALUES (?, ?, ?, ?, ?)`, [acc.username, hash, acc.role, acc.branch_name, acc.display_name]);
        }
      }
    });

    // Seed default Branches if empty
    db.get('SELECT COUNT(*) as count FROM branches', [], (err, row) => {
      if (err) return;
      const count = row ? Number(row.count) : 0;
      if (count === 0) {
        console.log('Seeding default department branches...');
        const defaultBranches = [
          { en: 'Certificate Branch', si: 'සහතික පත්‍ර අංශය', ta: 'சான்றிதழ் பிரிவு', icon: 'fa-certificate' },
          { en: 'Inquiry & Public Relations', si: 'විමසීම් සහ මහජන සම්බන්ධතා අංශය', ta: 'விசாரணைப் பிரிவு', icon: 'fa-headset' },
          { en: 'Confidential Branch', si: 'රහස්‍ය අංශය', ta: 'ரகசியப் பிரிவு', icon: 'fa-user-ninja' },
          { en: 'Evaluation Branch', si: 'ඇගයීම් ශාඛාව', ta: 'மதிப்பீட்டுப் பிரிவு', icon: 'fa-file-pen' },
          { en: 'Establishment HR', si: 'ආයතන ශාඛාව', ta: 'நிறுவனப் பிரிவு', icon: 'fa-id-card' },
          { en: 'Accounts Branch', si: 'ගිණුම් ශාඛාව', ta: 'கණக்குப் பிரிவு', icon: 'fa-calculator' },
          { en: 'Main Administration', si: 'පරිපාලන අංශය', ta: 'முதன்மை நிர்வாகப் பிரிவு', icon: 'fa-building-columns' }
        ];

        for (const b of defaultBranches) {
          db.run(`INSERT INTO branches (name_en, name_si, name_ta, icon) VALUES (?, ?, ?, ?)`, [b.en, b.si, b.ta, b.icon]);
        }
      }
    });

  });
}

module.exports = { db, initDatabase };
