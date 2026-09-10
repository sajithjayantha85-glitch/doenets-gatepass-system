const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');
const { createClient } = require('@libsql/client');
const { Pool } = require('pg');

let pgPool = null;
let tursoClient = null;

function cleanEnv(val) {
  if (!val || typeof val !== 'string') return '';
  let str = val.trim();
  if ((str.startsWith('"') && str.endsWith('"')) || (str.startsWith("'") && str.endsWith("'"))) {
    str = str.slice(1, -1).trim();
  }
  return str;
}

const rawDatabaseUrl = cleanEnv(process.env.DATABASE_URL);
const rawPostgresUrl = cleanEnv(process.env.POSTGRES_URL);
const rawTursoUrl = cleanEnv(process.env.TURSO_DATABASE_URL) || 
                     cleanEnv(process.env.TURSO_URL) || 
                     cleanEnv(process.env.LIBSQL_URL);
const rawTursoToken = cleanEnv(process.env.TURSO_AUTH_TOKEN) || 
                      cleanEnv(process.env.TURSO_TOKEN) || 
                      cleanEnv(process.env.LIBSQL_AUTH_TOKEN);

let tursoUrl = '';
let tursoToken = rawTursoToken;
let pgUrl = '';

// Check if Turso is configured directly or via DATABASE_URL
if (rawTursoUrl) {
  tursoUrl = rawTursoUrl;
} else if (rawDatabaseUrl && (rawDatabaseUrl.startsWith('libsql://') || rawDatabaseUrl.includes('turso.io'))) {
  tursoUrl = rawDatabaseUrl;
}

// Render PostgreSQL Internal URL for gatepass-db
const renderPgInternalUrl = 'postgresql://gatepass_user:67vka3eqT6dS3wONrnkawswRT95fPOJv@dpg-dadcip0jo6nc73e0afr0-a/gatepass_db_s3bc';

// Check if PostgreSQL is configured (only if not Turso)
if (!tursoUrl) {
  if (rawPostgresUrl && (rawPostgresUrl.startsWith('postgres://') || rawPostgresUrl.startsWith('postgresql://'))) {
    pgUrl = rawPostgresUrl;
  } else if (rawDatabaseUrl && (rawDatabaseUrl.startsWith('postgres://') || rawDatabaseUrl.startsWith('postgresql://'))) {
    pgUrl = rawDatabaseUrl;
  } else if (process.env.RENDER) {
    // Automatically connect to gatepass-db when hosted on Render
    pgUrl = renderPgInternalUrl;
  }
}

const dbStatus = {
  driver: 'SQLITE_LOCAL',
  provider: 'Local SQLite (gatepass.db)',
  isCloud: false,
  isPersistent: true,
  connected: false,
  url: null,
  error: null,
  lastChecked: new Date().toISOString()
};

if (pgUrl) {
  console.log('Connecting to Render PostgreSQL Database...');
  pgPool = new Pool({
    connectionString: pgUrl,
    ssl: { rejectUnauthorized: false }
  });
  dbStatus.driver = 'POSTGRESQL';
  dbStatus.provider = 'Render PostgreSQL Cloud Database';
  dbStatus.isCloud = true;
  dbStatus.isPersistent = true;
  dbStatus.url = pgUrl.replace(/:[^:@]+@/, ':***@');
} else if (tursoUrl) {
  console.log('Connecting to Turso Cloud SQLite Database:', tursoUrl);
  tursoClient = createClient({
    url: tursoUrl,
    authToken: tursoToken || undefined
  });
  dbStatus.driver = 'TURSO_LIBSQL';
  dbStatus.provider = 'Turso Cloud SQLite Database';
  dbStatus.isCloud = true;
  dbStatus.isPersistent = true;
  dbStatus.url = tursoUrl;
  if (!tursoToken && !tursoUrl.includes('authToken=')) {
    dbStatus.error = 'Warning: TURSO_AUTH_TOKEN is missing. Please set TURSO_AUTH_TOKEN in Render Environment.';
    console.warn('⚠️ Warning: TURSO_AUTH_TOKEN is not set in environment variables.');
  }
} else {
  console.log('Using Local SQLite Database file (gatepass.db).');
  dbStatus.driver = 'SQLITE_LOCAL';
  dbStatus.provider = 'Local SQLite (gatepass.db)';
  dbStatus.isCloud = false;
  dbStatus.isPersistent = true;
  dbStatus.connected = true;
}

async function testConnection() {
  dbStatus.lastChecked = new Date().toISOString();
  if (pgPool) {
    try {
      await pgPool.query('SELECT 1');
      dbStatus.connected = true;
      dbStatus.error = null;
      console.log('✓ Render PostgreSQL Database connected successfully.');
    } catch (err) {
      dbStatus.connected = false;
      dbStatus.error = 'PostgreSQL Connection Error: ' + err.message;
      console.error('✗ Render PostgreSQL connection error:', err.message);
    }
  } else if (tursoClient) {
    try {
      await tursoClient.execute('SELECT 1');
      dbStatus.connected = true;
      dbStatus.error = null;
      console.log('✓ Turso Cloud SQLite Database connected successfully.');
    } catch (err) {
      dbStatus.connected = false;
      dbStatus.error = 'Turso Connection Error: ' + err.message;
      console.error('✗ Turso Cloud SQLite connection error:', err.message);
    }
  } else {
    dbStatus.connected = true;
    dbStatus.error = null;
  }
}

async function getDbStatus(forceCheck = false) {
  if (forceCheck) {
    await testConnection();
  }
  return {
    ...dbStatus,
    timestamp: new Date().toISOString()
  };
}

function convertSqlForPostgres(sql) {
  let paramIndex = 1;
  let converted = sql.replace(/\?/g, () => `$${paramIndex++}`);
  
  // Replace SQLite specific types and functions for Postgres
  converted = converted.replace(/INTEGER PRIMARY KEY AUTOINCREMENT/gi, 'SERIAL PRIMARY KEY');
  converted = converted.replace(/\bDATETIME\b/gi, 'TIMESTAMP');
  converted = converted.replace(/DATE\('now',\s*'localtime'\)/gi, 'CURRENT_DATE');
  converted = converted.replace(/DATE\('now'\)/gi, 'CURRENT_DATE');
  converted = converted.replace(/DATE\(([^,)]+),\s*'localtime'\)/gi, 'DATE($1)');
  converted = converted.replace(/datetime\('now',\s*'-30 days'\)/gi, "NOW() - INTERVAL '30 days'");

  return converted;
}

const dbPath = path.resolve(__dirname, 'gatepass.db');
const localDb = new sqlite3.Database(dbPath);

// Unified Database Adapter (Supports Render PostgreSQL, Turso SQLite, and Local SQLite)
const db = {
  get(sql, params = [], cb) {
    if (pgPool) {
      const pgSql = convertSqlForPostgres(sql);
      pgPool.query(pgSql, params)
        .then(res => cb(null, res.rows.length > 0 ? res.rows[0] : null))
        .catch(err => cb(err, null));
    } else if (tursoClient) {
      tursoClient.execute({ sql, args: params })
        .then(res => cb(null, res.rows.length > 0 ? res.rows[0] : null))
        .catch(err => cb(err, null));
    } else {
      localDb.get(sql, params, cb);
    }
  },

  all(sql, params = [], cb) {
    if (pgPool) {
      const pgSql = convertSqlForPostgres(sql);
      pgPool.query(pgSql, params)
        .then(res => cb(null, res.rows))
        .catch(err => cb(err, null));
    } else if (tursoClient) {
      tursoClient.execute({ sql, args: params })
        .then(res => cb(null, res.rows))
        .catch(err => cb(err, null));
    } else {
      localDb.all(sql, params, cb);
    }
  },

  run(sql, params = [], cb) {
    if (pgPool) {
      let pgSql = convertSqlForPostgres(sql);
      if (/^INSERT\s+INTO/i.test(pgSql) && !/RETURNING/i.test(pgSql)) {
        pgSql += ' RETURNING id';
      }
      pgPool.query(pgSql, params)
        .then(res => {
          const fakeThis = {
            lastID: res.rows && res.rows[0] && res.rows[0].id ? Number(res.rows[0].id) : 0,
            changes: res.rowCount || 0
          };
          if (cb) cb.call(fakeThis, null);
        })
        .catch(err => {
          if (cb) cb(err);
        });
    } else if (tursoClient) {
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
    if (pgPool || tursoClient) {
      cb();
    } else {
      localDb.serialize(cb);
    }
  }
};

async function initDatabase() {
  try {
    await testConnection();

    // Promisified execution helpers for sequential execution
    const runAsync = (sql, params = []) => new Promise((resolve) => {
      db.run(sql, params, function(err) {
        if (err) resolve({ error: err });
        else resolve({ result: this });
      });
    });

    const getAsync = (sql, params = []) => new Promise((resolve) => {
      db.get(sql, params, (err, row) => {
        if (err) resolve(null);
        else resolve(row);
      });
    });

    // 1. Users Table
    await runAsync(`
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
    await runAsync(`
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
        rfid_card_uid TEXT,
        created_by TEXT DEFAULT 'SELF_REGISTRATION',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // Migration: Add rfid_card_uid to passes table if missing, and create index
    await runAsync("ALTER TABLE passes ADD COLUMN rfid_card_uid TEXT");
    await runAsync("CREATE INDEX IF NOT EXISTS idx_passes_rfid ON passes (rfid_card_uid)");

    // 3. Gate Logs Table
    await runAsync(`
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
    await runAsync(`
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
    await runAsync(`
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

    // 6. Administrative Security Audit Logs Table
    await runAsync(`
      CREATE TABLE IF NOT EXISTS admin_audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_username TEXT NOT NULL,
        admin_role TEXT NOT NULL,
        action_name TEXT NOT NULL,
        target_user TEXT,
        details TEXT,
        ip_address TEXT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
      )
    `);

    // 30-Day Public Visitor Pass Auto-Purge Cleanup (Keeps Database Light)
    await runAsync("DELETE FROM passes WHERE category = 'VISITOR' AND created_at < datetime('now', '-30 days')");

    // Seed default users if empty
    const userRow = await getAsync('SELECT COUNT(*) as count FROM users');
    const userCount = userRow ? Number(userRow.count) : 0;
    if (userCount === 0) {
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
        await runAsync(`INSERT INTO users (username, password_hash, role, branch_name, display_name) VALUES (?, ?, ?, ?, ?)`, [acc.username, hash, acc.role, acc.branch_name, acc.display_name]);
      }
    }

    // Seed default Branches if empty
    const branchRow = await getAsync('SELECT COUNT(*) as count FROM branches');
    const branchCount = branchRow ? Number(branchRow.count) : 0;
    if (branchCount === 0) {
      console.log('Seeding default department branches...');
      const defaultBranches = [
        { en: 'Certificate Branch', si: 'සහතික පත්‍ර අංශය', ta: 'சான்றிதழ் பிரிவு', icon: 'fa-certificate' },
        { en: 'Inquiry & Public Relations', si: 'විමසීම් සහ මහජන සම්බන්ධතා අංශය', ta: 'විசாரணைப் பிரிவு', icon: 'fa-headset' },
        { en: 'Confidential Branch', si: 'රහස්‍ය අංශය', ta: 'ரகசியப் பிரிவு', icon: 'fa-user-ninja' },
        { en: 'Evaluation Branch', si: 'ඇගයීම් ශාඛාව', ta: 'மதிப்பீட்டுப் பிரிவு', icon: 'fa-file-pen' },
        { en: 'Establishment HR', si: 'ආයතන ශාඛාව', ta: 'நிறுவனப் பிரிவு', icon: 'fa-id-card' },
        { en: 'Accounts Branch', si: 'ගිණුම් ශාඛාව', ta: 'கණக்குப் பிரிவு', icon: 'fa-calculator' },
        { en: 'Main Administration', si: 'පරිපාලන අංශය', ta: 'முதன்மை நிர்வாகப் பிரிவு', icon: 'fa-building-columns' }
      ];

      for (const b of defaultBranches) {
        await runAsync(`INSERT INTO branches (name_en, name_si, name_ta, icon) VALUES (?, ?, ?, ?)`, [b.en, b.si, b.ta, b.icon]);
      }
    }

    // Seed default Visit Purposes if empty
    const purposeRow = await getAsync('SELECT COUNT(*) as count FROM visit_purposes');
    const purposeCount = purposeRow ? Number(purposeRow.count) : 0;
    if (purposeCount === 0) {
      console.log('Seeding default visit purposes...');
      const defaultPurposes = [
        { branch_id: 1, en: 'Certificate Verification', si: 'සහතික පත්‍ර සත්‍යාපනය', ta: 'சான்றிதழ் சரிபார்ப்பு', icon: 'fa-certificate' },
        { branch_id: 1, en: 'Issue Duplicate Certificate', si: 'පිටපත් සහතික පත්‍ර ලබාගැනීම', ta: 'இரண்டாம் பிரதி சான்றிதழ் பெற', icon: 'fa-copy' },
        { branch_id: 2, en: 'General Inquiry', si: 'සාමාන්‍ය විමසීම්', ta: 'பொது விசாரணை', icon: 'fa-circle-question' },
        { branch_id: 2, en: 'Exam Results Inquiry', si: 'විභාග ප්‍රතිඵල විමසීම්', ta: 'தேர்வு முடிவுகள் விசாரணை', icon: 'fa-square-poll-vertical' },
        { branch_id: 3, en: 'Confidential Official Duty', si: 'නිල රහස්‍ය කාර්යයන්', ta: 'அதிகாரப்பூர்வ ரகசிய பணி', icon: 'fa-user-secret' },
        { branch_id: 4, en: 'Answer Script Evaluation Duty', si: 'උත්තර පත්‍ර පරීක්ෂක කාර්යයන්', ta: 'விடைத்தாள் மதிப்பீட்டு பணி', icon: 'fa-pen-to-square' },
        { branch_id: 5, en: 'HR & Service Matters', si: 'පිරිස් හා සේවා කටයුතු', ta: 'மனிதவள மற்றும் சேவை விவகாரங்கள்', icon: 'fa-id-badge' },
        { branch_id: 6, en: 'Payments & Bill Settlement', si: 'ගෙවීම් හා බිල්පත් කටයුතු', ta: 'கட்டணம் மற்றும் பில் கொடுப்பනவு', icon: 'fa-money-bill-wave' },
        { branch_id: 7, en: 'Administrative Duty', si: 'පරිපාලන සහ නිල හමුවීම්', ta: 'நிர்வாக மற்றும் உத்தியோகபூர்வ சந்திப்புகள்', icon: 'fa-building' },
        { branch_id: 0, en: 'Official Meeting', si: 'නිල හමුවීම', ta: 'அதிகாரப்பூர்வ சந்திப்பு', icon: 'fa-handshake' },
        { branch_id: 0, en: 'Document Submission', si: 'ලේඛන භාරදීම', ta: 'ஆவணங்கள் சமர்ப்பித்தல்', icon: 'fa-folder-open' }
      ];

      for (const p of defaultPurposes) {
        await runAsync(`INSERT INTO visit_purposes (branch_id, purpose_en, purpose_si, purpose_ta, icon) VALUES (?, ?, ?, ?, ?)`, [p.branch_id, p.en, p.si, p.ta, p.icon]);
      }
    }
    console.log('Database initialization completed successfully.');
  } catch (err) {
    console.error('Database initialization error:', err);
  }
}

module.exports = { db, initDatabase, getDbStatus };
