const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

const dbPath = path.resolve(__dirname, 'gatepass.db');
const db = new sqlite3.Database(dbPath);

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

    // Ensure daily_no and vehicle_number columns exist in existing database
    db.run(`ALTER TABLE passes ADD COLUMN daily_no INTEGER DEFAULT 1`, (err) => {
      // Column may already exist
    });

    db.run(`ALTER TABLE passes ADD COLUMN vehicle_number TEXT`, (err) => {
      // Column may already exist
    });

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

    // Re-create visit_purposes table to ensure branch_id column exists
    db.run(`DROP TABLE IF EXISTS visit_purposes`);

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

    // Seed default users if empty
    db.get('SELECT COUNT(*) as count FROM users', [], async (err, row) => {
      if (err) return;
      if (row.count === 0) {
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
      if (row.count === 0) {
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

    // Seed default Branch-Linked Purposes
    console.log('Seeding branch-linked visit purposes...');
    const defaultPurposes = [
      // Certificate Branch (branch_id = 1)
      { branch_id: 1, en: 'Collect G.C.E. O/L Certificate', si: 'සාමාන්‍ය පෙළ සහතිකය ලබාගැනීමට', ta: 'சாதாரண தர சான்றிதழ் பெற', icon: 'fa-graduation-cap' },
      { branch_id: 1, en: 'Collect G.C.E. A/L Certificate', si: 'උසස් පෙළ සහතිකය ලබාගැනීමට', ta: 'உயர்தர சான்றிதழ் பெற', icon: 'fa-award' },
      { branch_id: 1, en: 'Apply for Duplicate Certificate', si: 'පිටපත් සහතිකය සඳහා ඉල්ලුම් කිරීමට', ta: 'இரண்டாம் படி சான்றிதழ் பெற', icon: 'fa-copy' },
      { branch_id: 1, en: 'Certificate Verification / True Copy', si: 'සහතික පත්‍ර සත්‍යාපනය සඳහා', ta: 'சான்றிதழ் சரிபார்ப்பு', icon: 'fa-circle-check' },

      // Inquiry Branch (branch_id = 2)
      { branch_id: 2, en: 'Exam Results Inquiry', si: 'විභාග ප්‍රතිඵල විමසීමට', ta: 'தேர்வு முடிவுகள் விசாரணை', icon: 'fa-square-poll-vertical' },
      { branch_id: 2, en: 'Index Number / Admission Query', si: 'විභාග අංකය පිළිබඳ විමසීමට', ta: 'சுட்டெண் விசாரணை', icon: 'fa-id-badge' },
      { branch_id: 2, en: 'Name / NIC Correction Inquiry', si: 'නම හෝ හැඳුනුම්පත් සංශෝධන සඳහා', ta: 'பெயர் திருத்தம்', icon: 'fa-user-pen' },

      // Confidential Branch (branch_id = 3)
      { branch_id: 3, en: 'Paper Setting Panel Duty', si: 'ප්‍රශ්න පත්‍ර සම්පාදන රාජකාරි', ta: 'வினாத்தாள் தயாரிப்பு பணி', icon: 'fa-pen-nib' },
      { branch_id: 3, en: 'Paper Moderation Panel Meeting', si: 'ප්‍රශ්න පත්‍ර සමප්‍රදේශන මණ්ඩල රැස්වීම', ta: 'வினාத்தாள் மதிப்பாய்வு', icon: 'fa-users-gear' },
      { branch_id: 3, en: 'Confidential Printing / Proofreading', si: 'රහස්‍ය මුද්‍රණ පරීක්ෂා කිරීම්', ta: 'ரகசிய அச்சுப் பணி', icon: 'fa-print' },

      // Evaluation Branch (branch_id = 4)
      { branch_id: 4, en: 'Answer Script Marking Duty', si: 'උත්තර පත්‍ර ඇගයීම් රාජකාරි', ta: 'விடைத்தாள் மதிப்பீட்டு பணி', icon: 'fa-check-double' },
      { branch_id: 4, en: 'Chief Examiner Meeting', si: 'ප්‍රධාන පරීක්ෂක රැස්වීම සඳහා', ta: 'முதன்மை தேர்வாளர் சந்திப்பு', icon: 'fa-user-tie' },
      { branch_id: 4, en: 'Evaluation Mark Sheets Submission', si: 'ඇගයීම් ලකුණු පත්‍ර භාරදීමට', ta: 'மதிப்பெண் தாள் சமர்ப்பிப்பு', icon: 'fa-file-signature' },

      // Establishment HR (branch_id = 5)
      { branch_id: 5, en: 'Staff Service Record / HR Query', si: 'සේවක ආයතනික කරුණු සඳහා', ta: 'பணியாளர் சேவை விசாரணை', icon: 'fa-address-card' },
      { branch_id: 5, en: 'Staff Salary / Pension Query', si: 'වැටුප් හෝ විශ්‍රාම වැටුප් විමසීමට', ta: 'சம்பள விசாரணை', icon: 'fa-money-bill-wave' },
      { branch_id: 5, en: 'Official Transfer / Appointment', si: 'ස්ථාන මාරු / පත්වීම් කරුණු සඳහා', ta: 'பணிமாற்றம் / நியமனம்', icon: 'fa-briefcase' },

      // Accounts Branch (branch_id = 6)
      { branch_id: 6, en: 'Exam Fee Payment / Voucher Deposit', si: 'විභාග ගාස්තු / වවුචර් ගෙවීමට', ta: 'தேர்வு கட்டணம் செலுத்துதல்', icon: 'fa-receipt' },
      { branch_id: 6, en: 'Financial Refund / Allowance Query', si: 'මුදල් ප්‍රතිපූර්ණය / දීමනා විමසීමට', ta: 'பணத் திரும்பப்பெறுதல்', icon: 'fa-hand-holding-dollar' },

      // Main Administration (branch_id = 7)
      { branch_id: 7, en: 'Official Meeting with Officers', si: 'නිලධාරීන් හමුවීමේ සාකච්ඡාවට', ta: 'அதிகாரிகளுடன் சந்திப்பு', icon: 'fa-handshake' },
      { branch_id: 7, en: 'Official Document / Tender Submission', si: 'නිල ලේඛන / ටෙන්ඩර් භාරදීමට', ta: 'ஆவண சமர்ப்பிப்பு', icon: 'fa-file-lines' }
    ];

    for (const p of defaultPurposes) {
      db.run(`INSERT INTO visit_purposes (branch_id, purpose_en, purpose_si, purpose_ta, icon) VALUES (?, ?, ?, ?, ?)`, [p.branch_id, p.en, p.si, p.ta, p.icon]);
    }

  });
}

module.exports = { db, initDatabase };
