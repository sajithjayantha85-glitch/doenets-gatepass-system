const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const path = require('path');
const { db, initDatabase } = require('./database');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'doenets_gatepass_secret_key_2026';

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite DB
initDatabase();

// Utility Functions
function generatePassCode(category) {
  const prefix = {
    VISITOR: 'DOENETS-VIS',
    CONFIDENTIAL: 'DOENETS-CONF',
    EVALUATION: 'DOENETS-EVAL',
    STAFF: 'DOENETS-STF'
  }[category] || 'DOENETS-PASS';

  const randomNum = Math.floor(100000 + Math.random() * 900000);
  return `${prefix}-${randomNum}`;
}

// Authentication Middleware
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Authentication required' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired session' });
    req.user = user;
    next();
  });
}

// --- API ROUTES ---

// 1. User Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required / පරිශීලක නමය සහ මුරපදය අවශ්‍යයි' });
  }

  const cleanUsername = username.trim().toLowerCase();
  const cleanPassword = password.trim();

  db.get('SELECT * FROM users WHERE LOWER(username) = ?', [cleanUsername], async (err, user) => {
    if (err || !user) {
      return res.status(401).json({ error: 'Invalid credentials. Please check your username and password.\nපරිශීලක නමය හෝ මුරපදය වැරදියි!' });
    }

    const validPassword = await bcrypt.compare(cleanPassword, user.password_hash);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials. Please check your username and password.\nපරිශීලක නමය හෝ මුරපදය වැරදියි!' });
    }

    const token = jwt.sign(
      { id: user.id, username: user.username, role: user.role, branch_name: user.branch_name, display_name: user.display_name },
      JWT_SECRET,
      { expiresIn: '12h' }
    );

    res.json({
      message: 'Logged in successfully',
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        branch_name: user.branch_name,
        display_name: user.display_name
      }
    });
  });
});

// 2. Public Options API: Fetch Dynamic Branches and Branch-Linked Visit Purposes
app.get('/api/options', (req, res) => {
  db.all('SELECT * FROM branches WHERE is_active = 1 ORDER BY id ASC', [], (bErr, branches) => {
    if (bErr) return res.status(500).json({ error: 'Error loading branches' });

    db.all('SELECT * FROM visit_purposes WHERE is_active = 1 ORDER BY id ASC', [], (pErr, purposes) => {
      if (pErr) return res.status(500).json({ error: 'Error loading purposes' });

      res.json({
        branches: branches || [],
        purposes: purposes || []
      });
    });
  });
});

// 3. Visitor Self Registration (Public)
app.post('/api/visitors/register', async (req, res) => {
  const { person_name, nic_number, mobile_number, vehicle_number, branch_name, purpose } = req.body;

  if (!person_name || !nic_number || !branch_name) {
    return res.status(400).json({ error: 'Name, NIC, and Target Branch are required' });
  }

  // Calculate today's daily sequential visitor number
  db.get(`SELECT COUNT(*) as count FROM passes WHERE DATE(created_at) = DATE('now', 'localtime')`, [], async (cErr, countRow) => {
    const dailyNo = (countRow && countRow.count ? countRow.count : 0) + 1;
    const formattedDailyNo = String(dailyNo).padStart(3, '0');
    const passCode = generatePassCode('VISITOR');
    const formattedVeh = vehicle_number ? vehicle_number.trim().toUpperCase() : null;

    try {
      const qrDataUrl = await QRCode.toDataURL(passCode, { margin: 2, width: 320 });

      const sql = `
        INSERT INTO passes (pass_code, category, person_name, nic_number, mobile_number, vehicle_number, branch_name, purpose, access_zones, status, created_by, daily_no)
        VALUES (?, 'VISITOR', ?, ?, ?, ?, ?, ?, 'GENERAL_VISITOR', 'PENDING_VERIFICATION', 'SELF_REGISTRATION', ?)
      `;

      db.run(sql, [passCode, person_name, nic_number.trim().toUpperCase(), mobile_number, formattedVeh, branch_name, purpose || 'General Visit', dailyNo], function (err) {
        if (err) {
          console.error('Error creating visitor pass:', err);
          return res.status(500).json({ error: 'Database insert error' });
        }

        res.status(201).json({
          message: 'Registration successful!',
          pass: {
            id: this.lastID,
            daily_no: dailyNo,
            daily_no_formatted: formattedDailyNo,
            pass_code: passCode,
            person_name,
            nic_number,
            mobile_number,
            vehicle_number: formattedVeh,
            branch_name,
            purpose,
            status: 'PENDING_VERIFICATION',
            qr_code: qrDataUrl
          }
        });
      });
    } catch (qrErr) {
      res.status(500).json({ error: 'Error generating QR code' });
    }
  });
});

// 4. Get Pass Details & QR Code
app.get('/api/passes/:code', async (req, res) => {
  const rawCode = req.params.code.trim();
  const searchCode = rawCode.toUpperCase();
  const partialCode = `%${searchCode}%`;

  db.get(`
    SELECT * FROM passes 
    WHERE UPPER(pass_code) = ? OR pass_code LIKE ?
    ORDER BY id DESC LIMIT 1
  `, [searchCode, partialCode], async (err, pass) => {
    if (err || !pass) {
      return res.status(404).json({ error: 'Pass not found' });
    }

    try {
      const qrDataUrl = await QRCode.toDataURL(pass.pass_code, { margin: 2, width: 320 });

      db.all('SELECT * FROM gate_logs WHERE UPPER(pass_code) = ? ORDER BY timestamp DESC LIMIT 5', [pass.pass_code.toUpperCase()], (logErr, logs) => {
        res.json({
          pass: {
            ...pass,
            qr_code: qrDataUrl
          },
          logs: logs || []
        });
      });
    } catch (e) {
      res.status(500).json({ error: 'QR Generation Error' });
    }
  });
});

// 5. Security Scan Lookup (Authenticated)
app.post('/api/security/scan', authenticateToken, (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Pass code or NIC required' });

  const rawCode = code.trim();
  const searchCode = rawCode.toUpperCase();
  const partialCode = `%${searchCode}%`;

  db.get(`
    SELECT * FROM passes 
    WHERE UPPER(pass_code) = ? OR UPPER(pass_code) LIKE ? OR UPPER(nic_number) = ?
    ORDER BY id DESC LIMIT 1
  `, [searchCode, partialCode, searchCode], (err, pass) => {
    if (err || !pass) {
      return res.status(404).json({ error: `No pass record found for "${rawCode}". Please verify pass code/NIC or issue a new pass.` });
    }

    db.all('SELECT * FROM gate_logs WHERE UPPER(pass_code) = ? ORDER BY timestamp DESC LIMIT 5', [pass.pass_code.toUpperCase()], (logErr, logs) => {
      res.json({
        pass,
        logs: logs || []
      });
    });
  });
});

// 6. Security Verify & Entry/Exit Action (Authenticated)
app.post('/api/security/verify-entry', authenticateToken, (req, res) => {
  const { pass_code, action_type } = req.body;

  if (!pass_code || !action_type) {
    return res.status(400).json({ error: 'Pass code and action type required' });
  }

  const rawCode = pass_code.trim();
  const searchCode = rawCode.toUpperCase();
  const partialCode = `%${searchCode}%`;

  db.get(`
    SELECT * FROM passes 
    WHERE UPPER(pass_code) = ? OR pass_code LIKE ?
    ORDER BY id DESC LIMIT 1
  `, [searchCode, partialCode], (err, pass) => {
    if (err || !pass) return res.status(404).json({ error: 'Pass not found' });

    let newStatus = pass.status;
    if (action_type === 'CHECK_IN') {
      newStatus = 'CHECKED_IN';
    } else if (action_type === 'CHECK_OUT') {
      newStatus = 'CHECKED_OUT';
    }

    db.run('UPDATE passes SET status = ? WHERE id = ?', [newStatus, pass.id], function (updateErr) {
      if (updateErr) return res.status(500).json({ error: 'Status update failed' });

      const logSql = `
        INSERT INTO gate_logs (pass_code, person_name, nic_number, category, branch_name, action_type, security_officer_name)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `;

      const officerName = req.user ? req.user.display_name : 'Security Gate';

      db.run(logSql, [pass.pass_code, pass.person_name, pass.nic_number, pass.category, pass.branch_name, action_type, officerName], function (logErr) {
        res.json({
          message: action_type === 'CHECK_IN' ? 'Entry Granted & Checked In' : 'Departure Registered & Checked Out',
          new_status: newStatus,
          pass_code: pass.pass_code,
          person_name: pass.person_name,
          timestamp: new Date().toISOString()
        });
      });
    });
  });
});

// 7. Branch Administrative Pass Creation (Role Scoped)
app.post('/api/branch/passes/create', authenticateToken, async (req, res) => {
  const { category, person_name, nic_number, mobile_number, vehicle_number, branch_name, purpose, access_zones, valid_days, valid_from, valid_to } = req.body;
  const userRole = req.user.role;

  if (category === 'CONFIDENTIAL' && !['CONFIDENTIAL_ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
    return res.status(403).json({ error: 'Permission denied for Confidential Branch' });
  }

  if (category === 'EVALUATION' && !['EVALUATION_ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
    return res.status(403).json({ error: 'Permission denied for Evaluation Branch' });
  }

  if (category === 'STAFF' && !['HR_ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
    return res.status(403).json({ error: 'Permission denied for HR Branch' });
  }

  if (!person_name || !nic_number) {
    return res.status(400).json({ error: 'Name and NIC number are required' });
  }

  const passCode = generatePassCode(category);
  const days = parseInt(valid_days, 10) || (category === 'STAFF' ? 365 : 1);
  
  let validFrom = valid_from ? new Date(valid_from) : new Date();
  let validTo = valid_to ? new Date(valid_to) : new Date(validFrom);
  if (!valid_to) {
    validTo.setDate(validTo.getDate() + days);
  }

  try {
    const qrDataUrl = await QRCode.toDataURL(passCode, { margin: 2, width: 320 });

    const sql = `
      INSERT INTO passes (pass_code, category, person_name, nic_number, mobile_number, vehicle_number, branch_name, purpose, access_zones, valid_from, valid_to, status, created_by)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?)
    `;

    const branch = branch_name || req.user.branch_name;
    const formattedVeh = vehicle_number ? vehicle_number.trim().toUpperCase() : null;
    const accessZoneVal = access_zones || (category === 'CONFIDENTIAL' ? 'CONFIDENTIAL_ZONE' : (category === 'EVALUATION' ? 'EVALUATION_ZONE' : category));

    db.run(sql, [
      passCode, 
      category, 
      person_name, 
      nic_number.trim().toUpperCase(), 
      mobile_number, 
      formattedVeh, 
      branch, 
      purpose || 'Official Duty', 
      accessZoneVal, 
      validFrom.toISOString(), 
      validTo.toISOString(), 
      req.user.username
    ], function (err) {
      if (err) {
        console.error('Pass creation DB error:', err);
        return res.status(500).json({ error: 'Pass creation failed' });
      }

      res.status(201).json({
        message: 'QR Pass issued successfully',
        pass: {
          id: this.lastID,
          pass_code: passCode,
          category,
          person_name,
          nic_number: nic_number.trim().toUpperCase(),
          mobile_number,
          vehicle_number: formattedVeh,
          branch_name: branch,
          purpose,
          access_zones: accessZoneVal,
          valid_from: validFrom.toISOString(),
          valid_to: validTo.toISOString(),
          status: 'ACTIVE',
          qr_code: qrDataUrl
        }
      });
    });
  } catch (qrErr) {
    res.status(500).json({ error: 'QR Code Generation failed' });
  }
});

// 8. Get Branch Issued Passes (Authenticated)
app.get('/api/branch/passes', authenticateToken, (req, res) => {
  const userRole = req.user.role;
  let categoryFilter = '';

  if (userRole === 'CONFIDENTIAL_ADMIN') categoryFilter = "WHERE category = 'CONFIDENTIAL'";
  else if (userRole === 'EVALUATION_ADMIN') categoryFilter = "WHERE category = 'EVALUATION'";
  else if (userRole === 'HR_ADMIN') categoryFilter = "WHERE category = 'STAFF'";

  db.all(`SELECT * FROM passes ${categoryFilter} ORDER BY created_at DESC LIMIT 100`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database fetch error' });
    res.json({ passes: rows });
  });
});

// 9. Dynamic Options Management (Admin API)
app.post('/api/admin/branches', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Super Admin access required' });
  const { name_en, name_si, name_ta, icon } = req.body;
  
  if (!name_en || !name_si || !name_ta) {
    return res.status(400).json({ error: 'All 3 language names (EN, SI, TA) are required' });
  }

  db.run('INSERT INTO branches (name_en, name_si, name_ta, icon) VALUES (?, ?, ?, ?)', [name_en, name_si, name_ta, icon || 'fa-building'], function(err) {
    if (err) return res.status(500).json({ error: 'Error adding branch' });
    res.json({ message: 'Branch added successfully', id: this.lastID });
  });
});

app.delete('/api/admin/branches/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Super Admin access required' });
  db.run('DELETE FROM branches WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Error deleting branch' });
    res.json({ message: 'Branch deleted successfully' });
  });
});

app.post('/api/admin/purposes', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Super Admin access required' });
  const { branch_id, purpose_en, purpose_si, purpose_ta, icon } = req.body;
  
  if (!purpose_en || !purpose_si || !purpose_ta) {
    return res.status(400).json({ error: 'All 3 language purpose descriptions (EN, SI, TA) are required' });
  }

  db.run('INSERT INTO visit_purposes (branch_id, purpose_en, purpose_si, purpose_ta, icon) VALUES (?, ?, ?, ?, ?)', [branch_id || 0, purpose_en, purpose_si, purpose_ta, icon || 'fa-file-lines'], function(err) {
    if (err) return res.status(500).json({ error: 'Error adding purpose option' });
    res.json({ message: 'Purpose option added successfully', id: this.lastID });
  });
});

app.delete('/api/admin/purposes/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Super Admin access required' });
  db.run('DELETE FROM visit_purposes WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Error deleting purpose option' });
    res.json({ message: 'Purpose option deleted successfully' });
  });
});

// 10. Admin Live Dashboard Statistics (Authenticated)
app.get('/api/admin/dashboard', authenticateToken, (req, res) => {
  const stats = {
    total_inside: 0,
    visitors_inside: 0,
    staff_inside: 0,
    confidential_inside: 0,
    evaluation_inside: 0
  };

  db.all("SELECT category, COUNT(*) as count FROM passes WHERE status = 'CHECKED_IN' GROUP BY category", [], (err, rows) => {
    if (!err && rows) {
      rows.forEach(r => {
        stats.total_inside += r.count;
        if (r.category === 'VISITOR') stats.visitors_inside = r.count;
        if (r.category === 'STAFF') stats.staff_inside = r.count;
        if (r.category === 'CONFIDENTIAL') stats.confidential_inside = r.count;
        if (r.category === 'EVALUATION') stats.evaluation_inside = r.count;
      });
    }

    db.all("SELECT * FROM gate_logs ORDER BY timestamp DESC LIMIT 30", [], (logErr, logs) => {
      db.all("SELECT * FROM passes WHERE status = 'CHECKED_IN' ORDER BY created_at DESC", [], (passErr, checkedInPasses) => {
        res.json({
          stats,
          recent_logs: logs || [],
          currently_inside: checkedInPasses || []
        });
      });
    });
  });
});

// 11. Full System Database Backup Export API (Authenticated Super Admin)
app.get('/api/admin/backup/export', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin access required for database backups' });
  }

  db.all('SELECT * FROM passes ORDER BY id DESC', [], (pErr, passes) => {
    db.all('SELECT * FROM gate_logs ORDER BY id DESC', [], (lErr, logs) => {
      db.all('SELECT * FROM branches ORDER BY id ASC', [], (bErr, branches) => {
        db.all('SELECT * FROM visit_purposes ORDER BY id ASC', [], (purpErr, purposes) => {
          const backupPayload = {
            system: 'Department of Examinations Sri Lanka - Gate Pass System',
            backup_timestamp: new Date().toISOString(),
            total_passes: passes ? passes.length : 0,
            total_gate_logs: logs ? logs.length : 0,
            passes: passes || [],
            gate_logs: logs || [],
            branches: branches || [],
            visit_purposes: purposes || []
          };

          const dateStr = new Date().toISOString().split('T')[0];
          res.setHeader('Content-Type', 'application/json');
          res.setHeader('Content-Disposition', `attachment; filename=DoENets_GatePass_Backup_${dateStr}.json`);
          res.send(JSON.stringify(backupPayload, null, 2));
        });
      });
    });
  });
});

// Fallback SPA Route
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Start Server
app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`Department of Examinations - Gate Pass System Server`);
  console.log(`Server running at: http://localhost:${PORT}`);
  console.log(`=======================================================`);
});
