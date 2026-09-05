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

// Core Express Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite DB
initDatabase();

// HTTP Security Headers Middleware (OWASP Security Hardening)
app.use((req, res, next) => {
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(self), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com; font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:; img-src 'self' data: blob: https:; connect-src 'self';");
  next();
});

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

function logAdminAuditAction(username, role, actionName, targetUser, details, ip) {
  let cleanIp = ip ? String(ip).replace('::ffff:', '') : '127.0.0.1';
  if (cleanIp === '::1') cleanIp = '127.0.0.1';
  db.run(
    `INSERT INTO admin_audit_logs (admin_username, admin_role, action_name, target_user, details, ip_address) VALUES (?, ?, ?, ?, ?, ?)`,
    [username || 'SYSTEM', role || 'UNKNOWN', actionName, targetUser || '-', details || '-', cleanIp],
    (err) => {
      if (err) console.error('Audit Log Error:', err.message);
    }
  );
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

// Rate Limiting & Anti-Spam Safeguards
const registrationIpTracker = new Map();

function checkRegistrationRateLimit(ip) {
  const now = Date.now();
  const windowMs = 15 * 60 * 1000; // 15 minutes window
  const maxAttempts = 6; // Max 6 pass creations per 15 minutes per IP

  let record = registrationIpTracker.get(ip);
  if (!record || now - record.startTime > windowMs) {
    registrationIpTracker.set(ip, { count: 1, startTime: now });
    return false;
  }

  record.count += 1;
  if (record.count > maxAttempts) {
    return true; // Exceeded limit!
  }
  return false;
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
      logAdminAuditAction(cleanUsername, 'GUEST/UNKNOWN', 'LOGIN_FAILED', cleanUsername, 'Invalid credentials - User not found', req.ip);
      return res.status(401).json({ error: 'Invalid credentials. Please check your username and password.\nපරිශීලක නමය හෝ මුරපදය වැරදියි!' });
    }

    const validPassword = await bcrypt.compare(cleanPassword, user.password_hash);
    if (!validPassword) {
      logAdminAuditAction(user.username, user.role, 'LOGIN_FAILED', user.username, 'Invalid credentials - Incorrect password attempt', req.ip);
      return res.status(401).json({ error: 'Invalid credentials. Please check your username and password.\nපරිශීලක නමය හෝ මුරපදය වැරදියි!' });
    }

    logAdminAuditAction(user.username, user.role, 'LOGIN_SUCCESS', user.username, `Successful session started for ${user.display_name || user.username}`, req.ip);

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

// 1.1 User Logout (Audit Trail)
app.post('/api/logout', authenticateToken, (req, res) => {
  logAdminAuditAction(req.user.username, req.user.role, 'LOGOUT', req.user.username, `User logged out of session`, req.ip);
  res.json({ message: 'Logged out successfully' });
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

// 3. Visitor Self Registration (Public - Secured with Anti-Spam & Rate Limits)
app.post('/api/visitors/register', async (req, res) => {
  const { person_name, nic_number, mobile_number, vehicle_number, branch_name, purpose, honeypot_field } = req.body;

  // 1. Anti-Bot Honeypot Check
  if (honeypot_field) {
    console.log('[Security] Automated bot pass creation attempt blocked via honeypot.');
    return res.status(201).json({ message: 'Registration received' });
  }

  // 2. IP Rate Limiting (Max 6 passes per IP per 15 minutes)
  const clientIp = req.ip || req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
  if (checkRegistrationRateLimit(clientIp)) {
    return res.status(429).json({
      error: 'Too many pass creation requests from your device. Please wait 15 minutes before creating another pass. / වැඩි වාර ගණනක් පාස් සෑදීමට උත්සාහ කර ඇත. කරුණාකර විනාඩි 15කින් පසු නැවත උත්සාහ කරන්න.'
    });
  }

  if (!person_name || !nic_number || !branch_name) {
    return res.status(400).json({ error: 'Name, NIC, and Target Branch are required' });
  }

  const cleanNic = nic_number.trim().toUpperCase();

  // 3. Same NIC Active Duplicate Pass Lockout for Today
  db.get(
    `SELECT * FROM passes WHERE nic_number = ? AND status IN ('PENDING_VERIFICATION', 'CHECKED_IN') AND DATE(created_at) = DATE('now', 'localtime')`,
    [cleanNic],
    (existErr, existingPass) => {
      if (existingPass) {
        return res.status(400).json({
          error: `An active pass (${existingPass.pass_code}) already exists for NIC ${cleanNic} today. / මෙම හැඳුනුම්පත් අංකය සඳහා අද දිනට වලංගු පාස් එකක් (${existingPass.pass_code}) දැනටමත් සාදා ඇත.`
        });
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

          db.run(sql, [passCode, person_name, cleanNic, mobile_number, formattedVeh, branch_name, purpose || 'General Visit', dailyNo], function (err) {
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
                nic_number: cleanNic,
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
    }
  );
});

// 4. Get Pass Details & QR Code
app.get('/api/passes/:code', async (req, res) => {
  const rawCode = req.params.code.trim();
  const searchCode = rawCode.toUpperCase();
  const partialCode = `%${searchCode}%`;

  db.get(`
    SELECT * FROM passes 
    WHERE UPPER(pass_code) = ? OR pass_code LIKE ? OR UPPER(rfid_card_uid) = ?
    ORDER BY id DESC LIMIT 1
  `, [searchCode, partialCode, searchCode], async (err, pass) => {
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
  if (!code) return res.status(400).json({ error: 'Pass code, NIC, or RFID card required' });

  const rawCode = code.trim();
  const searchCode = rawCode.toUpperCase();
  const partialCode = `%${searchCode}%`;

  db.get(`
    SELECT * FROM passes 
    WHERE UPPER(pass_code) = ? OR UPPER(pass_code) LIKE ? OR UPPER(nic_number) = ? OR UPPER(rfid_card_uid) = ?
    ORDER BY id DESC LIMIT 1
  `, [searchCode, partialCode, searchCode, searchCode], (err, pass) => {
    if (err || !pass) {
      return res.status(404).json({ error: `No pass record found for "${rawCode}". Please verify pass code/NIC/RFID or issue a new pass.` });
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
    WHERE UPPER(pass_code) = ? OR pass_code LIKE ? OR UPPER(rfid_card_uid) = ?
    ORDER BY id DESC LIMIT 1
  `, [searchCode, partialCode, searchCode], (err, pass) => {
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
  const { category, person_name, nic_number, mobile_number, vehicle_number, branch_name, purpose, access_zones, valid_days, valid_from, valid_to, rfid_card_uid } = req.body;
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

  const cleanRfid = (category === 'STAFF' && rfid_card_uid && rfid_card_uid.trim()) ? rfid_card_uid.trim() : null;

  // Validate RFID uniqueness if provided
  if (cleanRfid) {
    const existingRfid = await new Promise(resolve => {
      db.get('SELECT id, person_name, pass_code FROM passes WHERE UPPER(rfid_card_uid) = ?', [cleanRfid.toUpperCase()], (err, row) => resolve(row));
    });
    if (existingRfid) {
      return res.status(400).json({ error: `RFID Card "${cleanRfid}" is already assigned to ${existingRfid.person_name} (${existingRfid.pass_code})` });
    }
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
      INSERT INTO passes (pass_code, category, person_name, nic_number, mobile_number, vehicle_number, branch_name, purpose, access_zones, valid_from, valid_to, status, created_by, rfid_card_uid)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
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
      req.user.username,
      cleanRfid
    ], function (err) {
      if (err) {
        console.error('Pass creation DB error:', err);
        return res.status(500).json({ error: 'Pass creation failed' });
      }

      if (cleanRfid) {
        logAdminAuditAction(req.user.username, req.user.role, 'ENROLL_STAFF_RFID', person_name, `Issued Staff Pass ${passCode} with RFID: ${cleanRfid}`, req.ip);
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
          rfid_card_uid: cleanRfid,
          qr_code: qrDataUrl
        }
      });
    });
  } catch (qrErr) {
    res.status(500).json({ error: 'QR Code Generation failed' });
  }
});

// 7.1 Link / Update RFID Card for Existing Staff Pass (Authenticated HR Admin or Super Admin)
app.post('/api/branch/passes/:id/link-rfid', authenticateToken, async (req, res) => {
  const userRole = req.user.role;
  if (!['HR_ADMIN', 'SUPER_ADMIN'].includes(userRole)) {
    return res.status(403).json({ error: 'Permission denied: HR Admin or Super Admin access required' });
  }

  const passId = parseInt(req.params.id, 10);
  const { rfid_card_uid } = req.body;
  const cleanRfid = (rfid_card_uid && rfid_card_uid.trim()) ? rfid_card_uid.trim() : null;

  db.get('SELECT * FROM passes WHERE id = ?', [passId], async (err, pass) => {
    if (err || !pass) return res.status(404).json({ error: 'Pass record not found' });
    if (pass.category !== 'STAFF') {
      return res.status(400).json({ error: 'RFID card assignment is exclusively permitted for Internal Staff passes' });
    }

    if (cleanRfid) {
      const existing = await new Promise(resolve => {
        db.get('SELECT id, person_name, pass_code FROM passes WHERE UPPER(rfid_card_uid) = ? AND id != ?', [cleanRfid.toUpperCase(), passId], (e, row) => resolve(row));
      });
      if (existing) {
        return res.status(400).json({ error: `RFID Card "${cleanRfid}" is already assigned to ${existing.person_name} (${existing.pass_code})` });
      }
    }

    db.run('UPDATE passes SET rfid_card_uid = ? WHERE id = ?', [cleanRfid, passId], function(uErr) {
      if (uErr) return res.status(500).json({ error: 'Failed to update RFID card assignment' });
      logAdminAuditAction(req.user.username, req.user.role, 'LINK_STAFF_RFID', pass.person_name, `Linked RFID: ${cleanRfid || 'UNASSIGNED'} to ${pass.pass_code}`, req.ip);
      res.json({
        message: cleanRfid ? `RFID Card "${cleanRfid}" successfully assigned to ${pass.person_name}` : `RFID Card unassigned from ${pass.person_name}`,
        rfid_card_uid: cleanRfid
      });
    });
  });
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
    logAdminAuditAction(req.user.username, req.user.role, 'ADD_BRANCH', name_en, `Branch Card Added: ${name_si}`, req.ip);
    res.json({ message: 'Branch added successfully', id: this.lastID });
  });
});

app.delete('/api/admin/branches/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Super Admin access required' });
  db.run('DELETE FROM branches WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Error deleting branch' });
    logAdminAuditAction(req.user.username, req.user.role, 'DELETE_BRANCH', String(req.params.id), 'Department branch card deleted', req.ip);
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
    logAdminAuditAction(req.user.username, req.user.role, 'ADD_PURPOSE', purpose_en, `Purpose Card Added for Branch #${branch_id}`, req.ip);
    res.json({ message: 'Purpose option added successfully', id: this.lastID });
  });
});

app.delete('/api/admin/purposes/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') return res.status(403).json({ error: 'Super Admin access required' });
  db.run('DELETE FROM visit_purposes WHERE id = ?', [req.params.id], function(err) {
    if (err) return res.status(500).json({ error: 'Error deleting purpose option' });
    logAdminAuditAction(req.user.username, req.user.role, 'DELETE_PURPOSE', String(req.params.id), 'Visit purpose choice card deleted', req.ip);
    res.json({ message: 'Purpose option deleted successfully' });
  });
});

// 9.5 User Management & Password Reset APIs (Authenticated)
app.get('/api/admin/users', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / සුපිරි පාලක බලතල අවශ්‍යයි' });
  }
  db.all('SELECT id, username, role, branch_name, display_name, created_at FROM users ORDER BY id ASC', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to load user accounts' });
    res.json({ users: rows });
  });
});

app.post('/api/admin/users/create', authenticateToken, async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / සුපිරි පාලක බලතල අවශ්‍යයි' });
  }

  const { username, password, role, branch_name, display_name } = req.body;
  if (!username || !password || !role || !display_name) {
    return res.status(400).json({ error: 'Username, password, role, and display name are required' });
  }

  const cleanUsername = username.trim().toLowerCase();

  db.get('SELECT id FROM users WHERE LOWER(username) = ?', [cleanUsername], async (err, existing) => {
    if (existing) {
      return res.status(400).json({ error: `Username "${cleanUsername}" is already in use.` });
    }

    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(password.trim(), salt);
    const branch = branch_name ? branch_name.trim() : 'Department Branch';

    db.run(
      `INSERT INTO users (username, password_hash, role, branch_name, display_name) VALUES (?, ?, ?, ?, ?)`,
      [cleanUsername, password_hash, role, branch, display_name.trim()],
      function(err) {
        if (err) return res.status(500).json({ error: 'Failed to create user account' });
        logAdminAuditAction(req.user.username, req.user.role, 'CREATE_USER', cleanUsername, `Role: ${role}, Display: ${display_name.trim()}`, req.ip);
        res.json({ message: 'User account created successfully', userId: this.lastID });
      }
    );
  });
});

app.post('/api/admin/users/reset-password', authenticateToken, async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / සුපිරි පාලක බලතල අවශ්‍යයි' });
  }

  const { userId, newPassword } = req.body;
  if (!userId || !newPassword || newPassword.trim().length < 4) {
    return res.status(400).json({ error: 'Valid user ID and new password (at least 4 characters) are required' });
  }

  db.get('SELECT username FROM users WHERE id = ?', [userId], async (uErr, uRow) => {
    const targetUsername = uRow ? uRow.username : String(userId);
    const salt = await bcrypt.genSalt(10);
    const password_hash = await bcrypt.hash(newPassword.trim(), salt);

    db.run('UPDATE users SET password_hash = ? WHERE id = ?', [password_hash, userId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to reset password' });
      if (this.changes === 0) return res.status(404).json({ error: 'User account not found' });
      logAdminAuditAction(req.user.username, req.user.role, 'RESET_PASSWORD', targetUsername, 'Password reset by admin', req.ip);
      res.json({ message: 'Password reset successfully' });
    });
  });
});

app.delete('/api/admin/users/:id', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / සුපිරි පාලක බලතල අවශ්‍යයි' });
  }

  const targetId = parseInt(req.params.id, 10);
  if (targetId === req.user.id) {
    return res.status(400).json({ error: 'Cannot delete your own active Super Admin account' });
  }

  db.get('SELECT username FROM users WHERE id = ?', [targetId], (uErr, uRow) => {
    const targetUsername = uRow ? uRow.username : String(targetId);
    db.run('DELETE FROM users WHERE id = ?', [targetId], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to delete user account' });
      if (this.changes === 0) return res.status(404).json({ error: 'User account not found' });
      logAdminAuditAction(req.user.username, req.user.role, 'DELETE_USER', targetUsername, 'User account deleted', req.ip);
      res.json({ message: 'User account deleted successfully' });
    });
  });
});

app.post('/api/user/change-password', authenticateToken, async (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword || newPassword.trim().length < 4) {
    return res.status(400).json({ error: 'Current password and new password (at least 4 chars) are required' });
  }

  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], async (err, user) => {
    if (err || !user) return res.status(404).json({ error: 'User account not found' });

    const isValid = await bcrypt.compare(currentPassword.trim(), user.password_hash);
    if (!isValid) {
      return res.status(401).json({ error: 'Current password is incorrect / පවතින මුරපදය වැරදියි!' });
    }

    const salt = await bcrypt.genSalt(10);
    const new_hash = await bcrypt.hash(newPassword.trim(), salt);

    db.run('UPDATE users SET password_hash = ? WHERE id = ?', [new_hash, req.user.id], function(err) {
      if (err) return res.status(500).json({ error: 'Failed to change password' });
      logAdminAuditAction(user.username, user.role, 'CHANGE_PASSWORD_SELF', user.username, 'Changed own password', req.ip);
      res.json({ message: 'Password updated successfully / මුරපදය සාර්ථකව වෙනස් කරන ලදී' });
    });
  });
});

// 9.8 Administrative Security Audit Logs API (Authenticated Super Admin)
app.get('/api/admin/audit-logs', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin access required for security audit logs' });
  }
  db.all('SELECT * FROM admin_audit_logs ORDER BY id DESC LIMIT 50', [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch audit logs' });
    res.json({ audit_logs: rows || [] });
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

          logAdminAuditAction(req.user.username, req.user.role, 'EXPORT_DB_BACKUP', '-', 'Full JSON Database Backup Downloaded', req.ip);
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
