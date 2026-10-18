const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const path = require('path');
const nodemailer = require('nodemailer');
const { db, initDatabase, getDbStatus } = require('./database');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'doenets_gatepass_secret_key_2026';
const REPORTS_API_KEY = process.env.REPORTS_API_KEY || 'doenets_executive_api_key_2026';

// Core Express Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize SQLite / Turso DB & Preload Memory Cache
initDatabase();
setTimeout(preloadPassCache, 1200);
setTimeout(loadGateSettingsFromDb, 1500);
setTimeout(loadEmailSettingsFromDb, 1800);
setInterval(checkDailyEmailSchedule, 60000);

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

// Ultra-Fast In-Memory Cache for Passes & Gate Verification (0.01ms response time)
const passCache = new Map();

function cachePass(pass) {
  if (!pass) return;
  if (pass.pass_code) passCache.set(String(pass.pass_code).toUpperCase(), pass);
  if (pass.nic_number) passCache.set(String(pass.nic_number).toUpperCase(), pass);
  if (pass.rfid_card_uid) passCache.set(String(pass.rfid_card_uid).toUpperCase(), pass);
  if (pass.employee_number) passCache.set(String(pass.employee_number).toUpperCase(), pass);
}

function updateCachedPassStatus(passCode, newStatus) {
  if (!passCode) return;
  const p = passCache.get(String(passCode).toUpperCase());
  if (p) {
    p.status = newStatus;
  }
}

function preloadPassCache() {
  db.all('SELECT * FROM passes ORDER BY id DESC LIMIT 2500', [], (err, rows) => {
    if (!err && rows) {
      for (const r of rows) {
        cachePass(r);
      }
      console.log(`✓ Preloaded ${rows.length} active passes into ultra-fast in-memory cache.`);
    }
  });
}

// Gate Security Console Policies (Managed by Admin)
let gateSettings = {
  allow_staff_auto_log: 1, // 1 = Admin Allowed, 0 = Admin Locked
  allow_visitor_express: 0, // 1 = Admin Allowed, 0 = Admin Locked
  updated_by: 'System Default',
  updated_at: new Date().toISOString()
};

function loadGateSettingsFromDb() {
  db.all('SELECT setting_key, setting_value, updated_by, updated_at FROM system_settings', [], (err, rows) => {
    if (!err && rows && rows.length > 0) {
      rows.forEach(r => {
        if (r.setting_key === 'allow_staff_auto_log') {
          gateSettings.allow_staff_auto_log = (r.setting_value === '1' || r.setting_value === 'true' || r.setting_value === 1) ? 1 : 0;
        } else if (r.setting_key === 'allow_visitor_express') {
          gateSettings.allow_visitor_express = (r.setting_value === '1' || r.setting_value === 'true' || r.setting_value === 1) ? 1 : 0;
        }
        if (r.updated_by) gateSettings.updated_by = r.updated_by;
        if (r.updated_at) gateSettings.updated_at = r.updated_at;
      });
      console.log(`✓ Gate Policies active: Staff Auto-Log: ${gateSettings.allow_staff_auto_log === 1 ? 'ENABLED' : 'DISABLED'}, Visitor Express: ${gateSettings.allow_visitor_express === 1 ? 'ENABLED' : 'DISABLED'}`);
    }
  });
}

// -------------------------------------------------------------
// Automated Daily Intelligence & Anomaly Email Reporting Engine
// -------------------------------------------------------------
let emailReportConfig = {
  enabled: 1,
  recipient: 'admin@doenets.lk',
  time: '17:00',
  resend_api_key: process.env.RESEND_API_KEY || '',
  smtp_host: process.env.SMTP_HOST || '',
  smtp_port: process.env.SMTP_PORT || 587,
  smtp_user: process.env.SMTP_USER || '',
  smtp_pass: process.env.SMTP_PASS || '',
  from_name: 'DoENETS Gate Pass Intelligence',
  from_address: process.env.EMAIL_FROM || 'gatepass-alerts@doenets.lk',
  last_sent_date: null,
  last_sent_status: null,
  last_sent_error: null
};

function loadEmailSettingsFromDb() {
  db.all("SELECT setting_key, setting_value FROM system_settings WHERE setting_key LIKE 'email_report_%' OR setting_key LIKE 'smtp_%' OR setting_key = 'resend_api_key'", [], (err, rows) => {
    if (!err && rows && rows.length > 0) {
      rows.forEach(r => {
        if (r.setting_key === 'email_report_enabled') emailReportConfig.enabled = (r.setting_value === '1' || r.setting_value === 'true' || r.setting_value === 1) ? 1 : 0;
        if (r.setting_key === 'email_report_recipient') emailReportConfig.recipient = r.setting_value;
        if (r.setting_key === 'email_report_time') emailReportConfig.time = r.setting_value;
        if (r.setting_key === 'email_report_last_sent') emailReportConfig.last_sent_date = r.setting_value;
        if (r.setting_key === 'email_report_last_status') emailReportConfig.last_sent_status = r.setting_value;
        if (r.setting_key === 'email_report_last_error') emailReportConfig.last_sent_error = r.setting_value;
        if (r.setting_key === 'resend_api_key') emailReportConfig.resend_api_key = r.setting_value;
        if (r.setting_key === 'smtp_host') emailReportConfig.smtp_host = r.setting_value;
        if (r.setting_key === 'smtp_port') emailReportConfig.smtp_port = parseInt(r.setting_value) || 587;
        if (r.setting_key === 'smtp_user') emailReportConfig.smtp_user = r.setting_value;
        if (r.setting_key === 'smtp_pass') emailReportConfig.smtp_pass = r.setting_value;
      });
      console.log(`✓ Automated Email Reporting: ${emailReportConfig.enabled ? 'ENABLED' : 'DISABLED'} (Daily at ${emailReportConfig.time} to ${emailReportConfig.recipient})`);
    }
  });
}

function compileDailyIntelligenceReport(targetDateStr = null) {
  return new Promise((resolve, reject) => {
    const now = new Date();
    const dateQuery = targetDateStr || new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().split('T')[0];

    const logSql = `SELECT * FROM gate_logs WHERE DATE(timestamp, 'localtime') = DATE(?) ORDER BY timestamp ASC`;
    db.all(logSql, [dateQuery], (err, logs) => {
      if (err) return reject(err);
      logs = logs || [];

      let totalCheckIns = 0;
      let totalCheckOuts = 0;
      let branchCounts = {};
      let categoryCounts = {};
      let passVisits = {};

      logs.forEach(l => {
        let dateStr = String(l.timestamp || '');
        if (!dateStr.endsWith('Z') && !dateStr.includes('+')) dateStr = dateStr.replace(' ', 'T');
        const d = new Date(dateStr);

        if (l.action_type === 'CHECK_IN') {
          totalCheckIns++;
          if (!passVisits[l.pass_code]) passVisits[l.pass_code] = [];
          passVisits[l.pass_code].push({ in: d, out: null });
        } else if (l.action_type === 'CHECK_OUT') {
          totalCheckOuts++;
          if (passVisits[l.pass_code] && passVisits[l.pass_code].length > 0) {
            const last = passVisits[l.pass_code][passVisits[l.pass_code].length - 1];
            if (last && !last.out) last.out = d;
          }
        }

        const b = l.branch_name || 'General Administration';
        branchCounts[b] = (branchCounts[b] || 0) + 1;
        const c = l.category || 'VISITOR';
        categoryCounts[c] = (categoryCounts[c] || 0) + 1;
      });

      let totalDwellMinutes = 0;
      let completedVisitCount = 0;
      Object.values(passVisits).forEach(visits => {
        visits.forEach(v => {
          if (v.in && v.out && !isNaN(v.in.getTime()) && !isNaN(v.out.getTime())) {
            const diffMs = v.out.getTime() - v.in.getTime();
            if (diffMs > 0 && diffMs < 24 * 3600 * 1000) {
              totalDwellMinutes += Math.round(diffMs / 60000);
              completedVisitCount++;
            }
          }
        });
      });
      const avgDwellMins = completedVisitCount > 0 ? Math.round(totalDwellMinutes / completedVisitCount) : 0;

      db.all("SELECT * FROM passes WHERE status = 'CHECKED_IN'", [], (pErr, checkedInPasses) => {
        checkedInPasses = checkedInPasses || [];
        const currentTimeMs = Date.now();
        let vehiclesInside = 0;
        let overstayAlerts = [];

        checkedInPasses.forEach(p => {
          if (p.vehicle_number && p.vehicle_number.trim() && p.vehicle_number.toUpperCase() !== 'NONE') {
            vehiclesInside++;
          }
          let entryTime = null;
          if (passVisits[p.pass_code] && passVisits[p.pass_code].length > 0) {
            const last = passVisits[p.pass_code][passVisits[p.pass_code].length - 1];
            if (last && last.in) entryTime = last.in;
          }
          if (!entryTime) {
            let s = String(p.created_at || '');
            if (!s.endsWith('Z') && !s.includes('+')) s = s.replace(' ', 'T');
            entryTime = new Date(s);
          }
          const elapsedMins = Math.max(0, Math.round((currentTimeMs - (entryTime.getTime() || currentTimeMs)) / 60000));
          if (elapsedMins >= 240) {
            overstayAlerts.push({
              pass_code: p.pass_code,
              person_name: p.person_name,
              category: p.category,
              branch_name: p.branch_name,
              entry_time: entryTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
              duration: `${(elapsedMins / 60).toFixed(1)} hrs`
            });
          }
        });

        // Staff Movement & Disciplinary Anomalies
        let staffLogs = {};
        logs.forEach(l => {
          if (l.category === 'STAFF') {
            if (!staffLogs[l.pass_code]) {
              staffLogs[l.pass_code] = {
                pass_code: l.pass_code,
                person_name: l.person_name,
                branch_name: l.branch_name,
                events: []
              };
            }
            let s = String(l.timestamp || '');
            if (!s.endsWith('Z') && !s.includes('+')) s = s.replace(' ', 'T');
            staffLogs[l.pass_code].events.push({
              action: l.action_type,
              time: new Date(s)
            });
          }
        });

        let nightOutings = [];
        let prolongedOutings = [];
        let frequentExits = [];

        Object.values(staffLogs).forEach(stf => {
          stf.events.sort((a, b) => a.time.getTime() - b.time.getTime());
          let exitCount = 0;
          let exitTimes = [];

          for (let i = 0; i < stf.events.length; i++) {
            const ev = stf.events[i];
            if (ev.action === 'CHECK_OUT') {
              exitCount++;
              exitTimes.push(ev.time);

              let returnTime = null;
              for (let j = i + 1; j < stf.events.length; j++) {
                if (stf.events[j].action === 'CHECK_IN') {
                  returnTime = stf.events[j].time;
                  break;
                }
              }

              const outStart = ev.time;
              const outEnd = returnTime || new Date();
              const diffMs = outEnd.getTime() - outStart.getTime();
              const durMins = Math.max(1, Math.round(diffMs / 60000));
              const h = Math.floor(durMins / 60);
              const m = durMins % 60;
              const durStr = h > 0 ? `${h}h ${m}m` : `${durMins}m`;

              const exitHour = outStart.getHours();
              const isNight = (exitHour >= 19 || exitHour < 6);

              if (durMins >= 120 || !returnTime) {
                prolongedOutings.push({
                  pass_code: stf.pass_code,
                  person_name: stf.person_name,
                  branch_name: stf.branch_name,
                  exit_time: outStart.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                  return_time: returnTime ? returnTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Still Out / ආපසු පැමිණ නැත',
                  duration: durStr,
                  duration_minutes: durMins,
                  status: returnTime ? 'Returned' : 'STILL_OUTSIDE'
                });
              }

              if (isNight) {
                nightOutings.push({
                  pass_code: stf.pass_code,
                  person_name: stf.person_name,
                  branch_name: stf.branch_name,
                  exit_time: outStart.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
                  return_time: returnTime ? returnTime.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Still Out (Night)',
                  duration: durStr,
                  status: returnTime ? 'Returned at Night' : 'STILL_OUTSIDE'
                });
              }
            }
          }

          if (exitCount >= 3) {
            frequentExits.push({
              pass_code: stf.pass_code,
              person_name: stf.person_name,
              branch_name: stf.branch_name,
              exit_count: exitCount,
              times: exitTimes.map(t => t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })).join(', ')
            });
          }
        });

        prolongedOutings.sort((a, b) => b.duration_minutes - a.duration_minutes);
        frequentExits.sort((a, b) => b.exit_count - a.exit_count);

        const totalAnomalies = nightOutings.length + prolongedOutings.length + frequentExits.length + overstayAlerts.length;

        resolve({
          dateStr: dateQuery,
          generatedAt: new Date().toLocaleString(),
          metrics: {
            totalCheckIns,
            totalCheckOuts,
            currentlyInside: checkedInPasses.length,
            vehiclesInside,
            avgDwellMins
          },
          branchCounts,
          categoryCounts,
          anomalies: {
            totalCount: totalAnomalies,
            nightOutings,
            prolongedOutings,
            frequentExits,
            overstayAlerts
          }
        });
      });
    });
  });
}

function generateEmailReportHtml(report) {
  const isAlert = report.anomalies.totalCount > 0;
  
  let prolongedHtml = '';
  if (report.anomalies.prolongedOutings.length > 0) {
    prolongedHtml = `
      <div style="margin-top: 15px; margin-bottom: 20px;">
        <h4 style="margin: 0 0 8px 0; color: #b91c1c; font-size: 14px;">⏱️ දීර්ඝ කාලයක් පිටත රැඳී සිටි සේවකයන් (Duty Hour Absences > 2 Hours / Still Out):</h4>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="background: #fee2e2; color: #991b1b; text-align: left;">
              <th style="padding: 8px; border: 1px solid #fca5a5;">Pass / Name</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Branch</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Exit Time</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Return Time</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Duration</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Status</th>
            </tr>
          </thead>
          <tbody>
            ${report.anomalies.prolongedOutings.map(p => `
              <tr style="background: ${p.status === 'STILL_OUTSIDE' ? '#fff1f2' : '#ffffff'};">
                <td style="padding: 8px; border: 1px solid #fca5a5; font-weight: bold;">${p.person_name} <span style="font-size: 11px; color: #64748b;">(${p.pass_code})</span></td>
                <td style="padding: 8px; border: 1px solid #fca5a5;">${p.branch_name}</td>
                <td style="padding: 8px; border: 1px solid #fca5a5;">${p.exit_time}</td>
                <td style="padding: 8px; border: 1px solid #fca5a5;">${p.return_time}</td>
                <td style="padding: 8px; border: 1px solid #fca5a5; font-weight: bold; color: #b91c1c;">${p.duration}</td>
                <td style="padding: 8px; border: 1px solid #fca5a5;">
                  <span style="background: ${p.status === 'STILL_OUTSIDE' ? '#ef4444' : '#10b981'}; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: bold;">
                    ${p.status}
                  </span>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  let nightHtml = '';
  if (report.anomalies.nightOutings.length > 0) {
    nightHtml = `
      <div style="margin-top: 15px; margin-bottom: 20px;">
        <h4 style="margin: 0 0 8px 0; color: #9d174d; font-size: 14px;">🌙 රාත්‍රී කාලයේ පිටවීම් (Night Security Outings - 7:00 PM to 6:00 AM):</h4>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="background: #fdf2f8; color: #9d174d; text-align: left;">
              <th style="padding: 8px; border: 1px solid #fbcfe8;">Pass / Name</th>
              <th style="padding: 8px; border: 1px solid #fbcfe8;">Branch</th>
              <th style="padding: 8px; border: 1px solid #fbcfe8;">Night Exit</th>
              <th style="padding: 8px; border: 1px solid #fbcfe8;">Return</th>
              <th style="padding: 8px; border: 1px solid #fbcfe8;">Duration</th>
              <th style="padding: 8px; border: 1px solid #fbcfe8;">Alert Status</th>
            </tr>
          </thead>
          <tbody>
            ${report.anomalies.nightOutings.map(n => `
              <tr style="background: #ffffff;">
                <td style="padding: 8px; border: 1px solid #fbcfe8; font-weight: bold;">${n.person_name} <span style="font-size: 11px; color: #64748b;">(${n.pass_code})</span></td>
                <td style="padding: 8px; border: 1px solid #fbcfe8;">${n.branch_name}</td>
                <td style="padding: 8px; border: 1px solid #fbcfe8;">${n.exit_time}</td>
                <td style="padding: 8px; border: 1px solid #fbcfe8;">${n.return_time}</td>
                <td style="padding: 8px; border: 1px solid #fbcfe8; font-weight: bold;">${n.duration}</td>
                <td style="padding: 8px; border: 1px solid #fbcfe8; color: #be185d; font-weight: bold;">${n.status}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  let frequentHtml = '';
  if (report.anomalies.frequentExits.length > 0) {
    frequentHtml = `
      <div style="margin-top: 15px; margin-bottom: 20px;">
        <h4 style="margin: 0 0 8px 0; color: #b45309; font-size: 14px;">🔄 දිනකට වැඩි වාර ගණනක් පිටතට ගිය සේවකයන් (Frequent Exits &ge; 3 Times):</h4>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="background: #fef3c7; color: #92400e; text-align: left;">
              <th style="padding: 8px; border: 1px solid #fde68a;">Pass / Name</th>
              <th style="padding: 8px; border: 1px solid #fde68a;">Branch</th>
              <th style="padding: 8px; border: 1px solid #fde68a;">Total Exits</th>
              <th style="padding: 8px; border: 1px solid #fde68a;">Recorded Exit Times</th>
            </tr>
          </thead>
          <tbody>
            ${report.anomalies.frequentExits.map(f => `
              <tr style="background: #ffffff;">
                <td style="padding: 8px; border: 1px solid #fde68a; font-weight: bold;">${f.person_name} <span style="font-size: 11px; color: #64748b;">(${f.pass_code})</span></td>
                <td style="padding: 8px; border: 1px solid #fde68a;">${f.branch_name}</td>
                <td style="padding: 8px; border: 1px solid #fde68a; font-weight: bold; color: #b45309; font-size: 14px;">${f.exit_count} වතාවක්</td>
                <td style="padding: 8px; border: 1px solid #fde68a; font-size: 12px; color: #475569;">${f.times}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  let overstayHtml = '';
  if (report.anomalies.overstayAlerts.length > 0) {
    overstayHtml = `
      <div style="margin-top: 15px; margin-bottom: 20px;">
        <h4 style="margin: 0 0 8px 0; color: #991b1b; font-size: 14px;">🚨 නියමිත කාලය ඉක්මවා පරිශ්‍රයේ රැඳී සිටින පුද්ගලයින් (Overstay Alerts &gt; 4 Hours):</h4>
        <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
          <thead>
            <tr style="background: #fee2e2; color: #991b1b; text-align: left;">
              <th style="padding: 8px; border: 1px solid #fca5a5;">Pass / Name</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Category</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Visiting Branch</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Check-In Time</th>
              <th style="padding: 8px; border: 1px solid #fca5a5;">Time Inside</th>
            </tr>
          </thead>
          <tbody>
            ${report.anomalies.overstayAlerts.map(o => `
              <tr style="background: #ffffff;">
                <td style="padding: 8px; border: 1px solid #fca5a5; font-weight: bold;">${o.person_name} <span style="font-size: 11px; color: #64748b;">(${o.pass_code})</span></td>
                <td style="padding: 8px; border: 1px solid #fca5a5;">${o.category}</td>
                <td style="padding: 8px; border: 1px solid #fca5a5;">${o.branch_name}</td>
                <td style="padding: 8px; border: 1px solid #fca5a5;">${o.entry_time}</td>
                <td style="padding: 8px; border: 1px solid #fca5a5; font-weight: bold; color: #dc2626;">${o.duration}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }

  const branchRows = Object.entries(report.branchCounts).map(([branch, count]) => `
    <tr>
      <td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0;">${branch}</td>
      <td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-weight: bold; text-align: right;">${count}</td>
    </tr>
  `).join('');

  const categoryRows = Object.entries(report.categoryCounts).map(([cat, count]) => `
    <tr>
      <td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0;">${cat}</td>
      <td style="padding: 6px 10px; border-bottom: 1px solid #e2e8f0; font-weight: bold; text-align: right;">${count}</td>
    </tr>
  `).join('');

  return `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>DoENETS Daily Gate Intelligence Report</title>
</head>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #f1f5f9; margin: 0; padding: 25px; color: #1e293b; line-height: 1.5;">
  <div style="max-width: 720px; margin: 0 auto; background: #ffffff; border-radius: 12px; overflow: hidden; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1), 0 2px 4px -2px rgba(0,0,0,0.1); border: 1px solid #e2e8f0;">
    
    <!-- Header Banner -->
    <div style="background: linear-gradient(135deg, #0f172a 0%, #1e3a8a 100%); color: #ffffff; padding: 25px 30px;">
      <div style="display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(255,255,255,0.15); padding-bottom: 15px; margin-bottom: 15px;">
        <div>
          <h1 style="margin: 0; font-size: 20px; font-weight: 800; letter-spacing: -0.025em; color: #ffffff;">ශ්‍රී ලංකා විභාග දෙපාර්තමේන්තුව</h1>
          <p style="margin: 3px 0 0 0; font-size: 13px; color: #93c5fd; font-weight: 500;">Department of Examinations Sri Lanka</p>
        </div>
        <div style="background: #2563eb; color: #ffffff; padding: 5px 12px; border-radius: 20px; font-size: 11px; font-weight: 800; text-transform: uppercase; letter-spacing: 0.5px;">
          GATE INTELLIGENCE
        </div>
      </div>
      <div>
        <h2 style="margin: 0; font-size: 17px; font-weight: 700; color: #f8fafc;">දෛනික ගේට්ටු පාලන සහ ආරක්ෂක බුද්ධිමත් සාරාංශ වාර්තාව</h2>
        <p style="margin: 5px 0 0 0; font-size: 13px; color: #cbd5e1;">දිනය (Date): <strong>${report.dateStr}</strong> | ජනනය කළ වේලාව: ${report.generatedAt}</p>
      </div>
    </div>

    <div style="padding: 25px 30px;">

      <!-- Anomaly Alert Card -->
      ${isAlert ? `
        <div style="background: #fff1f2; border: 2px solid #f43f5e; border-radius: 10px; padding: 18px 20px; margin-bottom: 25px;">
          <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 10px;">
            <span style="font-size: 24px;">⚠️</span>
            <div>
              <h3 style="margin: 0; color: #9f1239; font-size: 16px; font-weight: 800;">ආරක්ෂක සහ විනයාරක්ෂක අසාමාන්‍යතා හඳුනාගෙන ඇත (${report.anomalies.totalCount} Anomalies Flagged)</h3>
              <p style="margin: 2px 0 0 0; color: #be123c; font-size: 13px;">පරිපාලන සහ විනය අධීක්ෂණය සඳහා විශේෂ අවධානය යොමු කළ යුතු අවස්ථා පහත දැක්වේ:</p>
            </div>
          </div>
          <ul style="margin: 5px 0 0 25px; padding: 0; font-size: 13px; color: #881337; line-height: 1.6;">
            ${report.anomalies.prolongedOutings.length > 0 ? `<li><strong>දීර්ඝ කාලයක් පිටත රැඳී සිටි සේවකයන්:</strong> ${report.anomalies.prolongedOutings.length} දෙනෙක්</li>` : ''}
            ${report.anomalies.nightOutings.length > 0 ? `<li><strong>රාත්‍රී කාලයේ පිටවීම් (Night Outings):</strong> ${report.anomalies.nightOutings.length} අවස්ථාවක්</li>` : ''}
            ${report.anomalies.frequentExits.length > 0 ? `<li><strong>නිතර (3+ වතාවක්) පිටතට ගිය සේවකයන්:</strong> ${report.anomalies.frequentExits.length} දෙනෙක්</li>` : ''}
            ${report.anomalies.overstayAlerts.length > 0 ? `<li><strong>පැය 4 කට වඩා පරිශ්‍රයේ රැඳී සිටින අමුත්තන්:</strong> ${report.anomalies.overstayAlerts.length} දෙනෙක්</li>` : ''}
          </ul>
        </div>
      ` : `
        <div style="background: #f0fdf4; border: 2px solid #22c55e; border-radius: 10px; padding: 15px 20px; margin-bottom: 25px; display: flex; align-items: center; gap: 12px;">
          <span style="font-size: 24px;">✅</span>
          <div>
            <h3 style="margin: 0; color: #166534; font-size: 15px; font-weight: 800;">ආරක්ෂක තත්ත්වය සාමාන්‍යයි (All Clear)</h3>
            <p style="margin: 2px 0 0 0; color: #15803d; font-size: 13px;">අද දින කිසිදු අසාමාන්‍ය සේවක පිටවීමක්, රාත්‍රී පිටවීමක් හෝ දීර්ඝ කාලීන overstay අවදානමක් හඳුනාගෙන නොමැත.</p>
          </div>
        </div>
      `}

      <!-- 4 Core Metrics Grid -->
      <table style="width: 100%; border-collapse: separate; border-spacing: 10px; margin-bottom: 20px;">
        <tr>
          <td style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; width: 25%;">
            <div style="font-size: 24px; font-weight: 800; color: #2563eb;">${report.metrics.totalCheckIns}</div>
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-top: 2px;">Total Check-Ins</div>
          </td>
          <td style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; width: 25%;">
            <div style="font-size: 24px; font-weight: 800; color: #059669;">${report.metrics.totalCheckOuts}</div>
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-top: 2px;">Total Exits</div>
          </td>
          <td style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; width: 25%;">
            <div style="font-size: 24px; font-weight: 800; color: #d97706;">${report.metrics.currentlyInside}</div>
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-top: 2px;">Currently Inside</div>
          </td>
          <td style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 14px; text-align: center; width: 25%;">
            <div style="font-size: 24px; font-weight: 800; color: #7c3aed;">${report.metrics.vehiclesInside}</div>
            <div style="font-size: 11px; font-weight: 700; color: #64748b; text-transform: uppercase; margin-top: 2px;">Vehicles Inside</div>
          </td>
        </tr>
      </table>

      <!-- Section: Anomalies Detail -->
      ${prolongedHtml}
      ${nightHtml}
      ${frequentHtml}
      ${overstayHtml}

      <!-- Section: Branch Demand & Categories Side by Side -->
      <table style="width: 100%; border-collapse: collapse; margin-top: 20px;">
        <tr>
          <td style="width: 50%; vertical-align: top; padding-right: 10px;">
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px;">
              <h4 style="margin: 0 0 10px 0; color: #1e3a8a; font-size: 13px; font-weight: 800;">🏛️ ශාඛා අනුව ඉල්ලුම (Branch Visits):</h4>
              <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                <tbody>
                  ${branchRows || '<tr><td>තොරතුරු නොමැත</td></tr>'}
                </tbody>
              </table>
            </div>
          </td>
          <td style="width: 50%; vertical-align: top; padding-left: 10px;">
            <div style="background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 15px;">
              <h4 style="margin: 0 0 10px 0; color: #1e3a8a; font-size: 13px; font-weight: 800;">👥 කාණ්ඩ අනුව බෙදීයාම (Categories):</h4>
              <table style="width: 100%; font-size: 12px; border-collapse: collapse;">
                <tbody>
                  ${categoryRows || '<tr><td>තොරතුරු නොමැත</td></tr>'}
                </tbody>
              </table>
            </div>
          </td>
        </tr>
      </table>

      <!-- Additional Insights Note -->
      <div style="margin-top: 25px; padding: 12px 16px; background: #f0fdf4; border-left: 4px solid #10b981; border-radius: 4px; font-size: 12px; color: #166534;">
        <strong>සාමාන්‍ය රැඳී සිටි කාලය (Average Dwell Time):</strong> ${report.metrics.avgDwellMins} මිනිත්තු. සවිස්තරාත්මක සජීවී වාර්තා සහ එක්සෙල් (CSV) බාගත කිරීම් සඳහා දෙපාර්තමේන්තු පරිපාලන පද්ධතිය වෙත පිවිසෙන්න.
      </div>

    </div>

    <!-- Footer -->
    <div style="background: #f8fafc; border-top: 1px solid #e2e8f0; padding: 18px 30px; font-size: 12px; color: #64748b; text-align: center;">
      <p style="margin: 0 0 4px 0;">මෙම වාර්තාව ශ්‍රී ලංකා විභාග දෙපාර්තමේන්තු ගේට්ටු පාලන පද්ධතියේ (DoENETS Gate Pass System) ස්වයංක්‍රීය කාලසටහන මඟින් ජනනය කරන ලද්දකි.</p>
      <p style="margin: 0;">&copy; ${new Date().getFullYear()} Department of Examinations Sri Lanka. All Rights Reserved.</p>
    </div>

  </div>
</body>
</html>`;
}

function sendViaResendHttps(apiKey, fromAddress, toAddress, subject, htmlContent) {
  const https = require('https');
  return new Promise((resolve, reject) => {
    const from = (fromAddress && fromAddress.includes('@resend.dev')) ? fromAddress : 'DoENETS Gate Intelligence <onboarding@resend.dev>';
    const payload = JSON.stringify({
      from,
      to: [toAddress],
      subject,
      html: htmlContent
    });

    const options = {
      hostname: 'api.resend.com',
      port: 443,
      path: '/emails',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey.trim()}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload)
      },
      timeout: 15000
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (res.statusCode >= 200 && res.statusCode < 300) {
            resolve(parsed);
          } else {
            let errorMsg = parsed.message || `Resend Error ${res.statusCode}: ${data}`;
            if (errorMsg.includes('only send testing emails to your own email address')) {
              errorMsg = `Resend පරීක්ෂණ සීමාව: නොමිලේ Resend Test ගිණුමකින් (onboarding@resend.dev) ඊමේල් යැවිය හැක්කේ ඔබ Resend ගිණුම ලියාපදිංචි කළ ඔබගේම ඊමේල් ලිපිනයට (උදා: ඔබගේ Gmail ලිපිනයට) පමණි. කරුණාකර "ලබන්නාගේ ඊමේල් ලිපිනය (Recipient Email)" කොටුවට ඔබ Resend ලියාපදිංචි කළ ඊමේල් ලිපිනයම ඇතුළත් කර සුරකින්න.`;
            } else if (res.statusCode === 401 || errorMsg.toLowerCase().includes('api key')) {
              errorMsg = `Resend API Key එක වලංගු නැත: කරුණාකර resend.com වෙතින් ලබාගත් 're_' වලින් පටන්ගන්නා නිවැරදි API Key එක ඇතුළත් කරන්න.`;
            }
            reject(new Error(errorMsg));
          }
        } catch (e) {
          reject(new Error(`Resend Response Error: ${data}`));
        }
      });
    });

    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Resend API request timed out (15s).'));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

async function sendDailyIntelligenceEmail(recipientOverride = null) {
  const recipient = recipientOverride || emailReportConfig.recipient || 'admin@doenets.lk';
  const report = await compileDailyIntelligenceReport();
  const htmlContent = generateEmailReportHtml(report);
  const textSummary = `Department of Examinations - Gate Pass Daily Intelligence Report (${report.dateStr}). Total Entries: ${report.metrics.totalCheckIns}, Exits: ${report.metrics.totalCheckOuts}, Inside: ${report.metrics.currentlyInside}, Anomalies Flagged: ${report.anomalies.totalCount}.`;

  const isAlert = report.anomalies.totalCount > 0;
  const subject = `[${isAlert ? '⚠️ ALERT: ' + report.anomalies.totalCount + ' ANOMALIES' : '✓ ALL CLEAR'}] DoENETS Gate Intelligence Report - ${report.dateStr}`;

  const resendKey = emailReportConfig.resend_api_key || process.env.RESEND_API_KEY;
  const host = emailReportConfig.smtp_host || process.env.SMTP_HOST;
  const user = emailReportConfig.smtp_user || process.env.SMTP_USER;
  let pass = emailReportConfig.smtp_pass || process.env.SMTP_PASS;
  const port = emailReportConfig.smtp_port || process.env.SMTP_PORT || 587;

  if (pass) pass = String(pass).replace(/\s+/g, '');

  let dispatchResult = { success: false, mode: 'SIMULATION', message: '', recipient, reportSummary: report };

  // Priority 1: Resend HTTPS API (Recommended for Render Cloud - Port 443 is never blocked)
  if (resendKey && resendKey.trim() !== '') {
    try {
      const info = await sendViaResendHttps(resendKey, emailReportConfig.from_address, recipient, subject, htmlContent);
      console.log(`✓ Email report successfully dispatched via Resend HTTPS API to ${recipient}: ${info.id}`);
      dispatchResult = { success: true, mode: 'RESEND_API', messageId: info.id, recipient, sentAt: new Date().toISOString(), reportSummary: report };
    } catch (resendErr) {
      console.error(`✗ Resend API delivery failed: ${resendErr.message}`);
      dispatchResult = { success: false, mode: 'RESEND_FAILED', error: resendErr.message, recipient, sentAt: new Date().toISOString(), reportSummary: report };
    }
  }
  // Priority 2: Direct SMTP (Works on Localhost and cloud instances with open SMTP ports)
  else if (host && user && pass) {
    try {
      const isGmail = host.toLowerCase().includes('gmail');
      const isSecure = Number(port) === 465;

      const transportConfig = isGmail ? {
        service: 'gmail',
        auth: { user, pass },
        tls: { rejectUnauthorized: false },
        connectionTimeout: 12000,
        greetingTimeout: 10000,
        socketTimeout: 15000
      } : {
        host,
        port: Number(port),
        secure: isSecure,
        auth: { user, pass },
        tls: { rejectUnauthorized: false },
        connectionTimeout: 12000,
        greetingTimeout: 10000,
        socketTimeout: 15000
      };

      const transporter = nodemailer.createTransport(transportConfig);

      const info = await transporter.sendMail({
        from: `"${emailReportConfig.from_name}" <${emailReportConfig.from_address || user}>`,
        to: recipient,
        subject,
        text: textSummary,
        html: htmlContent
      });

      console.log(`✓ Email report successfully dispatched via SMTP to ${recipient}: ${info.messageId}`);
      dispatchResult = { success: true, mode: 'SMTP', messageId: info.messageId, recipient, sentAt: new Date().toISOString(), reportSummary: report };
    } catch (sendErr) {
      console.error(`✗ SMTP delivery failed (${sendErr.message}).`);
      dispatchResult = { success: false, mode: 'SMTP_FAILED', error: sendErr.message, recipient, sentAt: new Date().toISOString(), reportSummary: report };
    }
  } else {
    console.log(`ℹ SMTP credentials not configured. Executed simulated report generation for ${recipient}.`);
    dispatchResult = {
      success: true,
      mode: 'SIMULATION',
      message: 'SMTP credentials not configured. Real email was NOT dispatched to inbox; report compiled in Simulation mode.',
      recipient,
      sentAt: new Date().toISOString(),
      reportSummary: report
    };
  }

  logAdminAuditAction('SYSTEM_SCHEDULER', 'SYSTEM', 'DISPATCH_EMAIL_REPORT', recipient, `Mode: ${dispatchResult.mode}, Anomalies: ${report.anomalies.totalCount}, Status: ${dispatchResult.success ? 'SUCCESS' : 'FAILED'}`, '127.0.0.1');

  const todayStr = new Date().toISOString().split('T')[0];
  emailReportConfig.last_sent_date = todayStr;
  emailReportConfig.last_sent_status = `${dispatchResult.mode}:${dispatchResult.success ? 'SUCCESS' : 'FAILED'}`;
  emailReportConfig.last_sent_error = dispatchResult.error || '';

  db.run(
    "INSERT INTO system_settings (setting_key, setting_value, updated_by) VALUES ('email_report_last_sent', ?, 'System Scheduler') ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP",
    [todayStr]
  );
  db.run(
    "INSERT INTO system_settings (setting_key, setting_value, updated_by) VALUES ('email_report_last_status', ?, 'System Scheduler') ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP",
    [emailReportConfig.last_sent_status]
  );
  db.run(
    "INSERT INTO system_settings (setting_key, setting_value, updated_by) VALUES ('email_report_last_error', ?, 'System Scheduler') ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_at = CURRENT_TIMESTAMP",
    [emailReportConfig.last_sent_error]
  );

  return dispatchResult;
}

function checkDailyEmailSchedule() {
  if (!emailReportConfig.enabled) return;

  const now = new Date();
  const hours = String(now.getHours()).padStart(2, '0');
  const minutes = String(now.getMinutes()).padStart(2, '0');
  const currentTime = `${hours}:${minutes}`;

  const year = now.getFullYear();
  const month = String(now.getMonth() + 1).padStart(2, '0');
  const day = String(now.getDate()).padStart(2, '0');
  const todayDate = `${year}-${month}-${day}`;

  if (currentTime === emailReportConfig.time && emailReportConfig.last_sent_date !== todayDate) {
    console.log(`⏰ Scheduled trigger matched (${currentTime}). Dispatching Daily Intelligence Email Report to ${emailReportConfig.recipient}...`);
    sendDailyIntelligenceEmail().catch(err => {
      console.error('Error during scheduled email report dispatch:', err);
    });
  }
}

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

// Authentication Middleware (Supports JWT Bearer Token & Executive API Key)
function authenticateToken(req, res, next) {
  // 1. Check for Executive API Key (For External BI / Dashboard / Script integrations)
  const apiKey = req.headers['x-api-key'] || req.query.api_key;
  if (apiKey && apiKey === REPORTS_API_KEY) {
    req.user = { username: 'api_executive', role: 'SUPER_ADMIN', display_name: 'Executive Reporting Client' };
    return next();
  }

  // 2. Standard Session JWT Bearer Token
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) return res.status(401).json({ error: 'Authentication required / අවසරය අවශ්‍යයි (Provide Bearer Token or X-API-KEY)' });

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

            const newVisitorPass = {
              id: this.lastID,
              daily_no: dailyNo,
              daily_no_formatted: formattedDailyNo,
              pass_code: passCode,
              category: 'VISITOR',
              person_name,
              nic_number: cleanNic,
              mobile_number,
              vehicle_number: formattedVeh,
              branch_name,
              purpose: purpose || 'General Visit',
              access_zones: 'GENERAL_VISITOR',
              status: 'PENDING_VERIFICATION',
              created_by: 'SELF_REGISTRATION',
              created_at: new Date().toISOString()
            };
            cachePass(newVisitorPass);

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

// 5. Security Scan Lookup & Express Auto-Log (Authenticated)
app.post('/api/security/scan', authenticateToken, (req, res) => {
  const { code, auto_staff = true, auto_visitor = false } = req.body;
  if (!code) return res.status(400).json({ error: 'Pass code, NIC, or RFID card required' });

  const rawCode = code.trim();
  const searchCode = rawCode.toUpperCase();
  const partialCode = `%${searchCode}%`;

  const processPassScan = (pass) => {
    // Strictly enforce Admin authorization policies:
    const effectiveAutoStaff = (gateSettings.allow_staff_auto_log === 1) && Boolean(auto_staff);
    const effectiveAutoVisitor = (gateSettings.allow_visitor_express === 1) && Boolean(auto_visitor);

    const isStaffAuto = (pass.category === 'STAFF' && effectiveAutoStaff);
    const isVisitorAuto = (pass.category !== 'STAFF' && effectiveAutoVisitor);

    // Fast Auto-Log for Staff or Express-Enabled Visitors/Special Passes
    if (isStaffAuto || isVisitorAuto) {
      const officerName = req.user ? req.user.display_name : 'Security Gate';
      const action_type = (pass.status === 'CHECKED_IN') ? 'CHECK_OUT' : 'CHECK_IN';
      const newStatus = (action_type === 'CHECK_IN') ? 'CHECKED_IN' : 'CHECKED_OUT';

      // Accidental double-tap protection (within 6 seconds)
      db.get(`
        SELECT timestamp, action_type FROM gate_logs 
        WHERE pass_code = ? 
        ORDER BY id DESC LIMIT 1
      `, [pass.pass_code], (logCheckErr, lastLog) => {
        let isDoubleTap = false;
        if (lastLog && lastLog.timestamp) {
          let tsStr = String(lastLog.timestamp);
          if (!tsStr.endsWith('Z')) tsStr = tsStr.replace(' ', 'T') + 'Z';
          const logTime = new Date(tsStr).getTime();
          const diffMs = Math.abs(Date.now() - logTime);
          if (diffMs < 6000) {
            isDoubleTap = true;
          }
        }

        if (isDoubleTap) {
          return res.json({
            pass,
            auto_logged: true,
            double_tap: true,
            action_type: lastLog.action_type,
            message: `⚠️ දැනටමත් සටහන් කර ඇත: ${pass.person_name} (${lastLog.action_type === 'CHECK_IN' ? 'ඇතුළු වීම' : 'පිටවීම'})`,
            officer: officerName
          });
        }

        db.run('UPDATE passes SET status = ? WHERE id = ?', [newStatus, pass.id], (upErr) => {
          if (upErr) return res.status(500).json({ error: 'Status update failed' });
          updateCachedPassStatus(pass.pass_code, newStatus);

          const logSql = `
            INSERT INTO gate_logs (pass_code, person_name, nic_number, category, branch_name, action_type, security_officer_name)
            VALUES (?, ?, ?, ?, ?, ?, ?)
          `;
          db.run(logSql, [pass.pass_code, pass.person_name, pass.nic_number, pass.category, pass.branch_name, action_type, officerName], (insLogErr) => {
            const catLabel = pass.category === 'STAFF' ? 'අභ්‍යන්තර සේවක' : (pass.category === 'CONFIDENTIAL' ? 'රහස්‍ය අංශ සම්පත්දායක' : (pass.category === 'EVALUATION' ? 'ඇගයීම් සම්පත්දායක' : 'අමුත්තා'));
            res.json({
              pass: { ...pass, status: newStatus },
              auto_logged: true,
              double_tap: false,
              action_type: action_type,
              message: action_type === 'CHECK_IN'
                ? `✓ ${catLabel} ඇතුළුවීම සටහන් විය: ${pass.person_name} (CHECK-IN)`
                : `✓ ${catLabel} පිටවීම සටහන් විය: ${pass.person_name} (CHECK-OUT)`,
              officer: officerName
            });
          });
        });
      });
      return;
    }

    // For Non-Staff (Visitors, Confidential, Evaluation): Check Today's Gate Log History
    const passCodeUpper = String(pass.pass_code || '').toUpperCase();
    const nicUpper = String(pass.nic_number || '').toUpperCase();

    db.all(`
      SELECT id, pass_code, action_type, timestamp, security_officer_name 
      FROM gate_logs 
      WHERE (UPPER(pass_code) = ? OR (nic_number IS NOT NULL AND UPPER(nic_number) = ?))
      ORDER BY id DESC LIMIT 10
    `, [passCodeUpper, nicUpper], (logErr, rows) => {
      const allLogs = rows || [];
      const now = new Date();
      const todayDateStr = now.toLocaleDateString('en-CA'); // 'YYYY-MM-DD'

      const todayLogs = allLogs.filter(l => {
        if (!l.timestamp) return false;
        const logDateStr = String(l.timestamp).slice(0, 10);
        return logDateStr === todayDateStr || Math.abs(now - new Date(l.timestamp)) < 24 * 60 * 60 * 1000;
      });

      const checkInsToday = todayLogs.filter(l => l.action_type === 'CHECK_IN');
      const checkOutsToday = todayLogs.filter(l => l.action_type === 'CHECK_OUT');
      const lastLog = todayLogs.length > 0 ? todayLogs[0] : null;

      return res.json({
        pass,
        today_logs: todayLogs,
        today_summary: {
          has_checked_in_today: checkInsToday.length > 0,
          currently_inside: (pass.status === 'CHECKED_IN') || (lastLog && lastLog.action_type === 'CHECK_IN'),
          check_in_count: checkInsToday.length,
          check_out_count: checkOutsToday.length,
          last_entry_time: checkInsToday[0] ? checkInsToday[0].timestamp : null,
          last_exit_time: checkOutsToday[0] ? checkOutsToday[0].timestamp : null,
          last_officer: lastLog ? lastLog.security_officer_name : null
        },
        auto_logged: false
      });
    });
  };

  // 1. FAST PATH: Instant In-Memory RAM Lookup (0.01ms latency)
  const cachedPass = passCache.get(searchCode);
  if (cachedPass) {
    return processPassScan(cachedPass);
  }

  // 2. Database Fallback (Indexed DB Query)
  db.get(`
    SELECT * FROM passes 
    WHERE UPPER(pass_code) = ? OR UPPER(pass_code) LIKE ? OR UPPER(nic_number) = ? OR UPPER(rfid_card_uid) = ? OR UPPER(employee_number) = ?
    ORDER BY id DESC LIMIT 1
  `, [searchCode, partialCode, searchCode, searchCode, searchCode], (err, pass) => {
    if (err || !pass) {
      return res.status(404).json({ error: `No pass record found for "${rawCode}". Please verify pass code/NIC/RFID or issue a new pass.` });
    }

    cachePass(pass);
    processPassScan(pass);
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
      updateCachedPassStatus(pass.pass_code, newStatus);

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
  const { category, person_name, nic_number, employee_number, mobile_number, vehicle_number, branch_name, purpose, access_zones, valid_days, valid_from, valid_to, rfid_card_uid } = req.body;
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

  const cleanEmpNo = (category === 'STAFF' && employee_number && employee_number.trim()) ? employee_number.trim().toUpperCase() : null;

  if (category === 'STAFF' && !cleanEmpNo) {
    return res.status(400).json({ error: 'Employee Number is required for Internal Staff passes / අභ්‍යන්තර සේවක පාස් සඳහා සේවක අංකය ඇතුළත් කිරීම අනිවාර්ය වේ.' });
  }

  // Validate Employee Number uniqueness for staff
  if (cleanEmpNo) {
    const existingEmp = await new Promise(resolve => {
      db.get('SELECT id, person_name, pass_code FROM passes WHERE category = "STAFF" AND UPPER(employee_number) = ?', [cleanEmpNo], (err, row) => resolve(row));
    });
    if (existingEmp) {
      return res.status(400).json({ error: `Employee Number "${cleanEmpNo}" is already assigned to ${existingEmp.person_name} (${existingEmp.pass_code}) / මෙම සේවක අංකය දැනටමත් ${existingEmp.person_name} වෙත නිකුත් කර ඇත.` });
    }
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
      INSERT INTO passes (pass_code, category, person_name, nic_number, employee_number, mobile_number, vehicle_number, branch_name, purpose, access_zones, valid_from, valid_to, status, created_by, rfid_card_uid)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'ACTIVE', ?, ?)
    `;

    const branch = branch_name || req.user.branch_name;
    const formattedVeh = vehicle_number ? vehicle_number.trim().toUpperCase() : null;
    const accessZoneVal = access_zones || (category === 'CONFIDENTIAL' ? 'CONFIDENTIAL_ZONE' : (category === 'EVALUATION' ? 'EVALUATION_ZONE' : category));

    db.run(sql, [
      passCode, 
      category, 
      person_name, 
      nic_number.trim().toUpperCase(), 
      cleanEmpNo,
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

      const createdPass = {
        id: this.lastID,
        pass_code: passCode,
        category,
        person_name,
        nic_number: nic_number.trim().toUpperCase(),
        employee_number: cleanEmpNo,
        mobile_number,
        vehicle_number: formattedVeh,
        branch_name: branch,
        purpose: purpose || 'Official Duty',
        access_zones: accessZoneVal,
        valid_from: validFrom.toISOString(),
        valid_to: validTo.toISOString(),
        status: 'ACTIVE',
        rfid_card_uid: cleanRfid,
        created_at: new Date().toISOString()
      };
      cachePass(createdPass);

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
          employee_number: cleanEmpNo,
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
      if (pass.rfid_card_uid) {
        passCache.delete(String(pass.rfid_card_uid).toUpperCase());
      }
      pass.rfid_card_uid = cleanRfid;
      cachePass(pass);
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

// 9.4 Gate Security Console Policy Control APIs (Admin Controlled)
app.get('/api/gate/settings', authenticateToken, (req, res) => {
  res.json({
    allow_staff_auto_log: gateSettings.allow_staff_auto_log === 1,
    allow_visitor_express: gateSettings.allow_visitor_express === 1,
    updated_by: gateSettings.updated_by,
    updated_at: gateSettings.updated_at
  });
});

app.post('/api/admin/gate-settings', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / ගේට්ටු ප්‍රතිපත්ති වෙනස් කිරීමට සුපිරි පාලක බලතල අවශ්‍යයි' });
  }

  const { allow_staff_auto_log, allow_visitor_express } = req.body;
  const staffVal = allow_staff_auto_log ? '1' : '0';
  const visitorVal = allow_visitor_express ? '1' : '0';
  const adminUser = req.user.display_name || req.user.username || 'Super Admin';

  const sqlStaff = `
    INSERT INTO system_settings (setting_key, setting_value, updated_by, updated_at)
    VALUES ('allow_staff_auto_log', ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP
  `;
  const sqlVisitor = `
    INSERT INTO system_settings (setting_key, setting_value, updated_by, updated_at)
    VALUES ('allow_visitor_express', ?, ?, CURRENT_TIMESTAMP)
    ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP
  `;

  db.run(sqlStaff, [staffVal, adminUser], (err1) => {
    if (err1) return res.status(500).json({ error: 'Failed to update Staff Auto-Log policy' });
    db.run(sqlVisitor, [visitorVal, adminUser], (err2) => {
      if (err2) return res.status(500).json({ error: 'Failed to update Visitor Express policy' });

      gateSettings.allow_staff_auto_log = allow_staff_auto_log ? 1 : 0;
      gateSettings.allow_visitor_express = allow_visitor_express ? 1 : 0;
      gateSettings.updated_by = adminUser;
      gateSettings.updated_at = new Date().toISOString();

      logAdminAuditAction(
        req.user.username,
        req.user.role,
        'UPDATE_GATE_POLICIES',
        'GATE_SECURITY_CONSOLE',
        `Staff Auto-Log: ${gateSettings.allow_staff_auto_log === 1 ? 'ENABLED' : 'DISABLED'}, Visitor Express: ${gateSettings.allow_visitor_express === 1 ? 'ENABLED' : 'DISABLED'}`,
        req.ip
      );

      res.json({
        success: true,
        message: 'Gate Security Policies updated successfully / ගේට්ටු ආරක්ෂක ප්‍රතිපත්ති සාර්ථකව යාවත්කාලීන විය',
        settings: {
          allow_staff_auto_log: gateSettings.allow_staff_auto_log === 1,
          allow_visitor_express: gateSettings.allow_visitor_express === 1,
          updated_by: gateSettings.updated_by,
          updated_at: gateSettings.updated_at
        }
      });
    });
  });
});

// 9.4b Automated Email Reporting Settings & Dispatch APIs
app.get('/api/admin/email-settings', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / සුපිරි පාලක බලතල අවශ්‍යයි' });
  }
  res.json({
    enabled: emailReportConfig.enabled === 1,
    recipient: emailReportConfig.recipient,
    time: emailReportConfig.time,
    smtp_host: emailReportConfig.smtp_host,
    smtp_port: emailReportConfig.smtp_port,
    smtp_user: emailReportConfig.smtp_user,
    has_smtp_pass: !!emailReportConfig.smtp_pass,
    has_resend_key: !!emailReportConfig.resend_api_key,
    from_address: emailReportConfig.from_address,
    last_sent_date: emailReportConfig.last_sent_date,
    last_sent_status: emailReportConfig.last_sent_status,
    last_sent_error: emailReportConfig.last_sent_error || ''
  });
});

app.post('/api/admin/email-settings', authenticateToken, (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / සුපිරි පාලක බලතල අවශ්‍යයි' });
  }

  const { enabled, recipient, time, smtp_host, smtp_port, smtp_user, smtp_pass, resend_api_key } = req.body;
  const adminUser = req.user.display_name || req.user.username || 'Super Admin';

  const enabledVal = enabled ? '1' : '0';
  const recipientVal = (recipient && recipient.trim()) || 'admin@doenets.lk';
  const timeVal = (time && time.trim()) || '17:00';

  const queries = [
    { key: 'email_report_enabled', val: enabledVal },
    { key: 'email_report_recipient', val: recipientVal },
    { key: 'email_report_time', val: timeVal }
  ];
  if (resend_api_key !== undefined && String(resend_api_key).trim() !== '') queries.push({ key: 'resend_api_key', val: String(resend_api_key).trim() });
  if (smtp_host !== undefined) queries.push({ key: 'smtp_host', val: String(smtp_host).trim() });
  if (smtp_port !== undefined) queries.push({ key: 'smtp_port', val: String(smtp_port).trim() });
  if (smtp_user !== undefined) queries.push({ key: 'smtp_user', val: String(smtp_user).trim() });
  if (smtp_pass !== undefined && String(smtp_pass).trim() !== '') queries.push({ key: 'smtp_pass', val: String(smtp_pass).trim() });

  queries.forEach(q => {
    db.run(
      `INSERT INTO system_settings (setting_key, setting_value, updated_by)
       VALUES (?, ?, ?)
       ON CONFLICT(setting_key) DO UPDATE SET setting_value = excluded.setting_value, updated_by = excluded.updated_by, updated_at = CURRENT_TIMESTAMP`,
      [q.key, q.val, adminUser]
    );
  });

  emailReportConfig.enabled = enabled ? 1 : 0;
  emailReportConfig.recipient = recipientVal;
  emailReportConfig.time = timeVal;
  if (resend_api_key !== undefined && String(resend_api_key).trim() !== '') emailReportConfig.resend_api_key = String(resend_api_key).trim();
  if (smtp_host !== undefined) emailReportConfig.smtp_host = String(smtp_host).trim();
  if (smtp_port !== undefined) emailReportConfig.smtp_port = parseInt(smtp_port) || 587;
  if (smtp_user !== undefined) emailReportConfig.smtp_user = String(smtp_user).trim();
  if (smtp_pass !== undefined && String(smtp_pass).trim() !== '') emailReportConfig.smtp_pass = String(smtp_pass).trim();

  logAdminAuditAction(req.user.username, req.user.role, 'UPDATE_EMAIL_SETTINGS', recipientVal, `Enabled: ${emailReportConfig.enabled}, Time: ${emailReportConfig.time}`, req.ip);

  res.json({
    success: true,
    message: 'ස්වයංක්‍රීය ඊමේල් වාර්තා සැකසුම් සාර්ථකව සුරකින ලදී',
    settings: {
      enabled: emailReportConfig.enabled === 1,
      recipient: emailReportConfig.recipient,
      time: emailReportConfig.time,
      has_resend_key: !!emailReportConfig.resend_api_key,
      smtp_host: emailReportConfig.smtp_host,
      smtp_port: emailReportConfig.smtp_port,
      smtp_user: emailReportConfig.smtp_user,
      has_smtp_pass: !!emailReportConfig.smtp_pass,
      last_sent_date: emailReportConfig.last_sent_date,
      last_sent_status: emailReportConfig.last_sent_status
    }
  });
});

app.post('/api/admin/email-report/test', authenticateToken, async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin privileges required / සුපිරි පාලක බලතල අවශ්‍යයි' });
  }
  const recipient = req.body.recipient || emailReportConfig.recipient;
  try {
    const result = await sendDailyIntelligenceEmail(recipient);

    let message = '';
    if (result.mode === 'RESEND_API') {
      message = `දෛනික බුද්ධිමත් වාර්තාව ${recipient} වෙත Resend HTTPS API (Port 443) හරහා සාර්ථකව යවන ලදී!`;
    } else if (result.mode === 'RESEND_FAILED') {
      message = `Resend API මඟින් ඊමේල් යැවීම අසාර්ථක විය: ${result.error || 'API Error'}`;
    } else if (result.mode === 'SMTP') {
      message = `දෛනික බුද්ධිමත් වාර්තාව ${recipient} වෙත සැබෑ ඊමේල් පණිවිඩයක් ලෙස (SMTP හරහා) සාර්ථකව යවන ලදී!`;
    } else if (result.mode === 'SIMULATION') {
      message = `වාර්තාව සාර්ථකව සම්පාදනය විය. එහෙත් ඊමේල් සේවාදායකයක් (Resend API හෝ Gmail / Office365) සකසා නොමැති බැවින් එය සැබෑ ඊමේල් ලිපිනයට (Inbox) ලැබුණේ නැත (Simulated Delivery).`;
    } else {
      message = `ඊමේල් යැවීමට නොහැකි විය (SMTP Error): ${result.error || 'Connection Failed'}`;
    }

    res.json({
      success: result.mode === 'SMTP' || result.mode === 'RESEND_API' || result.mode === 'SIMULATION',
      mode: result.mode,
      message,
      result
    });
  } catch (err) {
    res.status(500).json({ error: 'වාර්තාව යැවීමේදී දෝෂයක් ඇති විය: ' + err.message });
  }
});

app.get('/api/admin/email-report/preview', async (req, res) => {
  const token = req.headers['authorization'] ? req.headers['authorization'].split(' ')[1] : req.query.token;
  if (!token) {
    return res.status(401).send('<h3 style="font-family:sans-serif;color:#b91c1c;">අවසර නැත (Unauthorized). කරුණාකර පද්ධතියට Log In වන්න.</h3>');
  }

  jwt.verify(token, JWT_SECRET, async (err, user) => {
    if (err) return res.status(403).send('<h3 style="font-family:sans-serif;color:#b91c1c;">වලංගු නොවන හෝ කල්ඉකුත් වූ Session එකක්.</h3>');
    try {
      const report = await compileDailyIntelligenceReport();
      const html = generateEmailReportHtml(report);
      res.setHeader('Content-Type', 'text/html; charset=utf-8');
      res.send(html);
    } catch (e) {
      res.status(500).send('Error compiling preview: ' + e.message);
    }
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
    evaluation_inside: 0,
    today_total_visitors: 0
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

    db.get("SELECT COUNT(*) as count FROM passes WHERE category = 'VISITOR' AND DATE(created_at, 'localtime') = DATE('now', 'localtime')", [], (tErr, tRow) => {
      if (!tErr && tRow) {
        stats.today_total_visitors = tRow.count || 0;
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
});

// 10.1 Get Daily Visitors Directory & Historical Log (Authenticated)
app.get('/api/admin/visitors', authenticateToken, (req, res) => {
  const targetDate = req.query.date ? req.query.date.trim() : null;
  const search = req.query.search ? `%${req.query.search.trim().toUpperCase()}%` : null;
  const status = req.query.status && req.query.status !== 'ALL' ? req.query.status.trim() : null;
  const branch = req.query.branch && req.query.branch !== 'ALL' ? req.query.branch.trim() : null;

  let whereClauses = ["category = 'VISITOR'"];
  let params = [];

  if (targetDate) {
    whereClauses.push("DATE(created_at, 'localtime') = ?");
    params.push(targetDate);
  } else {
    whereClauses.push("DATE(created_at, 'localtime') = DATE('now', 'localtime')");
  }

  if (status) {
    whereClauses.push("status = ?");
    params.push(status);
  }

  if (branch) {
    whereClauses.push("branch_name = ?");
    params.push(branch);
  }

  if (search) {
    whereClauses.push("(UPPER(person_name) LIKE ? OR UPPER(nic_number) LIKE ? OR UPPER(pass_code) LIKE ? OR UPPER(mobile_number) LIKE ? OR UPPER(vehicle_number) LIKE ?)");
    params.push(search, search, search, search, search);
  }

  const whereSql = whereClauses.length > 0 ? `WHERE ${whereClauses.join(' AND ')}` : '';
  const sql = `SELECT * FROM passes ${whereSql} ORDER BY id DESC LIMIT 500`;

  db.all(sql, params, (err, rows) => {
    if (err) {
      console.error('Error fetching visitors:', err);
      return res.status(500).json({ error: 'Failed to fetch visitor records' });
    }

    // Daily summary statistics for the selected date
    let statParams = [];
    let statWhere = "WHERE category = 'VISITOR' AND ";
    if (targetDate) {
      statWhere += "DATE(created_at, 'localtime') = ?";
      statParams.push(targetDate);
    } else {
      statWhere += "DATE(created_at, 'localtime') = DATE('now', 'localtime')";
    }

    db.all(`SELECT status, COUNT(*) as count FROM passes ${statWhere} GROUP BY status`, statParams, (sErr, statRows) => {
      let stats = {
        total: 0,
        pending: 0,
        checked_in: 0,
        checked_out: 0
      };

      if (!sErr && statRows) {
        statRows.forEach(r => {
          stats.total += r.count;
          if (r.status === 'PENDING_VERIFICATION') stats.pending = r.count;
          if (r.status === 'CHECKED_IN') stats.checked_in = r.count;
          if (r.status === 'CHECKED_OUT') stats.checked_out = r.count;
        });
      }

      res.json({
        date: targetDate || 'today',
        stats,
        visitors: rows || []
      });
    });
  });
});

// 10.2 Executive Analytics & Institutional Intelligence API (Authenticated via Bearer Token or X-API-KEY)
app.get('/api/admin/analytics', authenticateToken, (req, res) => {
  const timeframe = req.query.timeframe || (req.query.start_date ? 'custom' : 'today'); // 'today', 'yesterday', 'week', 'month', 'all', 'custom'
  const categoryFilter = req.query.category && req.query.category !== 'ALL' ? req.query.category.trim().toUpperCase() : null;
  const startDate = req.query.start_date ? req.query.start_date.trim() : null;
  const endDate = req.query.end_date ? req.query.end_date.trim() : null;

  let logWhereClauses = [];
  let logParams = [];

  if (startDate && endDate) {
    logWhereClauses.push("DATE(timestamp, 'localtime') >= DATE(?) AND DATE(timestamp, 'localtime') <= DATE(?)");
    logParams.push(startDate, endDate);
  } else if (startDate) {
    logWhereClauses.push("DATE(timestamp, 'localtime') >= DATE(?)");
    logParams.push(startDate);
  } else if (timeframe === 'today') {
    logWhereClauses.push("DATE(timestamp, 'localtime') = DATE('now', 'localtime')");
  } else if (timeframe === 'yesterday') {
    logWhereClauses.push("DATE(timestamp, 'localtime') = DATE('now', 'localtime', '-1 day')");
  } else if (timeframe === 'week') {
    logWhereClauses.push("DATE(timestamp, 'localtime') >= DATE('now', 'localtime', '-7 days')");
  } else if (timeframe === 'month') {
    logWhereClauses.push("DATE(timestamp, 'localtime') >= DATE('now', 'localtime', '-30 days')");
  }

  if (categoryFilter) {
    logWhereClauses.push("category = ?");
    logParams.push(categoryFilter);
  }

  const logWhereSql = logWhereClauses.length > 0 ? `WHERE ${logWhereClauses.join(' AND ')}` : '';
  const logSql = `SELECT * FROM gate_logs ${logWhereSql} ORDER BY timestamp ASC`;

  db.all(logSql, logParams, (err, logs) => {
    if (err) {
      console.error('Error fetching analytics logs:', err);
      return res.status(500).json({ error: 'Failed to load analytics data' });
    }
    logs = logs || [];

    let totalCheckIns = 0;
    let totalCheckOuts = 0;
    let branchCounts = {};
    let categoryCounts = {};
    let hourlyCounts = {};
    for (let h = 6; h <= 18; h++) {
      const hourStr = String(h).padStart(2, '0') + ':00';
      hourlyCounts[hourStr] = 0;
    }

    let passVisits = {};
    let staffPunctuality = { on_time: 0, late: 0, total_logged: 0 };

    logs.forEach(l => {
      let dateStr = String(l.timestamp || '');
      if (!dateStr.endsWith('Z') && !dateStr.includes('+')) {
        dateStr = dateStr.replace(' ', 'T');
      }
      const d = new Date(dateStr);
      const hour = isNaN(d.getTime()) ? 8 : d.getHours();

      if (l.action_type === 'CHECK_IN') {
        totalCheckIns++;
        const hourKey = String(hour).padStart(2, '0') + ':00';
        if (hourlyCounts[hourKey] !== undefined) {
          hourlyCounts[hourKey]++;
        } else {
          hourlyCounts[hourKey] = 1;
        }

        if (l.category === 'STAFF') {
          staffPunctuality.total_logged++;
          const mins = hour * 60 + d.getMinutes();
          if (mins <= 8 * 60 + 30) {
            staffPunctuality.on_time++;
          } else {
            staffPunctuality.late++;
          }
        }

        if (!passVisits[l.pass_code]) passVisits[l.pass_code] = [];
        passVisits[l.pass_code].push({ in: d, out: null });

      } else if (l.action_type === 'CHECK_OUT') {
        totalCheckOuts++;
        if (passVisits[l.pass_code] && passVisits[l.pass_code].length > 0) {
          const lastVisit = passVisits[l.pass_code][passVisits[l.pass_code].length - 1];
          if (lastVisit && !lastVisit.out) {
            lastVisit.out = d;
          }
        }
      }

      const b = l.branch_name || 'General Administration';
      branchCounts[b] = (branchCounts[b] || 0) + 1;

      const c = l.category || 'VISITOR';
      categoryCounts[c] = (categoryCounts[c] || 0) + 1;
    });

    // Compute average dwell time
    let totalDwellMinutes = 0;
    let completedVisitCount = 0;
    Object.values(passVisits).forEach(visits => {
      visits.forEach(v => {
        if (v.in && v.out && !isNaN(v.in.getTime()) && !isNaN(v.out.getTime())) {
          const diffMs = v.out.getTime() - v.in.getTime();
          if (diffMs > 0 && diffMs < 24 * 3600 * 1000) {
            totalDwellMinutes += Math.round(diffMs / 60000);
            completedVisitCount++;
          }
        }
      });
    });

    const avgDwellMins = completedVisitCount > 0 ? Math.round(totalDwellMinutes / completedVisitCount) : 0;

    // Determine Peak Hour
    let peakHour = 'No entries';
    let peakCount = 0;
    Object.entries(hourlyCounts).forEach(([h, cnt]) => {
      if (cnt > peakCount) {
        peakCount = cnt;
        const startH = parseInt(h);
        const ampm = startH >= 12 ? 'PM' : 'AM';
        const displayH = startH > 12 ? (startH - 12) : (startH === 0 ? 12 : startH);
        const nextH = startH + 1;
        const nextAmpm = nextH >= 12 ? 'PM' : 'AM';
        const nextDisplayH = nextH > 12 ? (nextH - 12) : nextH;
        peakHour = `${displayH}:00 ${ampm} - ${nextDisplayH}:00 ${nextAmpm} (${cnt} entries)`;
      }
    });

    // Fetch passes currently inside & overstay alerts
    let passWhere = ["status = 'CHECKED_IN'"];
    let passParams = [];
    if (categoryFilter) {
      passWhere.push("category = ?");
      passParams.push(categoryFilter);
    }
    const passSql = `SELECT * FROM passes WHERE ${passWhere.join(' AND ')} ORDER BY created_at DESC`;

    db.all(passSql, passParams, (pErr, checkedInPasses) => {
      checkedInPasses = checkedInPasses || [];
      const now = Date.now();
      let vehiclesInside = 0;
      let overstayList = [];

      checkedInPasses.forEach(p => {
        if (p.vehicle_number && p.vehicle_number.trim() && p.vehicle_number.toUpperCase() !== 'NONE') {
          vehiclesInside++;
        }

        // Calculate hours inside
        let entryTime = null;
        if (passVisits[p.pass_code] && passVisits[p.pass_code].length > 0) {
          const lastVisit = passVisits[p.pass_code][passVisits[p.pass_code].length - 1];
          if (lastVisit && lastVisit.in && !isNaN(lastVisit.in.getTime())) {
            entryTime = lastVisit.in;
          }
        }
        if (!entryTime) {
          let str = String(p.created_at || '');
          if (!str.endsWith('Z') && !str.includes('+')) str = str.replace(' ', 'T');
          entryTime = new Date(str);
        }

        const elapsedMs = now - (entryTime.getTime() || now);
        const elapsedMins = Math.max(0, Math.round(elapsedMs / 60000));
        const hoursInside = (elapsedMins / 60).toFixed(1);

        if (elapsedMins >= 240) { // Over 4 hours
          overstayList.push({
            pass_code: p.pass_code,
            person_name: p.person_name,
            employee_number: p.employee_number || null,
            nic_number: p.nic_number,
            category: p.category,
            branch_name: p.branch_name,
            vehicle_number: p.vehicle_number || '-',
            entry_time: entryTime.toISOString(),
            elapsed_minutes: elapsedMins,
            hours_display: `${hoursInside} hrs`
          });
        }
      });

      // Staff Movement & Disciplinary Analytics (Frequent Exits, Longest Outings, Night Shift Outings)
      let staffLogsByPass = {};
      logs.forEach(l => {
        if (l.category === 'STAFF') {
          if (!staffLogsByPass[l.pass_code]) {
            staffLogsByPass[l.pass_code] = {
              pass_code: l.pass_code,
              person_name: l.person_name,
              nic_number: l.nic_number,
              branch_name: l.branch_name,
              logs: []
            };
          }
          let dateStr = String(l.timestamp || '');
          if (!dateStr.endsWith('Z') && !dateStr.includes('+')) dateStr = dateStr.replace(' ', 'T');
          staffLogsByPass[l.pass_code].logs.push({
            action_type: l.action_type,
            time: new Date(dateStr)
          });
        }
      });

      let frequentExits = [];
      let longestOutings = [];
      let nightOutings = [];

      Object.values(staffLogsByPass).forEach(staff => {
        staff.logs.sort((a, b) => a.time.getTime() - b.time.getTime());

        let exitCount = 0;
        let checkInCount = 0;
        let exitTimes = [];

        for (let i = 0; i < staff.logs.length; i++) {
          const item = staff.logs[i];
          if (item.action_type === 'CHECK_IN') {
            checkInCount++;
          } else if (item.action_type === 'CHECK_OUT') {
            exitCount++;
            exitTimes.push(item.time);

            let returnTime = null;
            for (let j = i + 1; j < staff.logs.length; j++) {
              if (staff.logs[j].action_type === 'CHECK_IN') {
                returnTime = staff.logs[j].time;
                break;
              }
            }

            const outStart = item.time;
            const outEnd = returnTime || new Date(now);
            const diffMs = outEnd.getTime() - outStart.getTime();
            const durationMins = Math.max(1, Math.round(diffMs / 60000));
            const h = Math.floor(durationMins / 60);
            const m = durationMins % 60;
            const durationDisplay = h > 0 ? `${h}h ${m}m` : `${m}m`;

            const exitHour = outStart.getHours();
            const isNight = (exitHour >= 19 || exitHour < 6); // 7:00 PM to 6:00 AM

            const outingRecord = {
              pass_code: staff.pass_code,
              person_name: staff.person_name,
              branch_name: staff.branch_name,
              exit_time: outStart.toISOString(),
              return_time: returnTime ? returnTime.toISOString() : null,
              duration_minutes: durationMins,
              duration_display: durationDisplay,
              status: returnTime ? 'RETURNED' : 'STILL_OUTSIDE',
              is_night: isNight
            };

            if (durationMins >= 10 || !returnTime) {
              longestOutings.push(outingRecord);
            }

            if (isNight && (durationMins >= 15 || !returnTime)) {
              nightOutings.push({
                ...outingRecord,
                status_display: returnTime ? 'Returned at Night' : 'Still Outside (Night Alert!)'
              });
            }
          }
        }

        if (exitCount >= 1) {
          frequentExits.push({
            pass_code: staff.pass_code,
            person_name: staff.person_name,
            branch_name: staff.branch_name,
            exit_count: exitCount,
            check_in_count: checkInCount,
            last_exit_time: exitTimes.length > 0 ? exitTimes[exitTimes.length - 1].toISOString() : null,
            all_exit_times: exitTimes.map(t => t.toLocaleTimeString())
          });
        }
      });

      frequentExits.sort((a, b) => b.exit_count - a.exit_count);
      longestOutings.sort((a, b) => b.duration_minutes - a.duration_minutes);
      nightOutings.sort((a, b) => new Date(b.exit_time).getTime() - new Date(a.exit_time).getTime());

      // Total registered staff
      db.get("SELECT COUNT(*) as count FROM passes WHERE category = 'STAFF'", [], (stfErr, stfRow) => {
        const totalRegisteredStaff = stfRow ? (stfRow.count || 0) : 0;
        const staffCurrentlyInside = checkedInPasses.filter(p => p.category === 'STAFF').length;

        // Direct CSV File Export via API (format=csv)
        if (req.query.format === 'csv') {
          let csv = 'DEPARTMENT OF EXAMINATIONS SRI LANKA - GATE PASS EXECUTIVE ANALYTICS REPORT\r\n';
          csv += `Generated At,${new Date().toISOString()}\r\n`;
          csv += `Timeframe,${timeframe}\r\n`;
          csv += `Category Filter,${categoryFilter || 'ALL'}\r\n\r\n`;

          csv += 'KEY PERFORMANCE METRICS\r\n';
          csv += `Total Check-Ins,${totalCheckIns}\r\n`;
          csv += `Total Check-Outs,${totalCheckOuts}\r\n`;
          csv += `Currently Inside Campus,${checkedInPasses.length}\r\n`;
          csv += `Average Dwell Time (Minutes),${avgDwellMins}\r\n`;
          csv += `Peak Entry Hour,${peakHour}\r\n`;
          csv += `Campus Vehicles,${vehiclesInside}\r\n`;
          csv += `Overstay Alerts (> 4 hrs),${overstayList.length}\r\n\r\n`;

          csv += 'STAFF ATTENDANCE METRICS\r\n';
          csv += `Total Registered Staff,${totalRegisteredStaff}\r\n`;
          csv += `Staff Currently on Duty,${staffCurrentlyInside}\r\n`;
          csv += `On-Time Arrivals (Before 8:30 AM),${staffPunctuality.on_time}\r\n`;
          csv += `Late Arrivals (After 8:30 AM),${staffPunctuality.late}\r\n\r\n`;

          csv += 'STAFF FREQUENT EXITS (REPEAT OUTINGS)\r\n';
          csv += 'Pass Code,Name,Branch,Exit Count,Check-Ins,Departure Times\r\n';
          frequentExits.forEach(f => {
            csv += `"${f.pass_code}","${f.person_name}","${f.branch_name || '-'}",${f.exit_count},${f.check_in_count},"${(f.all_exit_times || []).join('; ')}"\r\n`;
          });
          csv += '\r\n';

          csv += 'LONGEST OUT-OF-OFFICE DURATIONS\r\n';
          csv += 'Pass Code,Name,Branch,Exit Time,Return Time,Duration,Status\r\n';
          longestOutings.forEach(l => {
            csv += `"${l.pass_code}","${l.person_name}","${l.branch_name || '-'}",${l.exit_time},${l.return_time || 'STILL_OUT'},${l.duration_display},${l.status}\r\n`;
          });
          csv += '\r\n';

          csv += 'NIGHT SHIFT OUTINGS (7 PM - 6 AM)\r\n';
          csv += 'Pass Code,Name,Branch,Exit Time,Return Time,Duration,Status\r\n';
          nightOutings.forEach(n => {
            csv += `"${n.pass_code}","${n.person_name}","${n.branch_name || '-'}",${n.exit_time},${n.return_time || 'STILL_OUT'},${n.duration_display},${n.status_display}\r\n`;
          });
          csv += '\r\n';

          csv += 'BRANCH WORKLOAD BREAKDOWN\r\n';
          csv += 'Branch Name,Visit Count\r\n';
          Object.entries(branchCounts).forEach(([b, cnt]) => {
            csv += `"${b.replace(/"/g, '""')}",${cnt}\r\n`;
          });

          res.setHeader('Content-Type', 'text/csv; charset=utf-8');
          res.setHeader('Content-Disposition', `attachment; filename=DoENets_Gate_Analytics_${timeframe}_${new Date().toISOString().split('T')[0]}.csv`);
          return res.send(csv);
        }

        res.json({
          timeframe,
          category: categoryFilter || 'ALL',
          summary: {
            total_entries: totalCheckIns,
            total_exits: totalCheckOuts,
            currently_inside: checkedInPasses.length,
            avg_dwell_minutes: avgDwellMins,
            peak_hour: peakHour,
            vehicles_inside: vehiclesInside,
            overstay_count: overstayList.length
          },
          staff_analytics: {
            total_registered: totalRegisteredStaff,
            currently_inside: staffCurrentlyInside,
            punctuality: staffPunctuality
          },
          staff_movement: {
            frequent_exits: frequentExits.slice(0, 50),
            longest_outings: longestOutings.slice(0, 50),
            night_outings: nightOutings.slice(0, 50)
          },
          hourly_traffic: hourlyCounts,
          branch_demand: branchCounts,
          category_distribution: categoryCounts,
          overstay_list: overstayList,
          currently_inside_list: checkedInPasses.slice(0, 50)
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

// 12. Full System Database Backup Import / Restore API (Authenticated Super Admin)
app.post('/api/admin/backup/import', authenticateToken, async (req, res) => {
  if (req.user.role !== 'SUPER_ADMIN') {
    return res.status(403).json({ error: 'Super Admin access required for database restore' });
  }

  const { passes, gate_logs } = req.body;
  if (!Array.isArray(passes) && !Array.isArray(gate_logs)) {
    return res.status(400).json({ error: 'Invalid backup file format. Expected passes or gate_logs.' });
  }

  let importedPasses = 0;
  let skippedPasses = 0;

  if (Array.isArray(passes)) {
    for (const p of passes) {
      if (!p.pass_code) continue;
      await new Promise((resolve) => {
        db.get('SELECT id FROM passes WHERE pass_code = ?', [p.pass_code], (err, row) => {
          if (!err && !row) {
            db.run(`
              INSERT INTO passes (
                daily_no, pass_code, category, person_name, nic_number, 
                mobile_number, vehicle_number, branch_name, purpose, 
                access_zones, valid_from, valid_to, status, rfid_card_uid, 
                created_by, created_at
              ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            `, [
              p.daily_no || 1, p.pass_code, p.category, p.person_name, p.nic_number,
              p.mobile_number || '', p.vehicle_number || '', p.branch_name || '', p.purpose || '',
              p.access_zones || 'GENERAL', p.valid_from || new Date().toISOString(), p.valid_to || null,
              p.status || 'APPROVED', p.rfid_card_uid || null, p.created_by || 'BACKUP_RESTORE', p.created_at || new Date().toISOString()
            ], (insErr) => {
              if (!insErr) importedPasses++;
              resolve();
            });
          } else {
            skippedPasses++;
            resolve();
          }
        });
      });
    }
  }

  let importedLogs = 0;
  if (Array.isArray(gate_logs)) {
    for (const l of gate_logs) {
      if (!l.pass_code) continue;
      await new Promise((resolve) => {
        db.run(`
          INSERT INTO gate_logs (
            pass_code, person_name, nic_number, category, branch_name, 
            action_type, timestamp, security_officer_name
          ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `, [
          l.pass_code, l.person_name, l.nic_number, l.category, l.branch_name,
          l.action_type, l.timestamp || new Date().toISOString(), l.security_officer_name || 'Security Gate'
        ], (logErr) => {
          if (!logErr) importedLogs++;
          resolve();
        });
      });
    }
  }

  logAdminAuditAction(req.user.username, req.user.role, 'IMPORT_DB_RESTORE', '-', `Restored ${importedPasses} passes, ${importedLogs} logs from backup`, req.ip);

  res.json({
    success: true,
    message: `දත්ත සාර්ථකව ප්‍රතිස්ථාපනය කරන ලදී. (ඇතුළත් කළ පාස්: ${importedPasses}, කලින් තිබූ පාස්: ${skippedPasses}, ආරක්ෂක ලොග්: ${importedLogs})`,
    importedPasses,
    skippedPasses,
    importedLogs
  });
});

// 13. System Database Status Diagnostic Endpoint
app.get('/api/system/db-status', async (req, res) => {
  try {
    const status = await getDbStatus(true);
    res.json(status);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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
  preloadPassCache();
});
