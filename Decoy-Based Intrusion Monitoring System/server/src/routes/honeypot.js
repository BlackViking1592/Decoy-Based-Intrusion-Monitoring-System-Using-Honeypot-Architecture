const express = require('express');
const router = express.Router();
const db = require('../db/connection');
const sendMail = require('../utils/sendMail');
const { logAttackerActivity } = require('../services/honeypotService') || { logAttackerActivity: async ()=>{} };

// Enter honeypot (this route will be used when a honeypot user logs in)
router.post('/enter', async (req, res) => {
  const attackerIP = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const ua = req.get('User-Agent') || '';
  const target_email = req.body.target_email || process.env.HONEYPOT_EMAIL || 'honeypot@local';
  try {
    // find honeypot user
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [target_email]);
    if (rows.length === 0) {
      return res.status(404).json({error:'honeypot user not found'});
    }
    const user = rows[0];
    // create intrusion record
    const [r] = await db.execute('INSERT INTO honeypot_intrusions (user_id, attacker_ip) VALUES (?, ?)', [user.id, attackerIP]);
    const intrusionId = r.insertId;
    // save a snapshot of fake data
    const fakeData = JSON.stringify({name:'ACME Corp', revenue:'USD 1,200,000', secrets:['fake-api-key-123','internal-plan-v1']});
    await db.execute('INSERT INTO stolen_snapshots (attacker_ip, attacker_ua, data_snapshot) VALUES (?, ?, ?)', [attackerIP, ua, fakeData]);
    // notify admin
    try {
      await sendMail(process.env.ADMIN_EMAIL, `[HONEYPOT] Honeypot accessed: ${target_email}`, `Attacker IP: ${attackerIP}\nUA: ${ua}\nIntrusion ID: ${intrusionId}`);
    } catch (e) { console.error('mail error', e.message); }
    return res.json({ok:true, intrusionId, fakeData, token:'HONEYPOT_SESSION'});
  } catch (e) {
    console.error(e);
    res.status(500).json({error:'server error'});
  }
});

// Middleware to protect honeypot actions
router.use((req, res, next) => {
  const token = req.headers['authorization'];
  if (!token || token !== 'HONEYPOT_SESSION') return res.status(403).json({error:'Forbidden'});
  next();
});

router.get('/fake-data', async (req, res) => {
  const intrusionId = req.headers['x-intrusion-id'];
  if (!intrusionId) return res.status(400).json({error:'Missing intrusion id'});
  // log view
  await db.execute('INSERT INTO attacker_activity_log (intrusion_id, action, details) VALUES (?, ?, ?)', [intrusionId, 'VIEW_FAKE_DATA', 'Attacker viewed fake dataset']);
  const [rows] = await db.execute('SELECT * FROM fake_corporate_data');
  res.json({ok:true, data:rows});
});

router.post('/modify', async (req, res) => {
  const intrusionId = req.headers['x-intrusion-id'];
  const { recordId, newValue } = req.body;
  if (!intrusionId || !recordId || !newValue) return res.status(400).json({error:'Missing fields'});
  await db.execute('INSERT INTO attacker_activity_log (intrusion_id, action, details) VALUES (?, ?, ?)', [intrusionId, 'MODIFY_FAKE_DATA', `Record ${recordId} -> ${newValue}`]);
  res.json({ok:true, message:'Fake change applied'});
});

router.get('/download', async (req, res) => {
  const intrusionId = req.headers['x-intrusion-id'];
  if (!intrusionId) return res.status(400).json({error:'Missing intrusion id'});
  await db.execute('INSERT INTO attacker_activity_log (intrusion_id, action, details) VALUES (?, ?, ?)', [intrusionId, 'DATA_THEFT', 'Attacker attempted to download fake data']);
  res.json({ok:true, message:'Download simulated — data tracked'});
});

module.exports = router;
