const express = require('express');
const router = express.Router();
const db = require('../db/connection');

// simple admin middleware
router.use((req, res, next) => {
  const key = req.headers['x-admin-key'];
  if (!key || key !== process.env.ADMIN_KEY) return res.status(403).json({error:'Forbidden'});
  next();
});

router.get('/intrusions', async (req, res) => {
  const [rows] = await db.execute(`SELECT hi.id intrusion_id, hi.attacker_ip, hi.timestamp, u.email honeypot_email, u.name honeypot_name FROM honeypot_intrusions hi LEFT JOIN users u ON hi.user_id = u.id ORDER BY hi.timestamp DESC`);
  res.json({ok:true, intrusions: rows});
});

router.get('/logs/:id', async (req, res) => {
  const id = req.params.id;
  const [rows] = await db.execute('SELECT action, details, timestamp FROM attacker_activity_log WHERE intrusion_id = ? ORDER BY timestamp ASC', [id]);
  res.json({ok:true, logs: rows});
});

router.get('/login-attempts', async (req, res) => {
  const [rows] = await db.execute('SELECT attempted_email, ip_address, reason, timestamp FROM login_attempts ORDER BY timestamp DESC');
  res.json({ok:true, attempts: rows});
});

router.get('/fake-data', async (req, res) => {
  const [rows] = await db.execute('SELECT * FROM fake_corporate_data');
  res.json({ok:true, data: rows});
});

module.exports = router;
