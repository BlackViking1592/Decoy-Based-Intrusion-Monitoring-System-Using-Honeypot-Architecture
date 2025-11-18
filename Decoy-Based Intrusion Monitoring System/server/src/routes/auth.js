const express = require('express');
const router = express.Router();
const db = require('../db/connection');
const { hashPassword, comparePassword } = require('../utils/hash');

// Register
router.post('/register', async (req, res) => {
  const { name, dob, gender, email, password, confirm } = req.body;
  if (!name || !email || !password || !confirm) return res.status(400).json({error:'Missing fields'});
  if (password !== confirm) return res.status(400).json({error:'Passwords do not match'});
  try {
    const hashed = await hashPassword(password);
    await db.execute(
      'INSERT INTO users (name, dob, gender, email, password_hash, hash_algo) VALUES (?, ?, ?, ?, ?, ?)',
      [name, dob || null, gender || 'O', email, hashed, (process.env.USE_BCRYPT === 'true') ? 'bcrypt' : 'sha256']
    );
    res.json({ok:true});
  } catch (e) {
    console.error(e);
    res.status(500).json({error:'db error or duplicate email'});
  }
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  const ua = req.get('User-Agent') || '';
  try {
    const [rows] = await db.execute('SELECT * FROM users WHERE email = ?', [email]);
    if (rows.length === 0) {
      // log fail
      await db.execute('INSERT INTO activity_logs (user_email, attempted_password, ip, user_agent, endpoint, action, result) VALUES (?, ?, ?, ?, ?, ?, ?)', [email, password, ip, ua, '/auth/login', 'login_attempt_unknown_user', 'failure']);
      return res.status(401).json({error:'Invalid credentials'});
    }
    const user = rows[0];
    const match = await comparePassword(password, user.password_hash, user.hash_algo);
    if (!match) {
      await db.execute('INSERT INTO activity_logs (user_email, attempted_password, ip, user_agent, endpoint, action, result) VALUES (?, ?, ?, ?, ?, ?, ?)', [email, password, ip, ua, '/auth/login', 'login_failed', 'failure']);
      if (user.is_honeypot === 1 || user.hash_algo === 'sha256') {
        // suspicious
        await db.execute('INSERT INTO activity_logs (user_email, attempted_password, ip, user_agent, endpoint, action, result) VALUES (?, ?, ?, ?, ?, ?, ?)', [email, password, ip, ua, '/auth/login', 'suspicious_attempt', 'suspicious']);
      }
      return res.status(401).json({error:'Invalid credentials'});
    }
    // success
    await db.execute('INSERT INTO activity_logs (user_email, attempted_password, ip, user_agent, endpoint, action, result) VALUES (?, ?, ?, ?, ?, ?, ?)', [email, '', ip, ua, '/auth/login', 'login_success', 'success']);
    if (user.is_honeypot === 1) {
      return res.json({ok:true, honeypot:true, message:'Welcome to internal dashboard', token:'HONEYPOT_SESSION'});
    }
    res.json({ok:true, honeypot:false, message:'Login successful'});
  } catch (e) {
    console.error(e);
    res.status(500).json({error:'server error'});
  }
});

module.exports = router;
