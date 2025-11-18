const db = require('../db/connection');
const sendMail = require('../utils/sendMail');

async function logIntrusion(email, ip, reason) {
  try {
    await db.execute('INSERT INTO activity_logs (user_email, attempted_password, ip, user_agent, endpoint, action, result) VALUES (?, ?, ?, ?, ?, ?, ?)', [email, '', ip, '', '/auth', reason, 'suspicious']);
  } catch (e) { console.error(e); }
}

async function triggerHoneypot(userId, attackerIP) {
  try {
    const [r] = await db.execute('INSERT INTO honeypot_intrusions (user_id, attacker_ip) VALUES (?, ?)', [userId, attackerIP]);
    const id = r.insertId;
    try { await sendMail(process.env.ADMIN_EMAIL, '[HONEYPOT] Accessed', `IntrusionID: ${id} IP: ${attackerIP}`); } catch(e){console.error(e);}
    return id;
  } catch (e) { console.error(e); return null; }
}

async function logAttackerActivity(intrusionId, action, details) {
  try {
    await db.execute('INSERT INTO attacker_activity_log (intrusion_id, action, details) VALUES (?, ?, ?)', [intrusionId, action, details]);
  } catch (e) { console.error(e); }
}

module.exports = { logIntrusion, triggerHoneypot, logAttackerActivity };
