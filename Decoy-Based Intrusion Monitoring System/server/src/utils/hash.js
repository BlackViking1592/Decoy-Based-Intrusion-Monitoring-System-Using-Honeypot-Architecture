const crypto = require('crypto');
const bcrypt = require('bcrypt');

function sha256(text) {
  return crypto.createHash('sha256').update(String(text)).digest('hex');
}

async function hashPassword(password) {
  if ((process.env.USE_BCRYPT || 'false') === 'true') {
    const rounds = Number(process.env.BCRYPT_ROUNDS) || 12;
    return await bcrypt.hash(password, rounds);
  }
  return sha256(password);
}

async function comparePassword(password, storedHash, algo) {
  if (algo === 'bcrypt') {
    return await bcrypt.compare(password, storedHash);
  }
  return sha256(password) === storedHash;
}

module.exports = { sha256, hashPassword, comparePassword };
