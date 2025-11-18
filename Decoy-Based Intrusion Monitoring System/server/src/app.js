const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const honeypotRoutes = require('./routes/honeypot');
const adminRoutes = require('./routes/admin');

const app = express();

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// basic rate limiter
const limiter = rateLimit({ windowMs: 60*1000, max: 120 });
app.use(limiter);

app.use('/auth', authRoutes);
app.use('/honeypot', honeypotRoutes);
app.use('/admin', adminRoutes);

app.get('/', (req, res) => res.json({status: 'SentinelTrap backend is running'}));

module.exports = app;
