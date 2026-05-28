// server/models/db.js — MongoDB connection + models
const mongoose = require('mongoose');
const logger   = require('../utils/logger');

// ---- Connect ----
async function connectDB(uri) {
  if (!uri) {
    logger.warn('MongoDB URI not set — running without database (localStorage only)');
    return false;
  }
  try {
    await mongoose.connect(uri);
    logger.info('✅ MongoDB connected');
    return true;
  } catch (err) {
    logger.error('MongoDB connection failed:', err.message);
    return false;
  }
}

// ---- User Model ----
const userSchema = new mongoose.Schema({
  name:      { type: String, required: true, trim: true, maxlength: 100 },
  email:     { type: String, required: true, unique: true, lowercase: true, trim: true },
  password:  { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  lastLogin: { type: Date }
});

// ---- Scan Model ----
const scanSchema = new mongoose.Schema({
  userId:        { type: mongoose.Schema.Types.ObjectId, ref: 'User', default: null },
  url:           { type: String, required: true, maxlength: 2000 },
  finalScore:    { type: Number, min: 0, max: 100 },
  verdict:       { type: String, enum: ['Safe', 'Suspicious', 'Phishing'] },
  threatCategory:{ type: String },
  analysis:      { type: String },
  topRisks:      [String],
  localChecks:   { type: Object },
  sources:       { type: Object },   // which intelligence sources fired
  ip:            { type: String },   // requester IP
  createdAt:     { type: Date, default: Date.now }
});

scanSchema.index({ userId: 1, createdAt: -1 });
scanSchema.index({ verdict: 1 });
scanSchema.index({ createdAt: -1 });

const User = mongoose.models.User || mongoose.model('User', userSchema);
const Scan = mongoose.models.Scan || mongoose.model('Scan', scanSchema);

module.exports = { connectDB, User, Scan };
