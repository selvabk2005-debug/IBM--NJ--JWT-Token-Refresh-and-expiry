const mongoose = require('mongoose');

const RefreshTokenSchema = new mongoose.Schema({
  token: { type: String, required: true },
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  expiresAt: { type: Date, required: true },
  createdAt: { type: Date, default: Date.now }
});

RefreshTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 }); // optional TTL index if you like

module.exports = mongoose.model('RefreshToken', RefreshTokenSchema);