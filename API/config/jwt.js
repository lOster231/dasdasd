// API/config/jwt.js - JWT Configuration for Authentication and Email Verification

module.exports = {
    // Configuration for regular authentication tokens
    secret: process.env.JWT_SECRET, // The secret key used to sign and verify JWTs
    expiresIn: process.env.JWT_EXPIRES_IN, // The expiration time for JWTs (e.g., '1h', '7d')

    // Configuration for email verification tokens (NEW)
    verificationSecret: process.env.VERIFICATION_SECRET, // Separate secret for verification tokens
    verificationExpiresIn: process.env.VERIFICATION_EXPIRES_IN, // Expiration for verification tokens

    // NEW: Configuration for password reset tokens
    resetSecret: process.env.RESET_SECRET, // Separate secret for password reset tokens
    resetExpiresIn: process.env.RESET_EXPIRES_IN // Expiration for password reset tokens (e.g., '1h')
};
