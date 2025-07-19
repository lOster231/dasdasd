// API/routes/authRoutes.js - Defines API endpoints for authentication and profile management

const express = require('express');
const authController = require('../controllers/authController'); // Authentication logic
const authMiddleware = require('../middleware/authMiddleware'); // JWT verification middleware

const router = express.Router();

// Public routes
router.post('/register', authController.register); // Route for user registration
router.post('/login', authController.login);     // Route for user login
router.post('/resend-verification', authController.resendVerificationEmail); // Route to resend verification email

// NEW: Password Reset Routes
router.post('/request-password-reset', authController.requestPasswordReset); // Request a password reset link
router.post('/reset-password/:token', authController.resetPassword);       // Reset password using the token

// Protected routes
router.post('/change-password', authMiddleware, authController.changePassword); // Route to change user password
router.put('/profile', authMiddleware, authController.updateProfile); // NEW: Route to update user profile
router.get('/protected', authMiddleware, authController.getProtectedData); // Example protected route

module.exports = router;
