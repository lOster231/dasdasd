// API/routes/verificationRoutes.js - Defines API endpoint for email verification

const express = require('express');
const verificationController = require('../controllers/verificationController'); // Import the verification logic 

const router = express.Router();

// Route for email verification 
// This route expects a token in the URL parameter.
// Example: GET /api/verify-email/your_verification_token_here
router.get('/verify-email/:token', verificationController.verifyEmail);

module.exports = router;