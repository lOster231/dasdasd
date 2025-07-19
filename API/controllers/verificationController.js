// API/controllers/verificationController.js - Handles email verification logic

const jwt = require('jsonwebtoken'); // For verifying JSON Web Tokens
const userModel = require('../models/userModel'); // Database interactions for users
const { verificationSecret } = require('../config/jwt'); // JWT verification secret from config

/**
 * Handles the email verification process when a user clicks the verification link.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.verifyEmail = async (req, res, next) => {
    try {
        const { token } = req.params; // Get the token from the URL parameters

        // IMPORTANT: Use process.env.FRONTEND_URL which should point to your React app's base URL
        // e.g., https://cpp-hub.com or http://localhost:5173
        const frontendBaseUrl = process.env.FRONTEND_URL;
        const verificationResultPagePath = '/verification-result'; // Path to your React component

        if (!token) {
            // Redirect to frontend with error if token is missing
            return res.redirect(`${frontendBaseUrl}${verificationResultPagePath}?status=error&message=${encodeURIComponent('Verification token is missing.')}`);
        }

        let decoded;
        try {
            // Verify the token using the verification secret.
            decoded = jwt.verify(token, verificationSecret);
        } catch (jwtError) {
            // Handle specific JWT errors and redirect to frontend with appropriate message
            let errorMessage = 'Invalid verification link.';
            if (jwtError.name === 'TokenExpiredError') {
                errorMessage = 'Verification link has expired. Please request a new one.';
            }
            return res.redirect(`${frontendBaseUrl}${verificationResultPagePath}?status=error&message=${encodeURIComponent(errorMessage)}`);
        }

        // Find the user in the database using the token.
        const user = await userModel.findByVerificationToken(token);

        if (!user) {
            // If no user is found for the token, it's an valid token but might have been used already
            // or the user was deleted, or the token doesn't match any user.
            return res.redirect(`${frontendBaseUrl}${verificationResultPagePath}?status=error&message=${encodeURIComponent('Verification token not found or already used.')}`);
        }

        if (user.is_verified) {
            // If the user is already verified, inform them.
            console.log(`User ${user.email} is already verified.`);
            return res.redirect(`${frontendBaseUrl}${verificationResultPagePath}?status=already-verified&message=${encodeURIComponent('Your email has already been verified.')}`);
        }

        // Update the user's status to verified and clear the verification token.
        const updateSuccess = await userModel.updateVerificationStatus(user.id, true, null); // Set status to true, clear token

        if (!updateSuccess) {
            // If the database update fails, return a server error.
            return res.redirect(`${frontendBaseUrl}${verificationResultPagePath}?status=error&message=${encodeURIComponent('Failed to update verification status in the database.')}`);
        }

        // Redirect to the frontend's success page
        res.redirect(`${frontendBaseUrl}${verificationResultPagePath}?status=success&message=${encodeURIComponent('Email verified successfully! You can now log in.')}`);

    } catch (error) {
        // Catch any unexpected errors during the process and pass to general error handler.
        next(error);
    }
};