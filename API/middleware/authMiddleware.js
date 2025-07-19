// API/middleware/authMiddleware.js - Middleware for JWT authentication

const jwt = require('jsonwebtoken');
const { secret } = require('../config/jwt'); // JWT secret key

/**
 * Middleware to verify JWT token and authenticate user.
 * Also checks if the user's email is verified.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
const authMiddleware = (req, res, next) => {
    // 1. Get token from header
    // The token is usually sent in the 'Authorization' header as 'Bearer TOKEN'
    const authHeader = req.header('Authorization');

    if (!authHeader) {
        return res.status(401).json({ message: 'No token, authorization denied.' });
    }

    // Extract the token part after 'Bearer '
    const token = authHeader.split(' ')[1];

    if (!token) {
        return res.status(401).json({ message: 'Token format invalid, authorization denied.' });
    }

    try {
        // 2. Verify token
        // jwt.verify throws an error if the token is invalid or expired
        const decoded = jwt.verify(token, secret);

        // 3. Attach user information to the request object
        // This makes user data available in subsequent route handlers
        req.user = decoded; // decoded will contain { id: userId, email: userEmail, is_verified: boolean, iat: ..., exp: ... }

        // 4. Check if user's email is verified (NEW)
        if (!req.user.is_verified) {
            return res.status(403).json({ message: 'Access denied. Please verify your email address.' });
        }

        next(); // Proceed to the next middleware/route handler

    } catch (error) {
        // Handle different JWT errors
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Token expired.' });
        }
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ message: 'Token invalid.' });
        }
        // Catch any other unexpected errors during verification
        next(error); // Pass to general error handler
    }
};

module.exports = authMiddleware;
