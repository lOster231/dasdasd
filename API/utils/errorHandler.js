// API/utils/errorHandler.js - Centralized error handling middleware

/**
 * Global error handling middleware for Express.
 * Catches errors passed from route handlers and other middleware.
 * @param {Error} err - The error object.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function (not used here but required by Express).
 */
const errorHandler = (err, req, res, next) => {
    // Log the error for debugging purposes (in a real app, use a proper logging library like Winston or Morgan)
    console.error('API Error:', err.stack);

    // Determine the status code based on the error type or default to 500
    const statusCode = err.statusCode || 500;

    // Send a generic error message in production for security,
    // but include more details in development.
    const message = process.env.NODE_ENV === 'development' ? err.message : 'An unexpected error occurred.';

    res.status(statusCode).json({
        message: message,
        // In development, you might want to send the full error stack
        ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
    });
};

module.exports = errorHandler;
