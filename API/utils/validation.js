// API/utils/validation.js - Basic input validation functions

// For more robust validation, consider using a library like 'Joi' or 'express-validator'.
// This example uses simple checks.

/**
 * Validates registration input.
 * @param {Object} data - Object containing username, email, and password.
 * @returns {Object} An object with an 'error' property if validation fails.
 */
exports.validateRegistration = (data) => {
    const { username, email, password } = data;

    if (!username || typeof username !== 'string' || username.length < 3) {
        return { error: { details: [{ message: 'Username must be a string of at least 3 characters.' }] } };
    }
    if (!email || typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email)) {
        return { error: { details: [{ message: 'Please provide a valid email address.' }] } };
    }
    if (!password || typeof password !== 'string' || password.length < 6) {
        return { error: { details: [{ message: 'Password must be a string of at least 6 characters.' }] } };
    }

    return {}; // No error
};

/**
 * Validates login input.
 * @param {Object} data - Object containing email and password.
 * @returns {Object} An object with an 'error' property if validation fails.
 */
exports.validateLogin = (data) => {
    const { email, password } = data;

    if (!email || typeof email !== 'string' || !/^\S+@\S+\.\S+$/.test(email)) {
        return { error: { details: [{ message: 'Please provide a valid email address.' }] } };
    }
    if (!password || typeof password !== 'string') {
        return { error: { details: [{ message: 'Password is required.' }] } };
    }

    return {}; // No error
};
