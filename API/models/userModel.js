// API/models/userModel.js - Handles database interactions for users

const pool = require('../config/db'); // Import the MySQL connection pool

/**
 * Creates a new user in the database.
 * @param {string} username - The user's username.
 * @param {string} email - The user's email.
 * @param {string} hashedPassword - The hashed password.
 * @param {string} verificationToken - The token for email verification.
 * @param {string} [group='Basic Plan'] - The user's initial group/plan.
 * @param {string|null} [profilePictureUrl=null] - The user's initial profile picture URL.
 * @param {string|null} [name=null] - The user's full name (NEW parameter).
 * @param {string|null} [programmingLanguages=null] - JSON string of programming languages. (NEW)
 * @param {string|null} [activeProjects=null] - JSON string of active projects. (NEW)
 * @returns {Promise<number>} The ID of the newly created user.
 */
exports.createUser = async (username, email, hashedPassword, verificationToken, group = 'Basic Plan', profilePictureUrl = null, name = null, programmingLanguages = null, activeProjects = null) => {
    // Corrected query: Added 'name', 'programming_languages', 'active_projects' columns and their placeholders
    const query = 'INSERT INTO users (username, email, password, is_verified, verification_token, group_name, profile_picture_url, name, programming_languages, active_projects) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)';
    // is_verified is set to 0 (false) by default for new registrations
    const [result] = await pool.execute(query, [username, email, hashedPassword, 0, verificationToken, group, profilePictureUrl, name, programmingLanguages, activeProjects]);
    return result.insertId; // Returns the ID of the newly inserted row
};

/**
 * Finds a user by their ID.
 * @param {number} id - The user's ID.
 * @returns {Promise<Object|null>} The user object if found, otherwise null.
 */
exports.findById = async (id) => {
    // Include all necessary fields for the frontend, including profile_picture_url, group_name, and new fields
    const query = 'SELECT id, username, email, password, is_verified, verification_token, name, bio, nationality, is_profile_public, group_name, profile_picture_url, banned_until, ban_reason, programming_languages, active_projects FROM users WHERE id = ?';
    const [rows] = await pool.execute(query, [id]);
    return rows.length > 0 ? rows[0] : null;
};

/**
 * Finds a user by their email address.
 * @param {string} email - The user's email.
 * @returns {Promise<Object|null>} The user object if found, otherwise null.
 */
exports.findByEmail = async (email) => {
    // Include all necessary fields for the frontend, including profile_picture_url, group_name, and new fields
    const query = 'SELECT id, username, email, password, is_verified, verification_token, name, bio, nationality, is_profile_public, group_name, profile_picture_url, banned_until, ban_reason, programming_languages, active_projects FROM users WHERE email = ?';
    const [rows] = await pool.execute(query, [email]);
    return rows.length > 0 ? rows[0] : null;
};

/**
 * Finds a user by their username.
 * @param {string} username - The user's username.
 * @returns {Promise<Object|null>} The user object if found, otherwise null.
 */
exports.findByUsername = async (username) => {
    // Include all necessary fields for the frontend, including profile_picture_url, group_name, and new fields
    const query = 'SELECT id, username, email, password, is_verified, verification_token, name, bio, nationality, is_profile_public, group_name, profile_picture_url, banned_until, ban_reason, programming_languages, active_projects FROM users WHERE username = ?';
    const [rows] = await pool.execute(query, [username]);
    return rows.length > 0 ? rows[0] : null;
};

/**
 * Finds a user by email or username (for registration checks).
 * @param {string} email - The user's email.
 * @param {string} username - The user's username.
 * @returns {Promise<Object|null>} The user object if found by either email or username, otherwise null.
 */
exports.findByEmailOrUsername = async (email, username) => {
    // Only fetch ID, username, email for conflict checking
    const query = 'SELECT id, username, email FROM users WHERE email = ? OR username = ?';
    const [rows] = await pool.execute(query, [email, username]);
    return rows.length > 0 ? rows[0] : null;
};

/**
 * Finds a user by their email verification token.
 * @param {string} token - The email verification token.
 * @returns {Promise<Object|null>} The user object if found, otherwise null.
 */
exports.findByVerificationToken = async (token) => {
    const query = 'SELECT id, username, email, is_verified FROM users WHERE verification_token = ?';
    const [rows] = await pool.execute(query, [token]);
    return rows.length > 0 ? rows[0] : null;
};

/**
 * Updates a user's email verification status.
 * @param {number} userId - The ID of the user to update.
 * @param {boolean} status - The new verification status (true for verified, false for unverified).
 * @param {string|null} token - The verification token to clear (set to NULL after verification).
 * @returns {Promise<boolean>} True if update was successful, false otherwise.
 */
exports.updateVerificationStatus = async (userId, status, token = null) => {
    const query = 'UPDATE users SET is_verified = ?, verification_token = ? WHERE id = ?';
    const [result] = await pool.execute(query, [status ? 1 : 0, token, userId]);
    return result.affectedRows > 0;
};

/**
 * Updates a user's verification token.
 * Used when resending a verification email.
 * @param {number} userId - The ID of the user to update.
 * @param {string} newToken - The new verification token.
 * @returns {Promise<boolean>} True if update was successful, false otherwise.
 */
exports.updateVerificationToken = async (userId, newToken) => {
    const query = 'UPDATE users SET verification_token = ? WHERE id = ?';
    const [result] = await pool.execute(query, [newToken, userId]);
    return result.affectedRows > 0;
};

/**
 * Updates a user's password.
 * @param {number} userId - The ID of the user whose password to update.
 * @param {string} hashedPassword - The new hashed password.
 * @returns {Promise<boolean>} True if update was successful, false otherwise.
 */
exports.updatePassword = async (userId, hashedPassword) => {
    const query = 'UPDATE users SET password = ? WHERE id = ?';
    const [result] = await pool.execute(query, [hashedPassword, userId]);
    return result.affectedRows > 0;
};

/**
 * Updates a user's profile information (NEW).
 * @param {number} userId - The ID of the user to update.
 * @param {Object} data - Object containing fields to update (name, username, bio, nationality, is_profile_public, profile_picture_url, programming_languages, active_projects).
 * @returns {Promise<boolean>} True if update was successful, false otherwise.
 */
exports.updateUserProfile = async (userId, data) => {
    let queryParts = [];
    let queryValues = [];

    // Dynamically build the UPDATE query based on provided data
    if (data.name !== undefined) {
        queryParts.push('name = ?');
        queryValues.push(data.name);
    }
    if (data.username !== undefined) {
        queryParts.push('username = ?');
        queryValues.push(data.username);
    }
    if (data.bio !== undefined) {
        queryParts.push('bio = ?');
        queryValues.push(data.bio);
    }
    if (data.nationality !== undefined) {
        queryParts.push('nationality = ?');
        queryValues.push(data.nationality);
    }
    if (data.is_profile_public !== undefined) {
        queryParts.push('is_profile_public = ?');
        queryValues.push(data.is_profile_public ? 1 : 0);
    }
    if (data.profile_picture_url !== undefined) {
        queryParts.push('profile_picture_url = ?');
        queryValues.push(data.profile_picture_url);
    }
    // Add other fields like 'group_name', 'banned_until', 'ban_reason' if you want admin tools to update them
    if (data.group_name !== undefined) {
        queryParts.push('group_name = ?');
        queryValues.push(data.group_name);
    }
    if (data.banned_until !== undefined) {
        queryParts.push('banned_until = ?');
        queryValues.push(data.banned_until);
    }
    if (data.ban_reason !== undefined) {
        queryParts.push('ban_reason = ?');
        queryValues.push(data.ban_reason);
    }
    // NEW: Add programming_languages and active_projects
    if (data.programming_languages !== undefined) {
        queryParts.push('programming_languages = ?');
        queryValues.push(data.programming_languages); // Should be JSON string
    }
    if (data.active_projects !== undefined) {
        queryParts.push('active_projects = ?');
        queryValues.push(data.active_projects); // Should be JSON string
    }


    if (queryParts.length === 0) {
        return false; // No fields to update
    }

    const query = `UPDATE users SET ${queryParts.join(', ')} WHERE id = ?`;
    queryValues.push(userId);

    const [result] = await pool.execute(query, queryValues);
    return result.affectedRows > 0;
};

// --- Password Reset Token Management ---

/**
 * Stores a password reset token for a user.
 * @param {number} userId - The ID of the user.
 * @param {string} token - The generated reset token.
 * @param {Date} expiresAt - The expiration timestamp for the token.
 * @returns {Promise<boolean>} True if the token was stored, false otherwise.
 */
exports.createPasswordResetToken = async (userId, token, expiresAt) => {
    // First, invalidate any existing tokens for this user to ensure only one active token at a time
    await pool.execute('UPDATE users SET reset_token = NULL, reset_token_expires_at = NULL WHERE id = ?', [userId]);

    const query = 'UPDATE users SET reset_token = ?, reset_token_expires_at = ? WHERE id = ?';
    const [result] = await pool.execute(query, [token, expiresAt, userId]);
    return result.affectedRows > 0;
};

/**
 * Finds a user by their password reset token and checks its validity.
 * @param {string} token - The password reset token.
 * @returns {Promise<Object|null>} The user object if the token is valid and not expired, otherwise null.
 */
exports.findByPasswordResetToken = async (token) => {
    const query = 'SELECT id, username, email, password, reset_token, reset_token_expires_at FROM users WHERE reset_token = ? AND reset_token_expires_at > NOW()';
    const [rows] = await pool.execute(query, [token]);
    return rows.length > 0 ? rows[0] : null;
};

/**
 * Invalidates a password reset token after it has been used.
 * @param {string} token - The token to invalidate.
 * @returns {Promise<boolean>} True if the token was invalidated, false otherwise.
 */
exports.invalidatePasswordResetToken = async (token) => {
    const query = 'UPDATE users SET reset_token = NULL, reset_token_expires_at = NULL WHERE reset_token = ?';
    const [result] = await pool.execute(query, [token]);
    return result.affectedRows > 0;
};
