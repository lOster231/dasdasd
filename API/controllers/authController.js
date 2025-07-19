// API/controllers/authController.js - Handles authentication logic (register, login, resend verification, change password, profile update, password reset)

const bcrypt = require('bcryptjs'); // For hashing and comparing passwords
const jwt = require('jsonwebtoken'); // For creating and verifying JSON Web Tokens
const userModel = require('../models/userModel'); // Database interactions for users
const { secret, expiresIn, verificationSecret, verificationExpiresIn, resetSecret, resetExpiresIn } = require('../config/jwt'); // JWT configuration
const { validateRegistration, validateLogin } = require('../utils/validation'); // Input validation
const emailService = require('../utils/emailService'); // Email sending service
const multer = require('multer'); // For handling multipart/form-data (file uploads)
const path = require('path'); // Node.js path module for file paths
const fs = require('fs'); // Node.js file system module

// --- Multer Configuration for Profile Picture Upload ---
// Define storage for files
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        // Ensure the uploads directory exists
        const uploadDir = path.join(__dirname, '../../uploads/profile_pictures');
        fs.mkdirSync(uploadDir, { recursive: true }); // Create directory if it doesn't exist
        cb(null, uploadDir); // Files will be stored in 'uploads/profile_pictures' relative to app.js
    },
    filename: (req, file, cb) => {
        // Generate a unique filename: userId-timestamp.ext
        const userId = req.user.id; // User ID from authenticated token
        const fileExtension = path.extname(file.originalname);
        cb(null, `${userId}-${Date.now()}${fileExtension}`);
    }
});

// File filter to accept only images
const fileFilter = (req, file, cb) => {
    if (file.mimetype.startsWith('image/')) {
        cb(null, true);
    } else {
        cb(new Error('Only image files are allowed!'), false);
    }
};

// Initialize multer upload middleware
const upload = multer({
    storage: storage,
    fileFilter: fileFilter,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5 MB file size limit
    }
}).single('profilePicture'); // 'profilePicture' is the field name from the frontend FormData

// --- Utility to delete old profile picture file ---
const deleteOldProfilePicture = async (userId) => {
    try {
        const user = await userModel.findById(userId);
        if (user && user.profile_picture_url) {
            // Assuming profile_picture_url is a local path relative to the server
            // If using cloud storage, you'd use the cloud storage SDK here
            const filename = path.basename(user.profile_picture_url);
            const filePath = path.join(__dirname, '../../uploads/profile_pictures', filename);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
                console.log(`Deleted old profile picture: ${filePath}`);
            }
        }
    } catch (error) {
        console.error('Error deleting old profile picture:', error);
    }
};


/**
 * Registers a new user.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.register = async (req, res, next) => {
    try {
        const { username, email, password, name } = req.body; // Added 'name' from frontend

        // 1. Validate input data
        const { error } = validateRegistration(req.body);
        if (error) {
            const errors = error.details.map(detail => detail.message);
            return res.status(400).json({ message: 'Validation failed', errors: errors });
        }

        // 2. Check if user already exists (by email or username)
        const existingUser = await userModel.findByEmailOrUsername(email, username);
        if (existingUser) {
            if (existingUser.email === email) {
                return res.status(409).json({ message: 'Email already registered.' });
            }
            if (existingUser.username === username) {
                return res.status(409).json({ message: 'Username already taken.' });
            }
        }

        // 3. Hash the password
        const salt = await bcrypt.genSalt(10); // Generate a salt for hashing
        const hashedPassword = await bcrypt.hash(password, salt); // Hash the password

        // 4. Generate email verification token
        const verificationToken = jwt.sign({ email: email }, verificationSecret, { expiresIn: verificationExpiresIn });

        // 5. Create the user in the database
        // Pass 'name' and default 'Basic Plan' group, and null for profile picture initially
        const userId = await userModel.createUser(username, email, hashedPassword, verificationToken, 'Basic Plan', null, name);

        // 6. Send verification email
        const verificationLink = `${process.env.BACKEND_URL}/api/verify-email/${verificationToken}`;
        await emailService.sendVerificationEmail(email, username, verificationLink);

        // 7. Send success response
        res.status(201).json({
            message: 'User registered successfully! Please check your email to verify your account.',
            userId: userId,
        });

    } catch (error) {
        next(error);
    }
};

/**
 * Logs in an existing user.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;

        // 1. Validate input data
        const { error } = validateLogin(req.body);
        if (error) {
            const errors = error.details.map(detail => detail.message);
            return res.status(400).json({ message: 'Validation failed', errors: errors });
        }

        // 2. Find user by email
        // Fetch all relevant user data including profile_picture_url and group_name
        const user = await userModel.findByEmail(email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials.' }); // Use generic message for security
        }

        // 3. Compare provided password with hashed password in DB
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials.' });
        }

        // 4. Check if email is verified
        if (!user.is_verified) {
            // If not verified, return 403 and include user ID and email
            return res.status(403).json({
                message: 'Please verify your email address to log in.',
                userId: user.id,
                email: user.email,
                username: user.username // Pass username to help identify user in modal
            });
        }

        // 5. Generate JWT token
        const tokenPayload = {
            id: user.id,
            email: user.email,
            is_verified: user.is_verified,
            username: user.username,
            name: user.name, // Include name
            group: user.group_name, // Use 'group_name' from DB
            profile_picture_url: user.profile_picture_url, // Include profile picture URL
            banned_until: user.banned_until,
            ban_reason: user.ban_reason
        };
        const token = jwt.sign(tokenPayload, secret, { expiresIn: expiresIn });

        // 6. Send success response
        res.status(200).json({
            message: 'Logged in successfully!',
            userId: user.id,
            token: token,
            // Send full user data for frontend context
            id: user.id,
            name: user.name,
            email: user.email,
            username: user.username,
            is_verified: user.is_verified,
            group: user.group_name,
            profile_picture_url: user.profile_picture_url,
            banned_until: user.banned_until,
            ban_reason: user.ban_reason,
            bio: user.bio,
            nationality: user.nationality,
            is_profile_public: user.is_profile_public
        });

    } catch (error) {
        next(error);
    }
};

/**
 * Resends a verification email to a user.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.resendVerificationEmail = async (req, res, next) => {
    try {
        const { email } = req.body;

        if (!email) {
            return res.status(400).json({ message: 'Email is required.' });
        }

        const user = await userModel.findByEmail(email);

        if (!user) {
            return res.status(404).json({ message: 'User with this email not found.' });
        }

        if (user.is_verified) {
            return res.status(400).json({ message: 'Email is already verified.' });
        }

        // Generate a new verification token
        const newVerificationToken = jwt.sign({ email: email }, verificationSecret, { expiresIn: verificationExpiresIn });

        // Update the user's verification token in the database
        const updateSuccess = await userModel.updateVerificationToken(user.id, newVerificationToken);

        if (!updateSuccess) {
            return res.status(500).json({ message: 'Failed to update verification token.' });
        }

        // Send the new verification email
        const verificationLink = `${process.env.BACKEND_URL}/api/verify-email/${newVerificationToken}`;
        await emailService.sendVerificationEmail(user.email, user.username, verificationLink);

        res.status(200).json({ message: 'Verification email resent successfully. Please check your inbox.' });

    } catch (error) {
        next(error);
    }
};

/**
 * Allows a logged-in user to change their password.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.changePassword = async (req, res, next) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id; // Get user ID from the authenticated token

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ message: 'Current password and new password are required.' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'New password must be at least 6 characters long.' });
        }

        // 1. Fetch user from DB to compare current password
        const user = await userModel.findById(userId); // Need a findById method in userModel

        if (!user) {
            return res.status(404).json({ message: 'User not found.' }); // Should not happen if authMiddleware works
        }

        // 2. Compare provided current password with stored hashed password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Incorrect current password.' });
        }

        // 3. Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedNewPassword = await bcrypt.hash(newPassword, salt);

        // 4. Update password in the database
        const updateSuccess = await userModel.updatePassword(userId, hashedNewPassword); // Need updatePassword method

        if (!updateSuccess) {
            return res.status(500).json({ message: 'Failed to update password.' });
        }

        res.status(200).json({ message: 'Password changed successfully.' });

    } catch (error) {
        next(error);
    }
};

/**
 * Allows a logged-in user to update their profile information.
 * This function now uses Multer to handle file uploads.
 * @param {Object} req - Express request object (includes req.file from Multer).
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.updateProfile = (req, res, next) => {
    // Multer middleware will process the file upload first
    upload(req, res, async (err) => {
        if (err) {
            // Handle Multer errors (e.g., file size limit, invalid file type)
            if (err instanceof multer.MulterError) {
                return res.status(400).json({ message: err.message });
            } else if (err) {
                return res.status(400).json({ message: err.message || 'Error uploading file.' });
            }
        }

        try {
            const userId = req.user.id; // User ID from authenticated token
            // req.body now contains text fields from FormData
            const updates = req.body; 

            // Handle profile picture URL
            let profilePictureUrl = updates.profile_picture_url; // Default to existing URL if not changed

            if (req.file) {
                // A new file was uploaded, set its URL
                // Assuming your server serves static files from '/uploads'
                profilePictureUrl = `${process.env.BACKEND_URL}/uploads/profile_pictures/${req.file.filename}`;
                // Delete old picture if it exists and a new one is uploaded
                await deleteOldProfilePicture(userId);
            } else if (updates.clearProfilePicture === 'true') {
                // Signal to clear the profile picture
                profilePictureUrl = null;
                await deleteOldProfilePicture(userId); // Delete the physical file
            } else if (updates.profile_picture_url === 'null' || updates.profile_picture_url === '') {
                // If frontend explicitly sends null/empty string for URL and no file, clear it
                profilePictureUrl = null;
                await deleteOldProfilePicture(userId);
            }
            // If no file, no clear signal, and no explicit null/empty string,
            // profilePictureUrl remains whatever was sent in updates.profile_picture_url (which could be the old one)


            // Construct updates object for userModel
            const userUpdates = {
                name: updates.name,
                username: updates.username,
                bio: updates.bio,
                nationality: updates.nationality,
                // Correctly convert string 'true'/'false' from FormData to boolean/number for DB
                is_profile_public: updates.is_profile_public === 'true' ? true : (updates.is_profile_public === 'false' ? false : undefined), 
                profile_picture_url: profilePictureUrl // Use the determined URL
            };

            // Basic validation (you might want more robust validation here, e.g., using Joi)
            if (Object.keys(userUpdates).length === 0) {
                return res.status(400).json({ message: 'No update data provided.' });
            }

            const updateSuccess = await userModel.updateUserProfile(userId, userUpdates);

            if (!updateSuccess) {
                return res.status(500).json({ message: 'Failed to update profile.' });
            }

            // Fetch the updated user data to send back to the frontend
            const updatedUser = await userModel.findById(userId);
            if (!updatedUser) {
                return res.status(500).json({ message: 'Failed to retrieve updated user data.' });
            }

            // Re-generate JWT with updated user data to ensure frontend has latest info
            const tokenPayload = {
                id: updatedUser.id,
                email: updatedUser.email,
                is_verified: updatedUser.is_verified,
                username: updatedUser.username,
                name: updatedUser.name,
                group: updatedUser.group_name, // Use 'group_name' from DB
                profile_picture_url: updatedUser.profile_picture_url, // Use updated profile picture URL
                banned_until: updatedUser.banned_until,
                ban_reason: updatedUser.ban_reason
            };
            const newToken = jwt.sign(tokenPayload, secret, { expiresIn: expiresIn });


            res.status(200).json({
                message: 'Profile updated successfully!',
                user: { // Send back the updated user object for the frontend to consume
                    id: updatedUser.id,
                    name: updatedUser.name,
                    email: updatedUser.email,
                    username: updatedUser.username,
                    is_verified: updatedUser.is_verified,
                    group: updatedUser.group_name,
                    profile_picture_url: updatedUser.profile_picture_url,
                    banned_until: updatedUser.banned_until,
                    ban_reason: updatedUser.ban_reason,
                    bio: updatedUser.bio,
                    nationality: updatedUser.nationality,
                    is_profile_public: updatedUser.is_profile_public
                },
                token: newToken // Send new token with updated data
            });

        } catch (error) {
            next(error); // Pass error to centralized error handler
        }
    });
};


// Example of a protected route
exports.getProtectedData = (req, res) => {
    // If this middleware is reached, the user is authenticated and email-verified via JWT
    res.status(200).json({
        message: 'This is protected data!',
        user: {
            id: req.user.id,
            email: req.user.email,
            is_verified: req.user.is_verified,
            username: req.user.username,
            name: req.user.name,
            group: req.user.group, // Use 'group' from req.user (from JWT payload)
            profile_picture_url: req.user.profile_picture_url, // Use profile_picture_url from JWT
            banned_until: req.user.banned_until,
            ban_reason: req.user.ban_reason
        }
    });
};


// --- NEW: Password Reset Functions ---

/**
 * Handles the request for a password reset link.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.requestPasswordReset = async (req, res, next) => {
    try {
        const { emailOrUsername } = req.body;

        if (!emailOrUsername) {
            return res.status(400).json({ message: 'Email or username is required.' });
        }

        // Find user by email or username
        let user = await userModel.findByEmail(emailOrUsername);
        if (!user) {
            user = await userModel.findByUsername(emailOrUsername);
        }

        // Important: Always send a generic success message for security,
        // even if the user doesn't exist, to prevent enumeration attacks.
        if (!user) {
            return res.status(200).json({ message: 'If an account with that email or username exists, a password reset link has been sent.' });
        }

        // Generate a unique, time-limited JWT for password reset
        const resetToken = jwt.sign({ id: user.id }, resetSecret, { expiresIn: resetExpiresIn });

        // Store the token and its expiry in the database
        const expiresAt = new Date(Date.now() + (parseInt(resetExpiresIn) * 60 * 60 * 1000)); // Convert '1h' to milliseconds
        const tokenStored = await userModel.createPasswordResetToken(user.id, resetToken, expiresAt);

        if (!tokenStored) {
            return res.status(500).json({ message: 'Failed to generate password reset token.' });
        }

        // Construct the password reset link for the frontend
        const resetLink = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;

        // Send the password reset email
        await emailService.sendPasswordResetEmail(user.email, user.username, resetLink);

        res.status(200).json({ message: 'If an account with that email or username exists, a password reset link has been sent.' });

    } catch (error) {
        console.error('Error in requestPasswordReset:', error);
        next(error);
    }
};

/**
 * Handles the actual password reset using the token.
 * @param {Object} req - Express request object.
 * @param {Object} res - Express response object.
 * @param {Function} next - Express next middleware function.
 */
exports.resetPassword = async (req, res, next) => {
    try {
        const { token } = req.params;
        const { newPassword, confirmPassword } = req.body;

        if (!newPassword || !confirmPassword) {
            return res.status(400).json({ message: 'New password and confirmation are required.' });
        }

        if (newPassword !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match.' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ message: 'Password must be at least 6 characters long.' });
        }

        let decoded;
        try {
            // Verify the JWT token
            decoded = jwt.verify(token, resetSecret);
        } catch (jwtError) {
            let errorMessage = 'Invalid or expired password reset link.';
            if (jwtError.name === 'TokenExpiredError') {
                errorMessage = 'Password reset link has expired.';
            }
            return res.status(400).json({ message: errorMessage });
        }

        // Find the user and validate the token from the database
        const user = await userModel.findByPasswordResetToken(token);

        if (!user || user.id !== decoded.id) {
            // Token not found in DB, or token ID does not match decoded ID (security check)
            return res.status(400).json({ message: 'Invalid or already used password reset link.' });
        }

        // Hash the new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update the user's password
        const updateSuccess = await userModel.updatePassword(user.id, hashedPassword);

        if (!updateSuccess) {
            return res.status(500).json({ message: 'Failed to reset password.' });
        }

        // Invalidate the used token in the database
        await userModel.invalidatePasswordResetToken(token);

        res.status(200).json({ message: 'Password has been reset successfully. You can now log in with your new password.' });

    } catch (error) {
        console.error('Error in resetPassword:', error);
        next(error);
    }
};
