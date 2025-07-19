// API/utils/emailService.js - Handles sending emails for verification, etc.

const nodemailer = require('nodemailer'); // Import Nodemailer for email sending
const fs = require('fs'); // Node.js file system module
const path = require('path'); // Node.js path module

// Configure the email transporter using SMTP details from environment variables
const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST, // SMTP server host (e.g., smtp.gmail.com, smtp-mail.outlook.com) 
    port: process.env.SMTP_PORT, // SMTP port (e.g., 587 for TLS, 465 for SSL) 
    secure: process.env.SMTP_PORT == 465, // True if port is 465 (SSL), false for other ports (TLS) 
    auth: {
        user: process.env.SMTP_USER,     // Your SMTP username (usually your email address) 
        pass: process.env.SMTP_PASSWORD  // Your SMTP password or app-specific password 
    }
});

/**
 * Sends a verification email to the user.
 * @param {string} toEmail - The recipient's email address.
 * @param {string} username - The username of the recipient.
 * @param {string} verificationLink - The full URL for the email verification link.
 * @returns {Promise<Object>} - Information about the sent email.
 */
exports.sendVerificationEmail = async (toEmail, username, verificationLink) => {
    try {
        const mailOptions = {
            from: `"${process.env.SENDER_NAME}" <${process.env.SENDER_EMAIL}>`, // Sender address and name 
            to: toEmail, // List of recipients 
            subject: 'Verify Your Email Address for CPP-Hub', // Subject line 
            html: `
                <div style="font-family: Arial, sans-serif; line-height: 1.6; color: #333;">
                    <h2>Hello ${username},</h2>
                    <p>Thank you for registering with CPP-Hub! To complete your registration and activate your account, please verify your email address by clicking the link below:</p>
                    <p style="margin: 20px 0;"><a href="${verificationLink}" style="display: inline-block; padding: 10px 20px; background-color: #007bff; color: #ffffff; text-decoration: none; border-radius: 5px;">Verify Email Address</a></p>
                    <p>If the button above does not work, you can copy and paste the following link into your browser:</p>
                    <p><a href="${verificationLink}">${verificationLink}</a></p>
                    <p>This link will expire in ${process.env.VERIFICATION_EXPIRES_IN}.</p>
                    <p>If you did not register for an account, please ignore this email.</p>
                    <p>Best regards,</p>
                    <p>${process.env.SENDER_NAME} Team</p>
                </div>
            `, // HTML body of the email 
        };

        const info = await transporter.sendMail(mailOptions); // Send the email 
        console.log('Verification Email sent: %s', info.messageId);
        return info;
    } catch (error) {
        console.error('Error sending verification email:', error);
        throw new Error('Failed to send verification email.');
    }
};

// NEW: Function to send password reset email
/**
 * Sends a password reset email to the user.
 * @param {string} toEmail - The recipient's email address.
 * @param {string} username - The username of the recipient.
 * @param {string} resetLink - The full URL for the password reset link.
 * @returns {Promise<Object>} - Information about the sent email.
 */
exports.sendPasswordResetEmail = async (toEmail, username, resetLink) => {
    try {
        const templatePath = path.join(__dirname, 'email_templates', 'passwordResetEmail.html');
        let emailTemplate = fs.readFileSync(templatePath, 'utf8');

        // Replace placeholders in the template
        emailTemplate = emailTemplate.replace(/<%= username %>/g, username);
        emailTemplate = emailTemplate.replace(/<%= resetLink %>/g, resetLink);
        emailTemplate = emailTemplate.replace(/<%= expiresIn %>/g, process.env.RESET_EXPIRES_IN);
        emailTemplate = emailTemplate.replace(/<%= senderName %>/g, process.env.SENDER_NAME);

        const mailOptions = {
            from: `"${process.env.SENDER_NAME}" <${process.env.SENDER_EMAIL}>`,
            to: toEmail,
            subject: 'Password Reset Request for CPP-Hub',
            html: emailTemplate,
        };

        const info = await transporter.sendMail(mailOptions);
        console.log('Password Reset Email sent: %s', info.messageId);
        return info;
    } catch (error) {
        console.error('Error sending password reset email:', error);
        throw new Error('Failed to send password reset email.');
    }
};
