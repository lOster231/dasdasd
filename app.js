// app.js - Main entry point for the Express application with enhanced security

// Load environment variables from .env file located in the API directory
// This must be done before any other modules that might depend on these variables.
require('dotenv').config({ path: './API/.env' });

const express = require('express');
const cors = require('cors'); // Already imported
const helmet = require('helmet'); // For setting various security-related HTTP headers
const rateLimit = require('express-rate-limit'); // For rate limiting to prevent abuse
const authRoutes = require('./API/routes/authRoutes');
const verificationRoutes = require('./API/routes/verificationRoutes'); // New verification routes
const errorHandler = require('./API/utils/errorHandler');
const path = require('path'); // Node.js path module for file paths

const app = express();

// --- Security Middleware (Global CORS first) ---

// 1. Helmet: Helps secure your apps by setting various HTTP headers.
app.use(helmet());

// 2. CORS: Enable CORS for your specific frontend application
// This allows your frontend (cpp-hub.com) to make requests to your backend (api.cpp-hub.com)
app.use(cors({
    origin: process.env.FRONTEND_URL, // Use environment variable for frontend URL
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// --- Static File Serving (REMOVED FROM NODE.JS - NOW HANDLED BY NGINX) ---
// The line below has been removed as per your Nginx configuration choice:
// app.use('/uploads/profile_pictures', express.static(path.join(__dirname, 'uploads', 'profile_pictures')));
// Nginx is now configured to serve these files directly from:
// alias /var/www/vhosts/cpp-hub.com/httpdocs/uploads/profile_pictures/;


// 3. Rate Limiting: Apply to all requests to prevent brute-force attacks and DDoS
const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again after 15 minutes.',
    standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
    legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});
// Apply the rate limiting middleware to all requests
app.use(apiLimiter);

// Parse incoming JSON requests
app.use(express.json());

// --- Routes ---

// Authentication routes (login, register)
app.use('/api/auth', authRoutes);

// Email verification routes
app.use('/api', verificationRoutes); // e.g., /api/verify-email/:token

// --- Error Handling Middleware ---
// This should be the last middleware added to catch all errors
app.use(errorHandler);

// --- Server Start ---

const PORT = process.env.PORT || 3000; // Use port from environment variable or default to 3000

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access backend at: ${process.env.BACKEND_URL}`);
});
