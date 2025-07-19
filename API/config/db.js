// API/config/db.js - MySQL Database Connection Configuration

const mysql = require('mysql2/promise'); // Use mysql2/promise for async/await support

// Create a connection pool to manage database connections efficiently
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    port: process.env.DB_PORT,
    waitForConnections: true, // If true, the pool will queue connections if none are available
    connectionLimit: 10,      // Maximum number of connections to create at once
    queueLimit: 0             // No limit to the number of requests in the queue
});

// Test the database connection when the module is loaded
pool.getConnection()
    .then(connection => {
        console.log('Successfully connected to the MySQL database!');
        connection.release(); // Release the connection back to the pool
    })
    .catch(err => {
        console.error('Error connecting to the database:', err.message);
        // It's crucial to exit the process if the database connection fails on startup
        // as the application cannot function without it.
        process.exit(1);
    });

module.exports = pool; // Export the connection pool for use in other modules
