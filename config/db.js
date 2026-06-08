const mongoose = require('mongoose');

const connectDB = async () => {
    try {
        // Looks for MONGO_URI first, falls back to MONGO_URL
        const connString = process.env.MONGO_URI || process.env.MONGO_URL;
        
        if (!connString) {
            console.error('Error: No MongoDB connection string found in environment variables.');
            process.exit(1);
        }

        const conn = await mongoose.connect(connString);
        console.log(`MongoDB Connected: ${conn.connection.host}`);
    } catch (error) {
        console.error(`Database Connection Error: ${error.message}`);
        process.exit(1);
    }
};

module.exports = connectDB;