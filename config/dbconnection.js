const mongoose = require('mongoose');
require('dotenv').config({ path: './config/config.env' });

// ! database url
const DB = process.env.DATABASE_LOCALE;
// DB = DB.replace('<USER>', process.env.MONGO_USER).replace('<PASS>', process.env.MONGO_PASS);

// ! Db connection
const connecWithRetry = async () => {
    try {
        await mongoose.connect(DB, {
            useNewUrlParser: true,
        });
    } catch (error) {
        setTimeout(() => {
            connecWithRetry();
        }, 5000);
    }
};

module.exports = connecWithRetry;
