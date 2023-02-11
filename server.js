const dotenv = require('dotenv');
const connecWithRetry = require('./config/dbconnection');

// ! uncaught exceptions
process.on('uncaughtException', (err) => {
    console.log('UNCAUGHT EXCEPTION... 💥💥💥 Shouting down');
    console.log(err.name, err.message);
    process.exit(1);
});

// ! connect config file.... this file must connect before requiring app
dotenv.config({ path: './config/config.env' });

// ! require app
const app = require('./app');

// ! database connection
// ! connecto to the database
connecWithRetry()
    .then(() => {
        console.log('DB connection successful!');
    })
    .catch((err) => {
        console.log(err);
        console.log('DB connection failed! Retrying...');
    });

// ! define port number
const port = process.env.PORT || 5050;

// ! listening app
const server = app.listen(port, () => {
    console.log(`>server up and running on ${port} port `);
});

// ! unhandle promise rejection
process.on('unhandledRejection', (err) => {
    console.log(err.name, err.message);
    console.log('Shutting down the application...💥💥💥');
    server.close(() => {
        process.exit(1);
    });
});
