/* eslint-disable comma-dangle */
const express = require('express');
const morgan = require('morgan');
const path = require('path');
const cors = require('cors');
const tourRouter = require('./routes/tourRouter');
const userRouter = require('./routes/userRouter');
const AppError = require('./utils/AppError');
const errorController = require('./controllers/errorController');

// ! initialize app
const app = express();

// * middleware stack
// ! use morgan
if (process.env.NODE_ENV === 'development') {
    app.use(morgan('dev'));
}

// ! cors policy
app.use(
    cors({
        origin: '*',
    })
);
// ! body parser
app.use(express.json());

// ! serving static file
app.use(express.static(path.join(__dirname, 'public')));

// ! mounted router
app.use('/api/v1/tours', tourRouter);
app.use('/api/v1/users', userRouter);

// ! global unhalder route handler
app.all('*', (req, res, next) => {
    next(new AppError(`Can't find ${req.originalUrl} on thi server.`, 404));
});

// ! global error handler
app.use(errorController.globalHanlder);

// ! export app
module.exports = app;
