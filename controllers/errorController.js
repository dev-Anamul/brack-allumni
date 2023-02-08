const AppError = require('../utils/AppError');

// ! send error message in development
const sendErrorDev = (error, res) => {
    res.status(error.statusCode).json({
        status: error.status,
        message: error.message,
        stacktrace: error.stack,
        error,
    });
};

// ! handle jwt token error
const handleJwtError = (err) => {
    const message = `${err.message}. Please login again`;
    return new AppError(message, 401);
};

// ! handle jwt expired error
const handleJwtExpiredError = () => new AppError('Your token is expird. Please login again', 401);

// ! handle duplicare key error
const handleDuplicateFields = (err) => {
    const message = `Duplicate fields Value : ${Object.keys(err.keyValue)} => ${
        err.keyValue[Object.keys(err.keyValue)]
    }`;
    return new AppError(message, 400);
};
// ! handle cast error
const handleCastError = (err) => {
    const message = `Invalid ${err.path} : ${err.value}`;
    return new AppError(message, 400);
};
// ! handle validation error
const handleValidationError = (err) => {
    const message = `${err.message}`;
    return new AppError(message, 400);
};
// ! send error message in production
const sendErrorProd = (error, res) => {
    if (error.isOperational) {
        res.status(error.statusCode).json({
            status: error.status,
            message: error.message,
        });
    } else {
        // ! error log to the console in production moode
        console.error('error 💥💥', error);

        // ! give response to the client in the production moode
        res.status(500).json({
            status: 'error',
            message: 'Something went very wrong..',
        });
    }
};
// ! global handler
// eslint-disable-next-line no-unused-vars
exports.globalHanlder = (err, req, res, next) => {
    let error = err;
    error.statusCode = err.statusCode || 500;
    error.status = err.status || 'error';

    if (process.env.NODE_ENV === 'development') {
        sendErrorDev(error, res);
    } else if (process.env.NODE_ENV === 'production') {
        if (error.name === 'CastError') {
            error = handleCastError(error);
        }
        if (error.code === 11000) {
            error = handleDuplicateFields(error);
        }
        if (error.name === 'ValidationError') {
            error = handleValidationError(error);
        }
        if (error.name === 'JsonWebTokenError') {
            error = handleJwtError(error);
        }
        if (error.name === 'TokenExpiredError') {
            error = handleJwtExpiredError(error);
        }
        sendErrorProd(error, res);
    }
};
