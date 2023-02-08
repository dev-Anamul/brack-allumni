/* eslint-disable comma-dangle */
/* eslint-disable implicit-arrow-linebreak */
/* eslint-disable operator-linebreak */
/* eslint-disable prefer-destructuring */
/* eslint-disable no-underscore-dangle */
const jwt = require('jsonwebtoken');
const { promisify } = require('util');
const crypto = require('crypto');
const User = require('../models/userModel');
const catchAsync = require('../utils/catchAsync');
const AppError = require('../utils/AppError');
const sendEmailToUser = require('../utils/email');

// ! generate json web token
const jwtToken = (id) => {
    const token = jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES,
    });

    return token;
};

// ! genarate token and send response to the user
const createTokenSendResponse = (user, statusCode, res) => {
    const token = jwtToken(user._id);

    res.status(statusCode).json({
        status: 'success',
        token,
        data: {
            user,
        },
    });
};
// ! signup controller
exports.signUp = catchAsync(async (req, res) => {
    const newUser = await User.create({
        name: req.body.name,
        email: req.body.email,
        password: req.body.password,
        confirmPassword: req.body.confirmPassword,
        photo: req.body.photo,
    });

    createTokenSendResponse(newUser, 201, res);
});

// ! login controller
exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;
    if (!email || !password) {
        return next(new AppError('Please Provide Email and password', 400));
    }

    const user = await User.findOne({ email }).select('+password');

    if (!user || !(await user.comparePassword(password, user.password))) {
        return next(new AppError('Invalid email or password', 401));
    }

    createTokenSendResponse(user, 200, res);
});

// ! protect routes
exports.protect = catchAsync(async (req, res, next) => {
    let token;
    if (req.headers.authorization && req.headers.authorization.startsWith('Bearer')) {
        token = req.headers.authorization.split(' ')[1];
    }

    if (!token) {
        return next(new AppError('You are not logged in. Please login', 401));
    }

    const decode = await promisify(jwt.verify)(token, process.env.JWT_SECRET);

    const verifiedUser = await User.findById(decode.id);
    if (!verifiedUser) {
        return next('The user belongs to this token no longer exists', 401);
    }

    // check if user changed password after usuing jwt token
    if (verifiedUser.passwordUpdatedAfter(decode.iat)) {
        return next(new AppError('User recently changed the password. Please log in again', 401));
    }
    req.user = verifiedUser;
    //! GRANT ACCESSS
    next();
});

// ! restricted To
exports.restrictTo =
    (...roles) =>
    (req, res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(new AppError('You have No permission to perform this task', 403));
        }

        next();
    };

// ! forgot password
exports.forgotPassword = catchAsync(async (req, res, next) => {
    // find user on the basis of email
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
        return next(new AppError('No account found with this email', 404));
    }

    // generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });

    // send email to the user
    const resetUrl = `${req.protocol}://${req.get(
        'host'
    )}/api/v1/users/resetPassword/${resetToken}`;

    const message = `Forgot your password..? Send a patch request with your new password and confirmPassword To: ${resetUrl}`;

    try {
        await sendEmailToUser({
            email: user.email,
            subject: 'Your reset token is valid only for 10 minutes',
            text: message,
        });

        res.status(200).json({
            status: 'success',
            message: 'Send email to the user successfully',
        });
    } catch (error) {
        user.passwordResetToken = undefined;
        user.passwordResetExpires = undefined;
        await user.save({ validateBeforeSave: false });

        return next(new AppError('There is an error with sending email..! try again later..', 500));
    }
});

// ! resetPassword controller
exports.resetPassword = catchAsync(async (req, res, next) => {
    const hashToken = crypto.createHash('sha256').update(req.params.token).digest('hex');

    const user = await User.findOne({
        passwordResetToken: hashToken,
        passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
        return next(new AppError('Invalid token or has expired', 400));
    }

    // if everything is okay
    user.password = req.body.password;
    user.confirmPassword = req.body.confirmPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // provide jwt token

    createTokenSendResponse(user, 200, res);
    // const token = jwtToken(user._id);

    // res.status(200).json({
    //     status: 'success',
    //     token,
    // });
});

// ! update password
exports.updatePassword = catchAsync(async (req, res, next) => {
    const { currentPassword, newPassword, confirmPassword } = req.body;

    const user = await User.findById(req.user._id).select('+password');

    if (!(await user.comparePassword(currentPassword, user.password))) {
        return next(new AppError('Your current password is wrong', 400));
    }

    user.password = newPassword;
    user.confirmPassword = confirmPassword;
    await user.save();

    createTokenSendResponse(user, 200, res);
});
