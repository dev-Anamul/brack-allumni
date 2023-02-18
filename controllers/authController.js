/* eslint-disable max-len */
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
// const sendEmailToUser = require('../utils/email');
const Email = require('../utils/EmailClass');
const { createUserValidator, updatePassword } = require('../validators/userValidators');

// ! generate json web token
const jwtToken = (id) => {
    const token = jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: process.env.JWT_EXPIRES,
    });
    return token;
};

// ! genarate token and send response to the user
const createTokenSendResponse = (user, statusCode, res) => {
    const returnUser = user;
    returnUser.__v = undefined;
    const token = jwtToken(user._id);
    res.status(statusCode).json({
        status: 'success',
        token,
        authToken: `Bearer ${token}`,
        data: {
            user: returnUser,
        },
    });
};

// ! @desc    signup user
// ! @route   POST /api/v1/users/signup
// ! @access  public
exports.signUp = catchAsync(async (req, res, next) => {
    const { errors, isValid } = createUserValidator(req.body);

    if (!isValid) {
        return res.status(400).json({
            status: 'error',
            errors,
        });
    }
    if (req.file) {
        req.body.photo = req.file.filename;
    }
    if (!req.file && req.body.gender === 'male') {
        req.body.photo = 'male_avater.jpg';
    }
    if (!req.file && req.body.gender === 'female') {
        req.body.photo = 'female-avater.png';
    }

    const user = await User.create({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        password: req.body.password,
        confirmPassword: req.body.confirmPassword,
        contactNumber: req.body.contactNumber,
        gender: req.body.gender,
        photo: req.body.photo,
    });

    // const message =
    // ('Your account has been created successfully. Please wait for admin approval to login your dashboard.');
    try {
        // await sendEmailToUser({
        //     email: user.email,
        //     subject: 'Wellcome to BRAC Allumni Association as a new member',
        //     text: message,
        // });
        const url = `${req.protocol}://${req.get('host')}/api/v1/users/login`;
        await new Email(user, url).sendWelcome();
        res.status(201).json({
            status: 'success',
            message:
                'Your account has been created successfully. Please wait for admin approval to login your dashboard.',
        });
    } catch (error) {
        console.log(error);
        await User.findOneAndDelete({ email: req.body.email });
        return next(
            new AppError(
                'Something wrong with your account creation. Please try after sometime',
                500
            )
        );
    }

    // createTokenSendResponse(newUser, 201, res);
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

    if (!user.isApproved) {
        return next(
            new AppError(
                'Your account is not approved by admin!! Please wait for admin approval to login',
                403
            )
        );
    }

    createTokenSendResponse(user, 200, res);
});

// ! protect routes
exports.protect = catchAsync(async (req, _res, next) => {
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
    if (verifiedUser.changePasswordAfterCreateJwt(decode.iat)) {
        return next(new AppError('User recently changed the password. Please log in again', 401));
    }
    req.user = verifiedUser;
    next();
});

// ! restricted To
exports.restrictTo =
    (...roles) =>
    (req, _res, next) => {
        if (!roles.includes(req.user.role)) {
            return next(new AppError('You have No permission to perform this task', 403));
        }
        next();
    };

// ! forgot password
exports.forgotPassword = catchAsync(async (req, res, next) => {
    // destructuring email from the request body
    const { email } = req.body;
    // check if email is provided
    if (!email) {
        return next(new AppError('Please provide email', 400));
    }
    // check if user exists
    const user = await User.findOne({ email: req.body.email });
    // if user not found
    if (!user) {
        return next(new AppError('No account found with this email', 404));
    }
    // generate reset token
    const resetToken = user.createPasswordResetToken();
    await user.save({ validateBeforeSave: false });
    // send email to the user
    // const resetUrl = `${req.protocol}://${req.get(
    //     'host'
    // )}/api/v1/users/reset-password/${resetToken}`;
    const resetUrl = `${req.headers?.origin}/reset-password/${resetToken}`;
    // const message = `Forgot your password..? Send a patch request with your new password and confirmPassword To: ${resetUrl}`;
    try {
        // await sendEmailToUser({
        //     email: user.email,
        //     subject: 'Your reset token is valid only for 10 minutes',
        //     text: message,
        // });
        await new Email(user, resetUrl).sendPasswordReset();
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

    if (!user.isApproved) {
        return next(
            new AppError(
                'Your account is not approved yet!! Please wait for admin approval to perform this action.',
                403
            )
        );
    }

    // if everything is okay
    user.password = req.body.password;
    user.confirmPassword = req.body.confirmPassword;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    await user.save();

    // provide jwt token
    createTokenSendResponse(user, 200, res);
});

// ! update password
exports.updatePassword = catchAsync(async (req, res, next) => {
    // destructuring the request body
    const { currentPassword, newPassword, confirmPassword } = req.body;

    // check if current password is provided
    const { errors, isValid } = updatePassword({ currentPassword, newPassword, confirmPassword });
    if (!isValid) {
        return res.status(400).json({
            status: 'fail',
            errors,
        });
    }
    // find the user
    const user = await User.findById(req.user._id).select('+password');
    // check if current password is correct
    if (!(await user.comparePassword(currentPassword, user.password))) {
        return next(new AppError('Your current password is wrong', 400));
    }
    // if everything is okay
    user.password = newPassword;
    // save the user
    await user.save();
    // provide jwt token
    createTokenSendResponse(user, 200, res);
});

// ! allowed filds to update
const newObj = (obj, ...allowedFields) => {
    const returnObj = {};
    Object.keys(obj).forEach((el) => {
        if (allowedFields.includes(el)) {
            returnObj[el] = obj[el];
        }
    });
    return returnObj;
};

// ! update me
exports.updateMe = catchAsync(async (req, res, next) => {
    if (req.body.password || req.body.passwordConfirm) {
        return next(
            new AppError(
                'This is route is not for password updates. Please use /update-my-password ',
                400
            )
        );
    }
    const filterObj = newObj(req.body, 'firstName', 'lastName', 'email', 'contactNumber', 'gender');
    if (req.file) {
        filterObj.photo = req.file.filename;
    }

    const updatedUser = await User.findByIdAndUpdate(req.user._id, filterObj, {
        new: true,
        runValidators: true,
    });

    res.status(200).json({
        status: 'success',
        data: {
            user: updatedUser,
        },
    });
});

// ! get logged in user
exports.getMe = (req, _res, next) => {
    req.params.id = req.user.id;
    next();
};

// ! delete logged in user
exports.deleteMe = catchAsync(async (req, res) => {
    await User.findByIdAndDelete(req.user.id);
    res.status(204).json({
        status: 'success',
        data: null,
    });
});

// ! @desc    approve user
// ! @route   POST /api/v1/users/approve
// ! @access  Private
exports.approveUser = catchAsync(async (req, res, next) => {
    const user = await User.findById(req.params.id);

    if (!user) {
        return next(new AppError('No user found with this ID.', 404));
    }

    user.isApproved = true;
    await user.save();
    // ! send mail to the user
    // const message = 'Your accoutn is now approved by an admin. Please try to login your dashboard';
    try {
        // await sendEmailToUser({
        //     email: user.email,
        //     subject: 'Welcome to BRAC Allumni Association',
        //     text: message,
        // });
        const loginUrl = `${req.headers.origin}/login`;
        await new Email(user, loginUrl).sendApproval();
        res.status(200).json({ success: true, data: user });
    } catch (error) {
        user.isApproved = false;
        await user.save();
        return next(
            new AppError('Something went wrong with user approve. Please try after sometime', 500)
        );
    }
});

// ! @desc    is account approved
// ! @route   middleware
// ! @access  Private
exports.isAccountApproved = catchAsync(async (req, _res, next) => {
    if (req.user.role === 'admin') return next();
    // check if user is approved
    if (!req.user.isApproved) {
        return next(
            new AppError(
                'Your account is not approved yet!! Please wait for admin approval to perform this action.',
                403
            )
        );
    }
    next();
});
