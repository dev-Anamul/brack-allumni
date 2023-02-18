/* eslint-disable no-underscore-dangle */
const catchAsync = require('../utils/catchAsync');
const User = require('../models/userModel');
const { createUserValidator } = require('../validators/userValidators');
const AppError = require('../utils/AppError');
const APIFeatures = require('../utils/APIFeatures');

// ! get all users
exports.getAllUsers = catchAsync(async (req, res) => {
    console.log(req.headers.origin);
    const totalUsers = await User.countDocuments();

    // ! build query
    const features = new APIFeatures(User.find(), req.query)
        .filter()
        .keywordSearch()
        .sort()
        .fields()
        .pagination();

    const users = await features.query;

    res.status(200).json({
        status: 'success',
        results: users.length,
        totalUsers,
        data: {
            users,
        },
    });
});

// ! create new user
exports.createNewUser = catchAsync(async (req, res) => {
    const { errors, isValid } = createUserValidator(req.body);
    if (!isValid) {
        return res.status(400).json({
            status: 'error',
            errors,
        });
    }
    const newUser = await User.create({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        password: req.body.password,
        confirmPassword: req.body.confirmPassword,
        contactNumber: req.body.contactNumber,
        gender: req.body.gender,
    });

    // ! remove __v from response
    newUser.__v = undefined;

    res.status(201).json({
        status: 'success',
        data: {
            user: newUser,
        },
    });
});

// ! get single user
exports.getSingleUser = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const user = await User.findById(id);

    if (!user) {
        return next(new AppError('No user found with this id', 404));
    }

    // ! remove __v from response
    user.__v = undefined;

    res.status(200).json({
        status: 'success',
        data: {
            user,
        },
    });
});

// ! update user data
exports.updateUser = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const user = await User.findByIdAndUpdate(id, req.body, {
        new: true,
        runValidators: true,
    });
    if (!user) {
        return next(new AppError('No user found with this id', 404));
    }

    // ! remove __v from response
    user.__v = undefined;

    res.status(200).json({
        status: 'success',
        data: {
            user,
        },
    });
});

// ! delete user data
exports.deleteUser = catchAsync(async (req, res, next) => {
    const { id } = req.params;
    const user = await User.findByIdAndDelete(id);
    if (!user) {
        return next(new AppError('No user found with this id', 404));
    }
    res.status(204).json({
        status: 'success',
        data: null,
    });
});
