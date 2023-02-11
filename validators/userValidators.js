const validator = require('validator');

// ! create user validator
const createUserValidator = (userObj) => {
    const errors = {};

    if (!userObj.firstName) {
        errors.firstName = 'User must have a first name';
    }

    if (!userObj.lastName) {
        errors.lastName = 'User must have a last name';
    }

    if (!userObj.email) {
        errors.email = 'Email is required';
    } else if (!validator.isEmail(userObj.email)) {
        errors.email = 'Please provide a valid email';
    }

    if (!userObj.password) {
        errors.password = 'User must have a password';
    }

    if (!userObj.confirmPassword) {
        errors.confirmPassword = 'User must have a confirm password';
    } else if (userObj.password !== userObj.confirmPassword) {
        errors.confirmPassword = 'Password and Confirm Password must be same';
    }

    if (!userObj.contactNumber) {
        errors.contactNumber = 'User must have a contact number';
    }

    if (!userObj.gender) {
        errors.gender = 'User must have a gender';
    }

    return {
        errors,
        isValid: Object.keys(errors).length === 0,
    };
};

// ! login validator
const loginValidator = (userObj) => {
    const errors = {};
    if (!userObj.email) {
        errors.email = 'Email is required';
    }
    if (!userObj.password) {
        errors.password = 'Password is required';
    }
    return {
        errors,
        isValid: Object.keys(errors).length === 0,
    };
};

// ! forgot password validator
const forgotPasswordValidator = (userObj) => {
    const errors = {};
    if (!userObj.email) {
        errors.email = 'Email is required';
    }
    return {
        errors,
        isValid: Object.keys(errors).length === 0,
    };
};
// ! reset password validator
const updatePassword = (userObj) => {
    const errors = {};
    if (!userObj.currentPassword) {
        errors.currentPassword = 'Current Password is required';
    }
    if (!userObj.newPassword) {
        errors.newPassword = 'Password is required';
    }
    if (!userObj.confirmPassword) {
        errors.confirmPassword = 'Confirm Password is required';
    }
    if (userObj.newPassword !== userObj.confirmPassword) {
        errors.confirmPassword = 'New Password and Confirm Password must be same';
    }
    return {
        errors,
        isValid: Object.keys(errors).length === 0,
    };
};

// ! export validators
module.exports = {
    createUserValidator,
    loginValidator,
    forgotPasswordValidator,
    updatePassword,
};
