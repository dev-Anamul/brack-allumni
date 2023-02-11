/* eslint-disable prefer-destructuring */
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
    {
        firstName: {
            type: String,
            required: [true, 'User must have a first name'],
        },

        lastName: {
            type: String,
            required: [true, 'User must have a last name'],
        },
        fullName: {
            type: String,
        },
        username: {
            type: String,
            index: true,
        },
        email: {
            type: String,
            trim: true,
            required: [true, 'User must have an email'],
            unique: true,
        },
        password: {
            type: String,
            trim: true,
            required: [true, 'User must have a password'],
            select: false,
        },
        role: {
            type: String,
            enum: ['user', 'paidUser', 'admin'],
            default: 'user',
        },
        contactNumber: {
            type: String,
            trim: true,
            index: true,
            required: [true, 'User must have a contact number'],
        },
        gender: {
            type: String,
            enum: ['male', 'female', 'other'],
            required: [true, 'User must have a gender'],
        },
        isApproved: {
            type: Boolean,
            default: false,
        },
        photo: {
            type: String,
        },
        passwordChangeAT: {
            type: Date,
        },
        passwordResetToken: String,
        passwordResetExpires: Date,
    },
    // eslint-disable-next-line comma-dangle
    { timestamps: true }
);

// ! set fullName and username before saving user to db
userSchema.pre('save', function (next) {
    this.fullName = `${this.firstName} ${this.lastName}`;
    this.username = this.email.split('@')[0];
    next();
});

// ! encrypt password before saving user to db
userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        return next();
    }
    this.password = await bcrypt.hash(this.password, 12);
    next();
});

// ! set pswword change at property if change password
userSchema.pre('save', function (next) {
    if (!this.isModified('password') || this.isNew) return next();
    this.passwordChangeAT = Date.now() - 1000;
    return next();
});

// ! compare password
userSchema.methods.comparePassword = async (cadidatePassword, userPassword) => {
    const comparisonResult = await bcrypt.compare(cadidatePassword, userPassword);
    return comparisonResult;
};

// ! change password after issuing jwt token
userSchema.methods.changePasswordAfterCreateJwt = function (jwtTimeStap) {
    if (this.passwordChangeAT) {
        const passChanged = parseInt(this.passwordChangeAT.getTime() / 1000, 10);
        return passChanged > jwtTimeStap;
    }
    return false;
};

// ! create password reset token
userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;
    return resetToken;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
