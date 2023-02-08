const mongoose = require('mongoose');
const validator = require('validator');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

const userSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, 'A user must have a name'],
        },

        email: {
            type: String,
            required: [true, 'A user must have an email'],
            unique: true,
            lowercase: true,
            validate: [validator.isEmail, 'Please provide valid email'],
        },
        password: {
            type: String,
            required: [true, 'A user must have a password'],
            minlength: [8, 'password must be more than 8 character'],
            select: false,
        },
        role: {
            type: String,
            enum: ['admin', 'user', 'lead-guide', 'guide'],
            default: 'user',
        },
        confirmPassword: {
            type: String,
            required: [true, 'Please provide confirm password'],
            validate: {
                validator(confirmpass) {
                    return confirmpass === this.password;
                },
                message: 'Password are not same',
            },
        },
        photo: {
            type: String,
        },
        passwordResetToken: String,
        passwordResetExpires: Date,
    },
    // eslint-disable-next-line comma-dangle
    { timestamps: true }
);

userSchema.pre('save', async function (next) {
    if (!this.isModified('password')) {
        return next();
    }
    this.password = await bcrypt.hash(this.password, 12);
    this.confirmPassword = undefined;
    next();
});

userSchema.methods.comparePassword = async (cadidatePassword, userPassword) => {
    const comparisonResult = await bcrypt.compare(cadidatePassword, userPassword);

    return comparisonResult;
};

userSchema.methods.passwordUpdatedAfter = function (jwtTimeStamp) {
    const passTimeStamp = parseInt(this.updatedAt.getTime() / 1000, 10);
    return jwtTimeStamp < passTimeStamp;
};

userSchema.methods.createPasswordResetToken = function () {
    const resetToken = crypto.randomBytes(32).toString('hex');
    this.passwordResetToken = crypto.createHash('sha256').update(resetToken).digest('hex');
    this.passwordResetExpires = Date.now() + 10 * 60 * 1000;

    return resetToken;
};

const User = mongoose.model('User', userSchema);
module.exports = User;
