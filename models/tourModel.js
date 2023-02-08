const mongoose = require('mongoose');
const validator = require('validator');

const tourSchema = new mongoose.Schema(
    {
        name: {
            type: String,
            required: [true, 'A tour must have a name'],
            unique: true,
            minlength: [10, 'A tour name must have more than or equal 10 characters'],
            maxlength: [40, 'A tour name must have less than or equal 40 characters'],
            // validate: [validator.isAlpha, 'A tour name only contains characters'],
            validate: {
                validator(val) {
                    return validator.isAlpha(val, 'en-US', { ignore: ' ' });
                },
                message: ' A tour name must only contains characters',
            },
        },
        slug: String,
        duration: {
            type: Number,
            required: [true, 'A tour must have a duration'],
        },
        maxGroupSize: {
            type: Number,
            required: [true, 'A tour must have a group size'],
        },
        difficulty: {
            type: String,
            required: [true, 'A tour must have a difficulty'],
            enum: {
                values: ['easy', 'medium', 'difficult'],
                message: ' Difficulty must be either: easy, medium, difficulty.',
            },
        },
        ratingsAverage: {
            type: Number,
            default: 4.5,
            max: [5, 'Ratings must be less than or equal 5.'],
            min: [1, 'Ratings must be more than or qual 1.'],
            set: (val) => Math.round(val * 10) / 10,
        },
        secretTour: {
            type: Boolean,
            default: false,
        },
        ratingsQuantity: {
            type: Number,
            default: 0,
        },
        price: {
            type: Number,
            required: [true, 'A tour must have a price'],
        },
        priceDiscount: {
            type: Number,
            validate: {
                validator(val) {
                    return val < this.price;
                },
                message: 'Discount price ({VALUE}) should be less than regular price',
            },
        },
        summary: {
            type: String,
            trim: true,
            required: [true, 'A tour must have a summery'],
        },
        description: {
            type: String,
            trim: true,
        },
        imageCover: {
            type: String,
            required: [true, 'A tour must have a cover image'],
        },
        images: [String],
        createdAt: {
            type: Date,
            default: Date.now(),
        },
        startDates: [Date],
        startLocation: {
            type: {
                type: String,
                default: 'Point',
                enum: ['Point'],
            },
            coordinates: [Number],
            address: String,
            description: String,
        },
        locations: [
            {
                type: {
                    type: String,
                    default: 'Point',
                    enum: ['Point'],
                },
                coordinates: [Number],
                address: String,
                description: String,
                day: Number,
            },
        ],
        guides: [
            {
                type: mongoose.Schema.ObjectId,
                ref: 'User',
            },
        ],
    },

    {
        toJSON: { virtuals: true },
        toObject: { virtuals: true },
        // eslint-disable-next-line prettier/prettier
    },
);

const Tour = mongoose.model('Tour', tourSchema);
module.exports = Tour;
