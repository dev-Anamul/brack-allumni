const Tour = require('../models/tourModel');
const APIFeatures = require('../utils/APIFeatures');
const AppError = require('../utils/AppError');
const catchAsync = require('../utils/catchAsync');

// ! top five alias tours
exports.aliasTopTours = (req, res, next) => {
    this.queryString.limit = '5';
    this.queryString.sort = '-ratingsAverage,price';
    this.queryString.fields = 'name,price,duration,dificulty';
    next();
};
// ! get all tour controller
exports.getAllTours = catchAsync(async (req, res) => {
    // ! total number of document
    const totalNumberOfDocument = await Tour.countDocuments();
    // ! we await query here... after adding all query features
    const features = new APIFeatures(Tour.find(), req.query)
        .filter()
        .keywordSearch()
        .fields()
        .sort()
        .pagination();

    const tours = await features.query;

    res.status(200).json({
        status: 'success',
        result: tours.length,
        totalProducts: totalNumberOfDocument,
        data: {
            tours,
        },
    });
});

// ! create new tour
exports.createNewTour = catchAsync(async (req, res) => {
    const newTour = await Tour.create(req.body);
    res.status(200).json({
        status: 'success',
        data: {
            tour: newTour,
        },
    });
});

// ! get single tour
exports.getSingleTour = catchAsync(async (req, res, next) => {
    const tour = await Tour.findById(req.params.id);

    if (!tour) {
        return next(new AppError('No tour found with this ID', 404));
    }
    res.status(200).json({
        status: 'success',
        data: {
            tour,
        },
    });
});

// ! update tour
exports.updateTour = catchAsync(async (req, res, next) => {
    const updateTour = await Tour.findByIdAndUpdate(req.params.id, req.body, {
        new: true,
        runValidators: true,
    });

    if (!updateTour) {
        return next(new AppError('No tour found with this ID', 404));
    }
    res.status(200).json({
        status: 'success',
        data: {
            tour: updateTour,
        },
    });
});

// ! delet tour
exports.deleteTour = catchAsync(async (req, res, next) => {
    const deleteTour = await Tour.findByIdAndDelete(req.params.id);

    if (!deleteTour) {
        return next(new AppError('No tour found with this ID', 404));
    }
    res.status(204).json({
        status: 'success',
        tour: deleteTour,
    });
});
