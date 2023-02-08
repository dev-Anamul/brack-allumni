/* eslint-disable comma-dangle */
const express = require('express');
const tourController = require('../controllers/tourController');
const authController = require('../controllers/authController');

// ! initialize router
const router = express.Router();

// ! param middleware a special type of middleware only run when requested url contains a parameter
router.param('id', (req, res, next, value) => {
    console.log(`tour id is ${value}`);
    next();
});

// ! mounte controller with router
router.route('/top-5-cheap').get(tourController.aliasTopTours, tourController.getAllTours);

router
    .route('/')
    .get(authController.protect, tourController.getAllTours)
    .post(tourController.createNewTour);

router
    .route('/:id')
    .get(tourController.getSingleTour)
    .patch(tourController.updateTour)
    .delete(
        authController.protect,
        authController.restrictTo('admin', 'lead-guide'),
        tourController.deleteTour
    );

module.exports = router;
