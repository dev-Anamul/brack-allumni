const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');

// ! initialize router
const router = express.Router();

// ! auth routes
router.post('/signup', authController.signUp);
router.post('/login', authController.login);
router.post('/forgotPassword', authController.forgotPassword);
router.patch('/resetPassword/:token', authController.resetPassword);
router.patch('/updateMyPassword', authController.protect, authController.updatePassword);

// ! mounting controllers to route
router.route('/').get(userController.getAllUsers).post(userController.createNewUser);

router
    .route('/:id')
    .get(userController.getSingleUser)
    .patch(userController.updateUser)
    .delete(userController.deleteUser);

// ! export router
module.exports = router;
