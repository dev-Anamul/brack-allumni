/* eslint-disable comma-dangle */
const express = require('express');
const userController = require('../controllers/userController');
const authController = require('../controllers/authController');
const { uploadUserImage, resizeProfilePhoto } = require('../middlewares/imageUpload');

// ! initialize router
const router = express.Router();

// ! auth routes
router.post('/signup', uploadUserImage, resizeProfilePhoto, authController.signUp);
router.post('/login', authController.login);
router.post('/forgot-password', authController.forgotPassword);
router.patch('/reset-password/:token', authController.resetPassword);

// ! private access routes
router.use(authController.protect, authController.isAccountApproved);
router.patch('/update-my-password', authController.updatePassword);
router.patch('/update-me', uploadUserImage, resizeProfilePhoto, authController.updateMe);
router.delete('/delete-me', authController.deleteMe);
router.get('/me', authController.getMe, userController.getSingleUser);

// ! private access routes for admin
router.use(authController.restrictTo('admin'));
router.get('/approve/:id', authController.approveUser);
router
    .route('/')
    .get(userController.getAllUsers)
    .post(uploadUserImage, resizeProfilePhoto, userController.createNewUser);
router
    .route('/:id')
    .get(userController.getSingleUser)
    .patch(uploadUserImage, resizeProfilePhoto, userController.updateUser)
    .delete(userController.deleteUser);

// ! export router
module.exports = router;
