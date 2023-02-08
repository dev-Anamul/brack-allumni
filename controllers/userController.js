// ! get all users
exports.getAllUsers = (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Get All the users with this route',
    });
};

// ! create new user
exports.createNewUser = (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Create a new user with this route',
    });
};

// ! get single user
exports.getSingleUser = (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Get a single user with this route',
    });
};

// ! update user data
exports.updateUser = (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Update an user data with this route',
    });
};

// ! delete user data
exports.deleteUser = (req, res) => {
    res.status(200).json({
        status: 'success',
        message: 'Delete an user information with this route',
    });
};
