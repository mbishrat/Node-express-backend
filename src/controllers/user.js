const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('../model/user');
const {SECRET_KEY }= require('../config/env')


exports.register = async (req, res) => {
  const { firstName, lastName, email, password } = req.body;

  if (password.length < 8) {
    return res
      .status(400)
      .json({ message: "Password must be at least 8 characters long" });
  }

  try {
    const existingUser = await User.findOne({ email: email });
    if (existingUser) {
      return res
        .status(400)
        .json({ message: "User with this email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      firstName,
      lastName,
      email,
      password: hashedPassword,
    });

    const savedUser = await newUser.save();
    res
      .status(201)
      .json({ message: "User created successfully", user: savedUser });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};

exports.login = async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email: email });
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);

    if (!passwordMatch) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const token = jwt.sign({ userId: user._id }, SECRET_KEY, { expiresIn: '1h' });

    // Exclude the password field from the response
    const userWithoutPassword = { ...user._doc };
    delete userWithoutPassword.password;

    res.status(200).json({ message: 'Sign in successful', user: userWithoutPassword, token });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong' });
  }
};

exports.getUserInfo = async (req, res) => {
  try {
    const userId = req.user._id;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    const { password, ...userWithoutPassword } = user._doc;

    res.status(200).json({
      message: "User information retrieved",
      user: userWithoutPassword,
    });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};
exports.updateUser = async (req, res) => {
  const userId = req.user._id;
  const { firstName, lastName, email, password,address,phoneNumber } = req.body;

  try {
    const user = await User.findById(userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    user.firstName = firstName || user.firstName;
    user.lastName = lastName || user.lastName;
    user.email = email || user.email;
    user.address = address|| user.address;
    user.phoneNumber = phoneNumber|| user.phoneNumber

    if (password) {
      const hashedPassword = await bcrypt.hash(password, 10);
      user.password = hashedPassword;
    }

    const updatedUser = await user.save();

    const { password: userPassword, ...userWithoutPassword } = updatedUser._doc;

    res.status(200).json({
      message: "User updated successfully",
      user: userWithoutPassword,
    });
  } catch (error) {
    res.status(500).json({ message: "Something went wrong" });
  }
};
exports.getAllUsersByAdmin = async (req, res) => {
  try {
    const currentUser = await User.findById(req.user._id);

    if (!currentUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (currentUser.userType !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized access, admin can access this page' });
    }

    const allUsers = await User.find({userType: "user"});

    res.status(200).json(allUsers);
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.deleteUserByAdmin = async (req, res) => {
  try {
    const currentUser = await User.findById(req.user._id);

    if (!currentUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    if (currentUser.userType !== 'admin') {
      return res.status(403).json({ message: 'Unauthorized access, admin privilege required' });
    }

    const userIdToDelete = req.params.userId;

    const userToDelete = await User.findById(userIdToDelete);

    if (!userToDelete) {
      return res.status(404).json({ message: 'User to delete not found' });
    }

    if (userToDelete.userType === 'admin') {
      return res.status(403).json({ message: 'Cannot delete other admins' });
    }

    await User.findByIdAndDelete(userIdToDelete);

    res.status(200).json({ message: 'User deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: error.message });
  }
};
exports.profileImage = async (req, res) => {
  try {
    const userId = req.user._id;

    const user = await User.findById(userId).select('-password');

    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }

    if (req.files) {
      const totalFileSize = req.files.reduce((acc, file) => acc + file.size, 0);
      if (totalFileSize > 50 * 1024 * 1024) {
        return res
          .status(400)
          .json({ error: "Maximum total file size is 50MB" });
      }
    }

    const profileImage = req.files;

    const processFiles = async (files, attachmentArray) => {
      if (files) {
        files.forEach((file) => {
          attachmentArray.push({
            filename: file.originalname,
            filePath: file.path,
          });
        });
      }
    };

    processFiles(profileImage, user.profileImage);

    await user.save();

    return res.status(201).json(user)
  } catch (error) {
    console.error(error);
    return res.status(500).json({ error: "Something Went Wrong!" });
  }
};