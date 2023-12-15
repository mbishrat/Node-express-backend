const express = require('express')
const userController = require('../controllers/user');
const { protect } = require('../utils/protect');
const router = express.Router();
const upload = require("../utils/multer");


router.post('/register', userController.register)
router.post('/login', userController.login)
router.get("/info",protect,userController.getUserInfo);
router.get("/users",protect,userController.getAllUsersByAdmin);
router.delete('/delete/:userId',protect, userController.deleteUserByAdmin);
router.put("/update",protect,userController.updateUser)
router.put(
    "/profileimage",
    protect,
    upload.array("attachments"),
    userController.profileImage
  );

module.exports = router
