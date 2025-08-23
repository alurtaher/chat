const express = require("express");
const router = express.Router();

const userController = require("../controller/userController");
const userAuthentication = require("../middleware/auth");

router.get("/", userController.getLoginPage);

module.exports = router;
