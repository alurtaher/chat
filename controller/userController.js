const path = require("path");
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sequelize = require("../util/database");
const Sib = require("sib-api-v3-sdk");
const { Op } = require("sequelize");

function generateAccessToken(id, email) {
  return jwt.sign({ userId: id, email: email }, process.env.TOKEN);
}

const getLoginPage = async (req, res, next) => {
  try {
    res.sendFile(path.join(__dirname, "../", "public", "views", "login.html"));
  } catch (error) {
    console.log(error);
  }
};

const postUserSignUp = async (req, res, next) => {
  try {
    const name = req.body.name;
    const email = req.body.email;
    const number = req.body.number;
    const password = req.body.password;

    const existingUser = await User.findOne({
      where: {
        [Op.or]: [{ email }, { number }],
      },
    });

    if (existingUser) {
      res
        .status(409)
        .send(
          `<script>alert('This email or number is already taken. Please choose another one.'); window.location.href='/'</script>`
        );
    } else {
      bcrypt.hash(password, 10, async (err, hash) => {
        await User.create({
          name: name,
          email: email,
          number: number,
          password: hash,
        });
      });
      res
        .status(200)
        .send(
          `<script>alert('User Created Successfully!'); window.location.href='/'</script>`
        );
    }
  } catch (error) {
    console.log(error);
  }
};

const postUserLogin = async (req, res, next) => {
  try {
    const { loginEmail: email, loginPassword: password } = req.body;

    // Check if user exists
    const user = await User.findOne({ where: { email } });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User doesn't exist!",
      });
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({
        success: false,
        message: "Password Incorrect!",
      });
    }

    // If login success
    return res.status(200).json({
      success: true,
      message: "Login Successful!",
      token: generateAccessToken(user.id, user.email),
    });

  } catch (error) {
    console.error(error);
    return res.status(500).json({
      success: false,
      message: "Something went wrong!",
    });
  }
};


module.exports = {
  getLoginPage,
  postUserSignUp,
  postUserLogin,
};