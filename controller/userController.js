const path = require("path");
const User = require("../models/userModel");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const sequelize = require("../util/database");
const Sib = require("sib-api-v3-sdk");
const { Op } = require("sequelize");

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

    await User.findOne({ [Op.or]: [{ email: email }, { number: number }] })
      .then((user) => {
        if (user) {
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
      })
      .catch((err) => console.log(err));
  } catch (error) {
    console.log(error);
  }
};

module.exports = {
  getLoginPage,
  postUserSignUp
};
