const path = require("path");
const User = require("../models/userModel");
const Chat = require("../models/chatModel");
const sequelize = require("../util/database");
const { Op } = require("sequelize");

// const io = require("socket.io")(5000, {
//   cors: {
//     origin: "http://localhost:4000",
//     methods: ["GET", "POST"],
//     allowedHeaders: ["my-custom-header"],
//     credentials: true,
//   },
// });

// io.on("connection", (socket) => {
//   socket.emit("data", "Hello World");
//   // Listen for "getMessages" event from client
//   socket.on("getMessages", async () => {
//     try {
//       const messages = await Chat.findAll();
//       // Emit "messages" event to the client with the messages data
//       io.emit("messages", messages);
//     } catch (error) {
//       console.log(error);
//     }
//   });
// });

exports.sendMessage = async (req, res, next) => {
  try {
    await Chat.create({
      name: req.user.name,
      message: req.body.message,
      userId: req.user.id,
    });
    return res.status(200).json({ message: "Success!" });
  } catch (error) {
    console.log(error);
    return res.status(400).json({ message: "Error" });
  }
};

exports.getMessages = async (req, res, next) => {
  try {
    const param = req.params.param;
    const messages = await Chat.findAll({
      where: {
        id: {
          [Op.gt]: param,
        },
      },
    });
    return res.status(200).json({ messages: messages });
  } catch (error) {
    console.log(error);
  }
};