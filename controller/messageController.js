const asyncHandler = require("express-async-handler");
const Message = require("../models/messageModel");
const Chat = require("../models/chatModel");
const User = require("../models/userModels");

//@description     Get all Messages
//@route           GET /api/Message/:chatId
//@access          Protected
const allMessages = asyncHandler(async (req, res) => {
    // console.log("1", req.params)
    try {
        const messages = await Message.find({ chat: req.params.chatId })
            .populate("sender", "name photo email")
            .populate("chat");
        res.json(messages);
    } catch (error) {
        return res.status(400).json({
            success: false,
            message: error.message,
        });
    }
});

//@description     Create New Message
//@route           POST /api/Message/
//@access          Protected
const sendMessage = asyncHandler(async (req, res) => {
    const { content, chatId } = req.body;

    if (!content || !chatId) {
        console.log("Invalid data passed into request");
        return res.sendStatus(400);
    }

    var newMessage = {
        sender: req.user._id,
        content: content,
        chat: chatId,
    };

    try {
        var message = await Message.create(newMessage);
        
        message = await message.populate("sender", "name photo");
        message = await message.populate("chat");
        
        message = await User.populate(message, {
            path: "chat.users",
            select: "name photo email",
        });

        await Chat.findByIdAndUpdate(req.body.chatId, { latestMessage: message });

        res.json(message);
    } catch (error) {
        return res.status(400).json({
            success: false,
            message: error.message,
        });
    }
});

module.exports = { allMessages, sendMessage };