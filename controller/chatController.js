const asyncHandler = require("express-async-handler");
const Chat = require("../models/chatModel");
const User = require("../models/userModels");

// create one by one chat
const accessChat = asyncHandler(async (req, res) => {
    const { userId } = req.body;

    if (!userId) {
        return res.status(400).json({
            success: false,
            message: "UserId param not sent with request",
        });
    }

    var existingChat = await Chat.findOne({
        isGroupChat: false,
        $and: [
            { users: { $elemMatch: { $eq: req.user._id } } },
            { users: { $elemMatch: { $eq: userId } } },
        ],
    });

    if (existingChat) {
        // Chat already exists, return chat ID and related status code
        return res.status(200).json({
            chatId: existingChat._id,
            message: "Chat already exists",
        });
    }

    var chatData = {
        chatName: "sender",
        isGroupChat: false,
        users: [req.user._id, userId],
    };

    try {
        const createdChat = await Chat.create(chatData);
        const FullChat = await Chat.findOne({ _id: createdChat._id }).populate(
            "users",
        );
        res.status(200).json(FullChat);
    } catch (error) {
        console.log("error", error);
        return res.status(400).json({
            success: false,
            message: error.message,
        });
    }
});


// fetch chats
const fetchChats = asyncHandler(async (req, res) => {
    try {
        Chat.find({ users: { $elemMatch: { $eq: req.user._id } } })
            .populate("users", "-password")
            .populate("groupAdmin", "-password")
            .populate("latestMessage")
            .sort({ updatedAt: -1 })
            .then(async (results) => {
                results = await User.populate(results, {
                    path: "latestMessage.sender",
                    select: "name photo email",
                });
                res.status(200).send(results);
            });
    } catch (error) {
        return res.status(400).json({
            success: false,
            message: error.message,
        });
    }
});

//create group chat
const createGroupChat = asyncHandler(async (req, res) => {

    if (!req.body.users || !req.body.name) {
        return res.status(400).json({
            success: false,
            message: "Please Fill all the fields",
        });
    }

    // Parse the stringified JSON array
    var users = JSON.parse(req.body.users);

    if (!Array.isArray(users) || users.length < 2) {
        return res.status(400).json({
            success: false,
            message: "Invalid users array. More than 2 users are required to form a group chat",
        });
    }

    // Convert req.user._id to a string if needed
    const userId = req.user._id.toString();

    // Push userId into the users array
    users.push(userId);

    try {
        const groupChat = await Chat.create({
            chatName: req.body.name,
            users: users,
            isGroupChat: true,
            groupAdmin: req.user,
        });

        const fullGroupChat = await Chat.findOne({ _id: groupChat._id })
            .populate("users", "-password")
            .populate("groupAdmin", "-password");

        res.status(200).json(fullGroupChat);
    } catch (error) {
        return res.status(400).json({
            success: false,
            message: error.message,
        });
    }
});

//rename group 
const renameGroup = asyncHandler(async (req, res) => {
    const { chatId, chatName } = req.body;

    const updatedChat = await Chat.findByIdAndUpdate(chatId,{chatName: chatName},{new: true})
        .populate("users", "-password")
        .populate("groupAdmin", "-password");

    if (!updatedChat) {
        return res.status(404).json({
            success: false,
            message: "Chat Not Found",
        });
    } else {
        res.json(updatedChat);
    }
});

// remove user to group
const removeFromGroup = asyncHandler(async (req, res) => {

    const { chatId, userId } = req.body;

    if (!chatId || !userId) {
        return res.status(400).json({
            success: false,
            message: "Invalid Request",
        });
    }

    // check if the requester is admin

    const removed = await Chat.findByIdAndUpdate(chatId, { $pull: { users: userId }, }, { new: true, }).populate("users", "-password").populate("groupAdmin", "-password");

    if (!removed) {
        return res.status(404).json({
            success: false,
            message: "Chat Not Found",
        });
    } else {
        res.status(200).json("removed");
    }
});

// add user to group
const addToGroup = asyncHandler(async (req, res) => {
    const { chatId, userId } = req.body;

    // console.log(chatId, userId)

    if (!chatId || !userId) {
        return res.status(400).json({
            success: false,
            message: "Invalid Request",
        });
    }

    // check if the requester is admin

    const added = await Chat.findByIdAndUpdate(chatId, { $push: { users: userId }, }, { new: true, })
        .populate("users")
        .populate("groupAdmin");

    if (!added) {
        return res.status(404).json({
            success: false,
            message: "Chat Not Found",
        });
    } else {
        res.json(added);
    }
});

module.exports = {
    accessChat,
    fetchChats,
    createGroupChat,
    renameGroup,
    addToGroup,
    removeFromGroup,
};