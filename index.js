const dotenv = require('dotenv').config();
const express = require('express')
const app = express()
const connectToMongo = require("./db");
const cookieParser = require("cookie-parser");
const cors = require('cors');
const bodyParser = require("body-parser");
const userRoutes = require("./routes/userRoutes")
const errorMiddleware = require("./Middleware/errorMiddleware");
const fileUpload = require("express-fileupload");
const chatRoutes = require("./routes/chatRoutes");
const messageRoutes = require("./routes/messageRoutes");


// Load environment variables early
if (dotenv.error) {
    console.error("Error loading .env file:", dotenv.error);
    process.exit(1); // Exit the process if .env loading fails
}

//constant value from dotenv 
const PORT = process.env.PORT || 8000

// Middleware for Errors
app.use(errorMiddleware);

//connect to database
connectToMongo()

// Middleware for express
app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true,
}));
app.use(express.json());
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(fileUpload({
    useTempFiles: true
}));

//routes
app.use("/api/v1", userRoutes);
app.use("/api/v1/chat", chatRoutes);
app.use("/api/v1/message", messageRoutes);

// Middleware for Errors 
// (it required to give database error so server can't crash)
// it used after db connect
app.use(errorMiddleware);

const server = app.listen(PORT, () => {
    console.log(`Example app listening on port http://localhost:${PORT}`)
})

const io = require("socket.io")(server, {
    pingTimeout: 60000,
    cors: {
        origin: "http://localhost:3000",
        credentials: true,
    },
});

io.on("connection", (socket) => {

    socket.on("setup", (userData) => {
        socket.join(userData._id);
        socket.emit("connected");
    });

    socket.on("join chat", (room) => {
        socket.join(room);
    });

    socket.on("new message", (newMessageReceived) => {
        // chat.users  ,
        var chat = newMessageReceived.chat;

        if (!chat || !chat.users) {
            return console.log("chat.users not defined");
        }

        chat.users.forEach((user) => {
            if (user._id == newMessageReceived.sender._id) return;

            socket.in(user._id).emit("message received", newMessageReceived);
        });
    });


    socket.off("setup", () => {
        console.log("USER DISCONNECTED");
        socket.leave(userData._id);
    });
});