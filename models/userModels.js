const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
const validator = require("validator");

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        required: [true, "Please Enter Your Name"],
        maxLength: [30, "First Name cannot exceed 30 characters"],
        minLength: [3, "First Name should have more than 4 characters"],
    },

    email: {
        type: String,
        required: [true, "Please Enter Your Email"],
        unique: true,
        validate: [validator.isEmail, "Please Enter a valid Email"],
    },
    password: {
        type: String,
        required: [true, "Please Enter Your Password"],
        minLength: [8, "Password should be greater than 8 characters"],
        // Prevent the password from being returned
        select: false,
    },
    photo: {
        public_id: {
            type: String,
            default: "",
        },
        url: {
            type: String,
            default: "https://i.ibb.co/4pDNDk1/avatar.png",
        },
    },
    // photo: {
    //     type: String,
    //     // required: [true, "Please add a photo"],
    //     default: "https://i.ibb.co/4pDNDk1/avatar.png",
    // },
    phone: {
        type: String,
        default: "1234567890"
    },
    bio: {
        type: String,
        maxLength: [250, "Bio must not be more than 250 characters"],
        default: "bio",
    },
    vToken: {
        type: Object,
        default: {},
    },
    isVerified: {
        type: Boolean,
        default: false,
    },
    role: {
        type: String,
        required: true,
        default: "user",
        // user, author and admin (suspended)
    },
    userAgent: {
        type: Array,
        required: true,
        default: [],
    },
    createdAt: {
        type: Date,
        default: Date.now,
    }
},
    {
        timestamps: true,
        minimize: false,
    }
);

//Encrypt password before saving to DB
userSchema.pre("save", async function (next) {
    const user = this;
    
    if (!user.isModified("password")) {
        return next();
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
    next();
});

const User = mongoose.model('User', userSchema);

module.exports = User;