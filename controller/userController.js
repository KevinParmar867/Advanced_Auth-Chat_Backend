const asyncHandler = require("express-async-handler");
const User = require("../models/userModels");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const Token = require("../models/tokenModel");
const crypto = require("crypto");
const sendEmail = require("../utils/sendEmail");
const parser = require("ua-parser-js");
const { hashToken, generateToken, decrypt, encrypt } = require("../utils/hash");
const cloudinary = require('cloudinary').v2;

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
    api_key: process.env.CLOUDINARY_API_KEY,
    api_secret: process.env.CLOUDINARY_API_SECRET,
});

//Done Register User
exports.registerUser = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
        return res.status(400).json({
            success: false,
            message: "Please fill in all required fields",
        });
    }
    if (password.length < 6) {
        return res.status(400).json({
            success: false,
            message: "Password must be up to 6 characters",
        });
    }

    // Check if user email already exists
    const userExists = await User.findOne({ email });

    if (userExists) {
        return res.status(400).json({
            success: false,
            message: "Email has already been registered",
        });
    }

    // Get User Device Details
    const ua = parser(req.headers["user-agent"]);
    const userAgent = [ua.ua];

    // Create new user
    const user = await User.create({
        name,
        email,
        password,
        userAgent,
    });

    //   Generate JWT Token
    const token = generateToken(user._id);

    // Send HTTP-only cookie
    res.cookie("token", token, {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
    });

    if (user) {
        const { _id, name, email, photo, phone, bio, isVerified, role } = user;
        res.status(201).json({
            success: true,
            message: "Register Successfully",
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            isVerified,
            role,
            token,
        });
    } else {
        return res.status(400).json({
            success: false,
            message: "Invalid user data",
        });
    }
});

//Done Login User
// loginToken used in save Login code 
exports.loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // Validate Request
    if (!email || !password) {
        return res.status(400).json({
            success: false,
            message: "Please add email and password",
        });
    }

    // Check if user exists
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
        return res.status(400).json({
            success: false,
            message: "User not found, please signup",
        });
    }

    // User exists, check if password is correct
    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
        return res.status(400).json({
            success: false,
            message: "Invalid email or password",
        });
    }

    // Trigger 2FA for unknown userAgent/device
    const ua = parser(req.headers["user-agent"]);
    const thisUserAgent = ua.ua;

    const allowedDevice = user.userAgent.includes(thisUserAgent);

    if (!allowedDevice) {
        const loginCode = Math.floor(100000 + Math.random() * 900000);
        console.log(loginCode)

        // Hash token before saving to DB
        const encryptedLoginCode = encrypt(loginCode.toString());

        // Delete token if it exists in DB
        let userToken = await Token.findOne({ userId: user._id });

        if (userToken) {
            await userToken.deleteOne();
        }

        // Save Access Token to DB
        await new Token({
            userId: user._id,
            loginToken: encryptedLoginCode,
            createdAt: Date.now(),
            expiresAt: Date.now() + 30 * (60 * 1000), // Thirty minutes
        }).save();

        return res.status(400).json({
            success: false,
            message: "Check your email for login code",
        });
    }

    //   Generate Token


    const token = generateToken(user._id);

    if (user && passwordIsCorrect) {

        const options = {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            secure: true,
        };

        const { _id, name, email, photo, phone, bio, isVerified, role } = user;
        return res.status(200).cookie("token", token, options).json({
            success: true,
            message: "Login Successfully",
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            isVerified,
            role,
        });
    } else {
        return res.status(400).json({
            success: false,
            message: "Something went wrong, please try again",
        });
    }
});

//Done Send Verification Email
// verify token used for here
exports.sendVerificationEmail = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    // Check if user doesn't exists
    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User not found",
        });
    }

    if (user.isVerified) {
        return res.status(400).json({
            success: false,
            message: "User already verified",
        })
    }

    // Delete token if it exists in DB
    let token = await Token.findOne({ userId: user._id });

    if (token) {
        await token.deleteOne();
    }

    // Create Verification Token and save
    const verificationToken = crypto.randomBytes(32).toString("hex") + user.id;

    // Hash token before saving to DB
    const hashedToken = hashToken(verificationToken);

    // Save Token to DB
    await new Token({
        userId: user._id,
        vToken: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 60 * (60 * 1000), // Thirty minutes
    }).save();

    // Construct Verification Url
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${verificationToken}`;
    const subject = "Verify Your Account - AUTH:Z";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "noreply@kevinparmar.com";

    // find file in ./view folder and match name and send in mail
    const template = "verifyEmail";
    const name = user.name;
    const link = verificationUrl;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );

        return res.status(200).json({
            success: true,
            message: "Verification Email Sent"
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Email not sent, please try again \n" + error,
        })
    }
});

// Done send Login Code
exports.sendLoginCode = asyncHandler(async (req, res) => {

    const { email } = req.params;

    const user = await User.findOne({ email });

    // Check if user doesn't exists
    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User not found",
        });
    }

    // Find Access Token in DB
    let userToken = await Token.findOne({ userId: user._id });

    if (!userToken) {
        return res.status(500).json({
            success: false,
            message: "Invalid or Expired token, Login again",
        });
    }

    // get the login code
    const loginCode = userToken.loginToken;
    const decryptedLoginCode = decrypt(loginCode);
    const subject = "Login Access Code - AUTH:Z";
    const send_to = email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "noreply@zinotrustacademy.com";
    const template = "accessToken";
    const name = user.name;
    const link = decryptedLoginCode;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({
            success: true,
            message: "Access Code Sent to your email."
        });
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Email not sent, please try again"
        });
    }
});

//Done Login with code
exports.loginWithCode = asyncHandler(async (req, res) => {
    const { email } = req.params;
    const { loginCode } = req.body;

    const user = await User.findOne({ email });

    // Check if user doesn't exists
    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User not found",
        });
    }

    // Find Token in DB
    const userToken = await Token.findOne({
        userId: user.id,
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        return res.status(404).json({
            success: false,
            message: "Invalid or Expired Code, please login again",
        });
    }

    const decryptedLoginCode = decrypt(userToken.loginToken);

    // Log user in
    if (loginCode !== decryptedLoginCode) {
        return res.status(400).json({
            success: false,
            message: "Incorrect login code, please try again",
        });
    } else {
        // Register the userAgent
        const ua = parser(req.headers["user-agent"]);
        const thisUserAgent = ua.ua;
        user.userAgent.push(thisUserAgent);
        await user.save();

        //   Generate Token
        const token = generateToken(user._id);

        // Send HTTP-only cookie
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            secure: true,
        });

        const { _id, name, email, photo, phone, bio, isVerified, role } = user;
        res.status(200).json({
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            isVerified,
            role,
            token,
        });
    }
});

//Done Verify User
//verify token used here
exports.verifyUser = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;

    // Hash Token
    const hashedToken = crypto
        .createHash("sha256")
        .update(verificationToken)
        .digest("hex");

    // FIND TOKEN in DB
    const userToken = await Token.findOne({
        vToken: hashedToken,
        //$gt represent greater than current time
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        return res.status(404).json({
            success: false,
            message: "Invalid or Expired Token!!!",
        });
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId });

    if (user.isVerified) {
        return res.status(400).json({
            success: false,
            message: "User is already verified!!!",
        });
    }

    // Now Verify user
    user.isVerified = true;
    await user.save();

    res.status(200).json({
        success: true,
        message: "Account Verification Successful",
    });
});

//Done Get User Data
exports.getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, photo, phone, bio, isVerified, role, vToken } =
            user;

        return res.status(200).json({
            success: true,
            _id,
            name,
            email,
            photo,
            phone,
            bio,
            isVerified,
            role,
            vToken,
        });
    } else {
        return res.status(400).json({
            success: false,
            message: "User Not Found",
        });
    }
});

//Done Get Login Status
exports.loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false);
    }
    // Verify Token
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    if (verified) {
        return res.json(true);
    }
    return res.json(false);
});

//Done Update User
exports.updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    const file = req.files?.photo;

    if (user) {
        const { name, email, phone, bio, role, isVerified } = user;
        user.email = email;
        user.name = req.body.name || name;
        user.phone = req.body.phone || phone;
        user.bio = req.body.bio || bio;

        if (file) {
            // Delete the old photo if it exists
            if (user.photo && user.photo.public_id) {
                await cloudinary.uploader.destroy(user.photo.public_id);
            }

            // Upload the new photo to Cloudinary
            const myCloud = await cloudinary.uploader.upload(file.tempFilePath, {
                folder: "Auth",
                width: 250,
                crop: "scale",
            });

            // Save the Cloudinary public_id and URL in your user object
            user.photo = {
                public_id: myCloud.public_id,
                url: myCloud.secure_url,
            };

        }

        const updatedUser = await user.save();

        return res.status(200).json({
            success: true,
            message: "User Update Successfully",
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            photo: updatedUser.photo,
            phone: updatedUser.phone,
            bio: updatedUser.bio,
            role,
            isVerified,
        });
    } else {
        res.status(404).json({
            success: true,
            message: "User not found",
        });
    }
});

//Done change password
exports.changePassword = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select("+password");
    const { oldPassword, password } = req.body;

    if (!user) {
        return res.status(400).json({
            success: false,
            message: "User not found, please signup",
        });
    }
    //Validate
    if (!oldPassword || !password) {
        return res.status(400).json({
            success: false,
            message: "Please add old and new password",
        });
    }

    // check if old password matches password in DB
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    // Save new password
    if (user && passwordIsCorrect) {
        user.password = password;
        await user.save();

        return res.status(200).json({
            success: true,
            message: "Password change successful, please re-login"
        });
    } else {
        return res.status(400).json({
            success: false,
            message: "Old password is incorrect",
        });
    }
});

//Done forgot password
//Token models token token is used here
exports.forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User does not exist",
        });
    }

    // Delete token if it exists in DB
    let token = await Token.findOne({ userId: user._id });
    if (token) {
        await token.deleteOne();
    }

    // Create Reset Token
    let resetToken = crypto.randomBytes(32).toString("hex") + user._id;

    // Hash token before saving to DB
    const hashedToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    // Save Token to DB
    await new Token({
        userId: user._id,
        token: hashedToken,
        createdAt: Date.now(),
        expiresAt: Date.now() + 30 * (60 * 1000), // Thirty minutes
    }).save();

    // Construct Reset Url
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // Reset Email
    const subject = "Password Reset Request";
    const send_to = user.email;
    const sent_from = process.env.EMAIL_USER;
    const reply_to = "noreply@zinotrustacademy.com";
    const template = "forgotPassword";
    const name = user.name;
    const link = resetUrl;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({ success: true, message: "Email Sent!!!" });
    } catch (error) {
        res.status(500).json({
            success: true,
            message: "Email not sent, please try again"
        });
    }
});

//Done Reset Password
//Token models token is used here 
exports.resetPassword = asyncHandler(async (req, res) => {
    const { password } = req.body;
    const { resetToken } = req.params;

    // Hash token, then compare to Token in DB
    const hashedToken = crypto
        .createHash("sha256")
        .update(resetToken)
        .digest("hex");

    // Find Token in DB
    const userToken = await Token.findOne({
        token: hashedToken,
        expiresAt: { $gt: Date.now() },
    });

    if (!userToken) {
        return res.status(404).json({
            success: false,
            message: "Invalid or Expired Token",
        });
    }

    // Find user and reset password
    const user = await User.findOne({ _id: userToken.userId });
    user.password = password;
    await user.save();

    return res.status(200).json({
        success: true,
        message: "Password Reset Successful, Please Login",
    });
});

//Done get all user data
exports.getUsers = asyncHandler(async (req, res) => {
    const users = await User.find().sort("-createdAt");
    if (!users) {
        res.status(500).json({
            success: false,
            message: "Something went wrong",
        });
    }
    res.status(200).json([
        ...users
    ]);
});

//Done Logout User
exports.logout = asyncHandler(async (req, res) => {
    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(0),
        sameSite: "none",
        secure: true,
    });
    return res.status(200).json({
        success: true,
        message: "Logout Successfully"
    });
});

//Done --Admin-- delete user
exports.deleteUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    // if user doesn't exist
    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User not found",
        });
    }

    await User.findByIdAndDelete(req.params.id);

    res.status(200).json({
        success: true,
        message: "User deleted successfully"
    });
});

//Done --Admin-- upgrade user
exports.upgradeUser = asyncHandler(async (req, res) => {
    const { role, id } = req.body;

    // Get the user
    const user = await User.findById(id);

    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User not found",
        });
    }

    user.role = role;
    await user.save();

    res.status(200).json({
        success: true,
        message: `User role updated to ${role}`
    });
});

//Done Send Automated Email
exports.sendAutomatedEmail = asyncHandler(async (req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;
    // res.send(template);

    if (!subject || !send_to || !reply_to || !template) {

        res.status(400).json({
            success: false,
            message: "Missing automated email parameter"
        });
    }

    // Get user
    const user = await User.findOne({ email: send_to });

    if (!user) {
        return res.status(404).json({
            success: false,
            message: "User not found"
        });
    }

    // const subject = "Verify Your Account - AUTH:Z";
    // const send_to = user.email;
    // const sent_from = process.env.EMAIL_USER;
    // const reply_to = "noreply@zinotrustacademy.com";
    // const template = "email";
    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link = `${process.env.FRONTEND_URL}${url}`;
    // const role = user.role;

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link
        );
        res.status(200).json({
            success: true,
            message: "Email Sent!!!"
        });
    } catch (error) {
        res.status(500).json({
            success: false,
            message: "Email not sent, please try again"
        });
    }
});


exports.deleteAll = asyncHandler(async (req, res) => {
    // await Token.deleteMany({});
    res.send("Encrypt");
    // const crypted = encrypt(content);

    // const decrypted = decrypt(crypted);
});