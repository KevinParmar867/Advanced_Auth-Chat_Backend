const express = require("express");
const router = express.Router();
const {
  registerUser,
  loginUser,
  logout,
  sendVerificationEmail,
  loginWithCode,
  verifyUser,
  getUser,
  loginStatus,
  getUsers,
  updateUser,
  changePassword,
  forgotPassword,
  resetPassword,
  deleteUser,
  deleteAll,
  upgradeUser,
  sendLoginCode,
  sendAutomatedEmail,
} = require("../controller/userController");
const { protect, adminOnly } = require("../Middleware/authMiddleware");

router.route("/register").post(registerUser);
router.route("/login").post(loginUser);
router.route("/logout").get(logout);

router.route("/sendLoginCode/:email").post(sendLoginCode);
router.route("/loginWithCode/:email").post(loginWithCode);

router.route("/sendVerificationEmail").post(protect, sendVerificationEmail);
router.route("/verifyUser/:verificationToken").patch(verifyUser);
router.route("/sendAutomatedEmail").post(protect, sendAutomatedEmail);

router.route("/getUser").get(protect, getUser);
router.route("/getUsers").get(protect, getUsers);
router.route("/loginStatus").get(loginStatus);

router.route("/updateUser").patch(protect, updateUser);
router.route("/changePassword").patch(protect, changePassword);
router.route("/forgotPassword").post(forgotPassword);
router.route("/resetPassword/:resetToken").patch(resetPassword);

router.route("/:id").delete(protect, adminOnly, deleteUser);
router.route("/upgrade").patch(protect, adminOnly, upgradeUser);
router.route("/delete").post(deleteAll); //incomplete

module.exports = router;
