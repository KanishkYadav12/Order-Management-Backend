import { catchAsyncError } from "../middlewares/catchAsyncError.js";
import { HotelOwner, SuperAdmin, User } from "../models/userModel.js";
import { createUserWithRole, authenticateUser } from "../services/authServices.js";
import sendEmail from "../utils/sendEmail.js";
import crypto from 'crypto';


export const signUp = catchAsyncError(async (req, res, next, session) => {
  console.log("signup-req : ", req.body);
  const { email, password, role, devKey, name } = req.body;

  const { newUser, token } = await createUserWithRole(
    { email, password, role, devKey, name },
    session
  );

  res.cookie("token", token, {
    httpOnly: false,
    sameSite: 'None',
    secure: process.env.NODE_ENV === "production",
    maxAge: 10 * 24 * 60 * 60 * 1000, // 10 days
  });

  res.status(201).json({
    status: "success",
    message: "User created successfully",
    data: newUser
    // data: {user: newUser}
  });
}, true);


export const login = catchAsyncError(async (req, res) => {
  const { email, password, role } = req.body;

  const { user, token } = await authenticateUser({ email, password, role });

  res.cookie("token", token, {
    httpOnly: false,
    sameSite: 'None',
    secure: true,
    maxAge: 10 * 24 * 60 * 60 * 1000, // 10 days
  });

  res.status(200).json({
    status: "success",
    message: 'Login successful',
    data: {
      id: user._id,
      name: user.name,
      role: user.role,
      email: user.email,
      token,
    }
  });
});

export const resendOtp = catchAsyncError(async (req, res) => {
  const { email } = req.body;
  console.log("resend-otp-called : ", email)
  // Find the user by email
  let user = await SuperAdmin.findOne({ email: email });
  if (!user) user = await HotelOwner.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ message: 'User not found.' });
  }

  // Check if the user is already verified
  if (user.isVerified) {
    return res.status(400).json({ message: 'User is already verified.' });
  }

  // Generate a new OTP
  const newOtp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
  const newExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

  // Update user's OTP details
  user.otpDetails = {
    value: newOtp,
    expiry: newExpiry,
  };
  await user.save();

  // Send the new OTP via email
  const subject = 'Resend OTP for Email Verification';
  const description = `Your new OTP for email verification is ${newOtp}. It is valid for 10 minutes.`;
  await sendEmail(email, subject, description);

  res.status(200).json({
    status: "success",
    message: 'OTP has been resent to your email.',
  });
});


export const logout = (req, res) => {
  res.cookie("token", "", { maxAge: 1, sameSite: "None" });
  res.status(200).json({ status: "success", message: "Logout successful" });
};

// Email Verification Controller
export const verifyEmail = catchAsyncError(async (req, res) => {
  const { email, otp } = req.body;

  // Find user by email
  console.log("email : ", email)
  let user = await SuperAdmin.findOne({ email: email });
  if (!user) user = await HotelOwner.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ status: "failed", message: 'User not found.' });
  }

  console.log(user)


  // Check if OTP matches and is not expired
  if (
    user?.otpDetails?.value === Number(otp) &&
    user?.otpDetails?.expiry > new Date()
  ) {
    // Mark user as verified
    user.isVerified = true;
    user.otpDetails = { value: null, expiry: null }; // Clear OTP details
    await user.save();

    return res.status(200).json({ status: "success", message: 'Email verified successfully from backend.' });
  } else {
    return res.status(400).json({ status: "success", message: 'Invalid or expired OTP.' });
  }
}
);

//reset password link sender after recieving email as input if email exists in db 
export const forgotPassword = catchAsyncError(async (req, res) => {
  const { email } = req.body;

  // Find user by email
  let user = await SuperAdmin.findOne({ email: email });
  if (!user) user = await HotelOwner.findOne({ email: email });
  if (!user) {
    return res.status(404).json({ status: "failed", message: 'User not found.' });
  }

  // Generate a password reset token with jwt 
  const resetToken = user.createPasswordResetToken();
  await user.save({ validateBeforeSave: false });


  // const frontendURL = process.env.FRONTEND_URL;
 
  const frontendURL = 'https://orm-frontend-eight.vercel.app';
  const resetURL = `${frontendURL}/reset-password/${resetToken}`;

  const subject = 'Password Reset Link';
  const description = `Click on the link below to reset your password. The link will expire in 10 minutes.\n\n${resetURL}`;
  await sendEmail(email, subject, description);

  res.status(200).json({
    status: "success",
    message: 'Password reset link has been sent to your email.',
  });
});


//reset password after recieving token and new password as input 
export const resetPassword = catchAsyncError(async (req, res) => {
  const { token } = req.params; // Plain token from the URL
  const { password } = req.body;

  // Hash the incoming token to match the stored hashed token
  const hashedToken = crypto.createHash('sha256').update(token).digest('hex');

  // Find user by hashed token and ensure the token is not expired
  let user = await SuperAdmin.findOne({
    passwordResetToken: hashedToken,
    passwordResetExpires: { $gt: Date.now() }, // Ensure token is still valid
  });

  if (!user) {
    user = await HotelOwner.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });
  }

  if (!user) {
    return res.status(400).json({ status: "failed", message: 'Invalid or expired token.' });
  }

  // Update user's password
  user.password = password; // Assuming you have pre-save middleware to hash passwords
  user.passwordResetToken = undefined; // Clear the reset token
  user.passwordResetExpires = undefined; // Clear the expiration time
  await user.save();

  res.status(200).json({
    status: "success",
    message: 'Password reset successful.',
  });
});

