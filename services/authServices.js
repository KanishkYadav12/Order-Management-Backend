import { ROLES, isValidRole } from "../utils/constant.js";
import { User, SuperAdmin, HotelOwner } from "../models/userModel.js";
import Hotel from "../models/hotelModel.js";
import DevKey from "../models/devKeyModel.js";
import { validateDevKey, generatetoken } from "../utils/index.js";
import { ClientError, ServerError } from "../utils/errorHandler.js";
import bcrypt from "bcryptjs";
import sendEmail from "../utils/sendEmail.js";

export const createUserWithRole = async (
  { email, password, role, devKey, name },
  session
) => {
  try {
    // Validate inputs
    if (!email || !password || !isValidRole(role) || !name) {
      throw new ClientError("ValidationError", "Missing required fields");
    }

    // Check if user already exists
    const userExists = await User.findOne({ email });
    if (userExists) {
      throw new ClientError("ConflictError", "User already exists");
    }

    if (role === ROLES.SUPER_ADMIN) {
      await validateDevKey(devKey).catch((error) => {
        throw new ClientError("InvalidDevKey", error.message);
      });

      await DevKey.updateOne(
        { key: devKey },
        { $set: { isUsed: true } },
        { session }
      );
    }

    const Model = role === ROLES.SUPER_ADMIN ? SuperAdmin : HotelOwner;
    const approve = role === ROLES.SUPER_ADMIN;
    const otp = Math.floor(100000 + Math.random() * 900000); // 6-digit OTP
    const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now
    // Create user
    console.log(Model);
    const newUser = new Model({
      name,
      email,
      password,
      role,
      isApproved: approve, // SuperAdmin is auto-approved
      isVerified: false,
      otpDetails: {
        value: otp,
        expiry: otpExpiry,
      },
    });

    const subject = "Email Verification OTP";
    const description = `Your OTP for email verification is ${otp}. It is valid for 10 minutes.`;
    await sendEmail(email, subject, description);
    // if (role === ROLES.HOTEL_OWNER) {
    //   const newHotel = new Hotel({
    //     name: `${name}'s Hotel`,
    //     location: "Default Location",
    //     ownerId: newUser._id,
    //   });

    //   const savedHotel = await newHotel.save({ session });
    //   newUser.hotelId = savedHotel._id;
    // }

    await newUser.save({ session });

    // Generate token
    const token = generatetoken(newUser._id, newUser.role);

    return { newUser, token };
  } catch (error) {
    if (error instanceof ClientError)
      throw new ClientError(error.name, error.message);
    else throw new ServerError(error.message);
  }
};

export const authenticateUser = async ({ email, password, role }) => {
  try {
    // Validate input
    if (!email || !password) {
      throw new ClientError(
        "ValidationError",
        "Email and password are required"
      );
    }

    const Model = role === ROLES.SUPER_ADMIN ? SuperAdmin : HotelOwner;

    // Find user by email
    const user = await Model.findOne({ email });

    if (!user) {
      throw new ClientError("AuthError", "Invalid credentials");
    }

    // Check approval status for hotel owners
    if (user.role === ROLES.HOTEL_OWNER && !user.isApproved) {
      throw new ClientError(
        "ApprovalError",
        "Account not approved by Super Admin"
      );
    }

    // Compare passwords
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      throw new ClientError("AuthError", "Invalid credentials");
    }

    const token = generatetoken(user._id, user.role);

    return { user, token };
  } catch (error) {
    if (error instanceof ClientError)
      throw new ClientError(error.name, error.message);
    else throw new ServerError("Error while authenticating user");
  }
};
