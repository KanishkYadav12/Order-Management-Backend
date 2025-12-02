import Joi from "joi";

const signUpSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required(),
    role: Joi.string().valid("superadmin", "hotelowner").required(),
    devKey: Joi.string().optional(),
    name: Joi.string().required(),
});

// should we use it ?