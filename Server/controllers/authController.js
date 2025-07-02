import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken';
import userModel from '../models/userModel.js';

import transporter from '../config/nodemailer.js';
import { EMAIL_VERIFY_TEMPLATE, PASSWORD_RESET_TEMPLATE } from '../config/emailTemplates.js';


//User Registration
export const register = async (req, res) => {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
        return res.json({ success: false, message: 'Missing Details!' })
    }
    try {

        //checking for existing user through email id
        const existingUser = await userModel.findOne({ email }) //Uses await because it's a MongoDB operation (asynchronous).

        if (existingUser) {
            return res.json({ success: false, message: "User already exists" });
        }

        //if we write there high number then it will provide high security but it will take more time to encrypt the password rang(5-15) as More rounds = more secure, but also more time.
        const hashedPassword = await bcrypt.hash(password, 10);

        const user = new userModel({ name, email, password: hashedPassword });
        await user.save();

        //  JWT Token Creation
        const token = jwt.sign(
            { id: user._id },            // payload-  This is the actual data you are storing in the token.
            process.env.JWT_SECRET,  // secret key for signature
            { expiresIn: '7d' });     // optional config (adds exp to payload)

        // Sending Token as a Cookie in response
        res.cookie('token',token,{
            httpOnly :true,
            secure: process.env.NODE_ENV === 'production',
            sameSite : process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge : 7 * 24 * 60 * 60 * 1000 //7days
        });
       



        //Sending welcome email
        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: email,
            subject: 'Welcome to MERN-AUTH',
            text: `Welcome to the MERN-AUTH Website. Your account has been created with email id : ${email}`
        }

        await transporter.sendMail(mailOptions);

        return res.json({ success: true });

    } catch (error) {
        res.json({ success: false, message: error.message })
    }
}

//User Login
export const login = async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.json({ success: false, message: 'Email and password are required' })
    }

    try {

        const user = await userModel.findOne({ email });

        if (!user) {
            return res.json({ success: false, message: 'Invalid email' })
        }

        const isMatch = await bcrypt.compare(password, user.password);

        if (!isMatch) {
            return res.json({ success: false, message: 'Invalid password' })
        }

        //  JWT Token Creation
        const token = jwt.sign(
            { id: user._id },            // payload-  This is the actual data you are storing in the token.
            process.env.JWT_SECRET,  // secret key for signature
            { expiresIn: '7d' });     // optional config (adds exp to payload)

        // Sending Token as a Cookie in response
        res.cookie('token', token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',
            maxAge: 7 * 24 * 60 * 60 * 1000 //7days
        });
       


        return res.json({ success: true });


    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//User Logout
export const logout = async (req, res) => {
    try {
        //clears the cookie from the users browse
        res.clearCookie('token', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'strict',

        })

       


        return res.json({ success: true, message: "Logged Out" })
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//Send Verification OTP to the User's Email
export const sendVerifyOtp = async (req, res) => {
    try {
        const { userId } = req.body;

        const user = await userModel.findById(userId);

        if (user.isAccountVerified) {
            return res.json({ success: false, message: "Account Already Verified" })
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));

        user.verifyOtp = otp;
        user.verifyOtpExpireAt = Date.now() + 10 * 60 * 60 * 1000 //10 hour

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'Account Verification OTP',
            //text: `Your OTP is ${otp}. Verify  your account using this OTP.`,
            html: EMAIL_VERIFY_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}",
                user.email)

        }
        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'Verification OTP Sent on Email' })

    } catch (error) {
        res.json({ success: false, message: error.message })
    }
}

//Verify  the Email using the OTP
export const verifyEmail = async (req, res) => {
    const { userId, otp } = req.body;

    if (!userId || !otp) {
        return res.json({ success: false, message: 'Missing Details' });
    }
    try {
        const user = await userModel.findById(userId);

        if (!user) {
            return res.json({ success: false, message: 'User not found' })
        }

        if (user.verifyOtp == '' || user.verifyOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' })
        }

        if (user.verifyOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP Expired' });
        }





        user.isAccountVerified = true;
        user.verifyOtp = '';
        user.verifyOtpExpireAt = 0;

        await user.save();

        return res.json({ success: true, message: 'Email verified successfully' })



    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}


//have you woundered how we will get userid from req body. from cookie through token we create a middleware actually we will get userid from token and token is stored in cookie so get need a middleware that will get the cookie from that cookie we will find token and from that token we find  userId and that userid will be added to req body that will done using a function i.e middleware


// Check if user is Authenticated
export const isAuthenticated = async (req, res) => {

    try {
        return res.json({ success: true });
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//Send Password Reset OTP
export const sendResetOtp = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.json({ success: false, message: 'Email is required' });
    }

    try {

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        const otp = String(Math.floor(100000 + Math.random() * 900000));
        user.resetOtp = otp;
        user.resetOtpExpireAt = Date.now() + 15 * 60 * 1000

        await user.save();

        const mailOptions = {
            from: process.env.SENDER_EMAIL,
            to: user.email,
            subject: 'PAssword Reset OTP',
            // text: `Your OTP for resetting your password is ${otp}.
            //Use this OTP to proceed with resetting your password.`,
            html: PASSWORD_RESET_TEMPLATE.replace("{{otp}}", otp).replace("{{email}}",
                user.email)

        }
        await transporter.sendMail(mailOptions);

        res.json({ success: true, message: 'OTP sent to your email. ' })
    } catch (error) {
        return res.json({ success: false, message: error.message });
    }
}

//Reset User Password
export const resetPassword = async (req, res) => {
    const { email, otp, newPassword } = req.body;

    if (!email || !otp || !newPassword) {
        return res.json({ success: false, message: 'Email, OTP and new password are required' })
    }

    try {

        const user = await userModel.findOne({ email });
        if (!user) {
            return res.json({ success: false, message: 'User not found' });
        }

        if (user.resetOtp === "" || user.resetOtp !== otp) {
            return res.json({ success: false, message: 'Invalid OTP' });
        }

        if (user.resetOtpExpireAt < Date.now()) {
            return res.json({ success: false, message: 'OTP Expired' });
        }

        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.password = hashedPassword;
        user.resetOtp = '';
        user.resetOtpExpireAt = 0;
        await user.save();

        return res.json({ success: true, message: 'Password has been reset successsfully' });

    } catch (error) {
        return res.json({ success: false, message: error.message });

    }
}