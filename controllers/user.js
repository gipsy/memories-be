import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';

import User from '../models/user.js';

export const signin = async (req, res) => {
  const { email, password, googleCode } = req.body;

  const oAuth2Client = new OAuth2Client(
    process.env.GOOGLE_CLIENT_ID,
    process.env.GOOGLE_CLIENT_SECRET,
    'postmessage',
  );

  try {
    if (!!googleCode) {
      const { tokens: { refresh_token, id_token, expiry_date } } = await oAuth2Client.getToken(googleCode); // exchange
      // code for tokens

      const userInfo = jwt.decode(id_token);

      res.status(200).json({ userInfo, token: id_token });
    } else {
      const existingUser = await User.findOne({ email });

      if (!existingUser) return res.status(404).json({ message: "User doesn't exist." });

      const isPasswordCorrect = await bcrypt.compare(password, existingUser.password);

      if (!isPasswordCorrect) return res.status(400).json({ message: "Invalid credentials." });

      const token = jwt.sign({ email: existingUser.email, id: existingUser._id }, 'test', { expiresIn: "1h" });

      res.status(200).json({ userInfo: existingUser, token });
    }
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong.' });
  }
}

export const signup = async (req, res) => {
  const { email, password, confirmPassword, firstName, lastName } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) return res.status(400).json({ message: "User already exists." });

    if (password !== confirmPassword) return res.status(400).json({ message: "Passwords don't match." });

    const hashedPassword = await bcrypt.hash(password, 12);

    const userInfo = await User.create({ email, password: hashedPassword, name: `${firstName} ${lastName}` });

    const token = jwt.sign({ email: userInfo.email, id: userInfo._id }, 'test', { expiresIn: "1h" });

    res.status(200).json({ userInfo, token });
  } catch (error) {
    res.status(500).json({ message: 'Something went wrong.' });
  }
}
