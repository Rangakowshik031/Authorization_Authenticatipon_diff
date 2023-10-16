const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const User = require("../models/user");

exports.signup = async (req, res) => {
  try {
    const { fullName, email, role, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 8);

    const user = new User({
      fullName,
      email,
      role,
      password: hashedPassword
    });

    await user.save();
    res.status(200).send({ message: "User Registered successfully" });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
};

exports.signin = async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email }).exec();

    if (!user) {
      return res.status(404).send({ message: "User Not found." });
    }

    const passwordIsValid = await bcrypt.compare(password, user.password);

    if (!passwordIsValid) {
      return res.status(401).send({
        accessToken: null,
        message: "Invalid Password!"
      });
    }

    const token = jwt.sign({ id: user.id }, process.env.API_SECRET, {
      expiresIn: 86400
    });

    res.status(200).send({
      user: {
        id: user._id,
        email: user.email,
        fullName: user.fullName
      },
      message: "Login successful",
      accessToken: token
    });
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
};
