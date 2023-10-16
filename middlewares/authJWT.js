const jwt = require("jsonwebtoken");
const User = require("../models/user");

const verifyToken = async (req, res, next) => {
  try {
    if (req.headers && req.headers.authorization && req.headers.authorization.split(' ')[0] === 'JWT') {
      const token = req.headers.authorization.split(' ')[1];
      const decoded = jwt.verify(token, process.env.API_SECRET);

      const user = await User.findOne({ _id: decoded.id }).exec();

      if (!user) {
        return res.status(404).send({ message: "User Not found." });
      }

      req.user = user;
      next();
    } else {
      req.user = undefined;
      next();
    }
  } catch (error) {
    res.status(500).send({ message: error.message });
  }
};

module.exports = verifyToken;
