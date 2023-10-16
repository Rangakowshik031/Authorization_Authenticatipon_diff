require("dotenv").config();
const express = require("express"),
  app = express(),
  mongoose = require("mongoose"),
  userRoutes = require("./routes/user");
try {
  mongoose.connect("mongodb://localhost:27017/usersdb", {
    useUnifiedTopology: true,
    useNewUrlParser: true
  });
  console.log("connected to db");
} catch (error) {
  handleError(error);
}
process.on('unhandledRejection', error => {
  console.log('unhandledRejection', error.message);
});
app.use(express.json());
app.use(express.urlencoded({
  extended: true
}));
app.use(userRoutes);
app.listen(process.env.PORT || 3000, () => {
  console.log("Server is live on port 3000");
})