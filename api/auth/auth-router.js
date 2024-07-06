const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");

router.post("/register", validateRoleName, async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hash = bcrypt.hashSync(password, 8);
    const newUser = await Users.add({
      username,
      password: hash,
      role_name: req.role_name,
    });
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  const { username, password } = req.body;

  if (bcrypt.compareSync(password, req.user.password)) {
    const token = jwt.sign(
      {
        subject: req.user.user_id,
        username: req.user.username,
        role_name: req.user.role_name,
      },
      JWT_SECRET,
      { expiresIn: "1d" }
    );

    res.json({
      message: `${username} is back!`,
      token,
    });
  } else {
    res.status(401).json({ message: "Invalid credentials" });
  }
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
