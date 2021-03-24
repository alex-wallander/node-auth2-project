const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const jwt = require("jsonwebtoken");
const bcryptjs = require("bcryptjs");
const  {jwtSecret}  = require("../secrets/index"); 
const Users = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  const credentials = req.body;

  if (credentials) {
    const rounds = process.env.BCRYPT_ROUNDS || 8;

    const hash = bcryptjs.hashSync(credentials.password, rounds);

    credentials.password = hash;
    console.log(credentials)
    
    Users.add(credentials)
      .then((user) => {
        res.status(201).json(user);
      })
      .catch((error) => {
        res.status(500).json({ message: error.message });
      });
  } else {
    res.status(400).json({
      message:
        "please provide username and password ",
    });
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

router.post("/login", checkUsernameExists, async (req, res, next) => {
  const { username, password } = req.body; 
  try {
    if (req.body) {
    const [newUser] = await Users.findBy({ username: username })
      // console.log(newUser[0])
      if(newUser && bcryptjs.compareSync(password, newUser.password)) {
        const token = buildToken(newUser)
        res.status(200).json({ message: `${username} is back!`, token });
      } else {
        res.status(401).json({ message: "invalid credentials" });
        }
      }
    } catch (err){
        next(err);
  }

});
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
function buildToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  const config = {
    expiresIn: "1d",
  };
  return jwt.sign(payload, jwtSecret, config);
}

module.exports = router;
