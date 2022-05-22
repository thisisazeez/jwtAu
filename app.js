require("dotenv").config();
require("./config/database").connect();
const express = require("express");
const User = require("./model/user");
const cors = require("cors");
const auth = require("./middleware/auth");
const app = express();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
app.use(cors()); 

app.use(express.json());
// Register
app.post("/register", async (req, res)=>{
    try{
        const{first_name, last_name, email, password} = req.body;

        if(!(email && password && first_name && last_name)){
            res.status(400).send("All Inputs Required!");
        }

        const oldUser = await User.findOne({email});

        if(oldUser){
            return res.status(409).send("User Already Exist. Please Login!");
        }

        encryptedPassword = await bcrypt.hash(password, 10);

        const user = await User.create({
            first_name,
            last_name,
            email:email.toLowerCase(),
            password:encryptedPassword,
        });

        const token = jwt.sign(
            {user_id:user._id, email},
            process.env.TOKEN_KEY,
            {
                expiresIn:"2h",
            }
        );

        user.token = token;

        res.status(201).json(user);
    }catch(err){
        console.log(err);
    }
});
// Login
app.post("/login", async (req, res) => {

    // Our login logic starts here
    try {
      // Get user input
      const { email, password } = req.body;
  
      // Validate user input
      if (!(email && password)) {
        res.status(400).send("All input is required");
      }
      // Validate if user exist in our database
      const user = await User.findOne({ email });
  
      if (user && (await bcrypt.compare(password, user.password))) {
        // Create token
        const token = jwt.sign(
          { user_id: user._id, email },
          process.env.TOKEN_KEY,
          {
            expiresIn: "2h",
          }
        );
  
        // save user token
        user.token = token;
  
        // user
        res.status(200).json(user);
      }
      res.status(400).send("Invalid Credentials");
    } catch (err) {
      console.log(err);
    }
    // Our register logic ends here
  });

// welcome 

app.post("/welcome", auth, (req, res) => {
  res.status(200).send("Welcome 🙌 ");
});
module.exports = app;
