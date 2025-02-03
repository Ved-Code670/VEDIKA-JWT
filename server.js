require("dotenv").config();
const express=require("express");
const jwt =require("jsonwebtoken");
const bcrypt =require("bcrypt");
const bodyParser =require("body-parser");
const cors=require("cors");

const app=express();
app.use(express.json());

app.use(bodyParser.json());
app.use(cors());

const users=[];
//REGISTER
app.post("/register",async(req,res)=>{
    const{username,password}=req.body;

    if(!username||!password){
        return res.status(400).json({messsage:"username and password are required"})
    }
    try{
        const hashedPassword=await bcrypt.hash(password,10);
        users.push({username,password:hashedPassword});

        res.json({message:"user registered successfully!!"});
    }
    catch(error){
        res.status(500).json({message:'Error hashing password',error});
    }
});
//LOGIN USER(GENERATE JWT)
app.post("/login",async(req,res)=>{
    const {username,password}=req.body;
    const user=users.find(u=>u.username===username);
    if(!user)return res.status(400).json({message:"usernot found"});

    const isValid=await bcrypt.compare(password,user.password);
    if(!isValid) return res.status(401).json({message:"invalid password"});

    const token=jwt.sign({username},process.env.JWT_SECRET,{expiresIn:"1h"})
        res.json({token});
    
});


//auth  MIDDLEWARE(PROTECTED ROUTES)
function authenticateToken(req,res,next){
    const token=req.header("Authorization")?.split(" ")[1];
    if (!token)return res.status(403).json({message:"Access denied"});

    jwt.verify(token,process.env.JWT_SECRET,(err,user)=>{
        if(err) return res.status(403).json({message:"invlaid token"});
    req.user=user;
    next();
    });
}

//protected route
app.get("/protected",authenticateToken,(req,res)=>{
    res.json({message:"welcome to the protected route",user:req.user});
});

const PORT=process.env.PORT||5000;
app.listen(PORT,()=>console.log('server running on port ${PORT}'));