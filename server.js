import express from "express";
import session from "express-session";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import fs from "fs";
import path from "path";
import {fileURLToPath} from "url";

const __dirname=path.dirname(fileURLToPath(import.meta.url));
const app=express(), PORT=process.env.PORT||3000, DB=path.join(__dirname,"data.json");
const adminEmail=process.env.ADMIN_EMAIL||"admin@famutech.com";
const adminHash=process.env.ADMIN_PASSWORD_HASH||bcrypt.hashSync("ChangeMe123!",12);
const read=()=>JSON.parse(fs.readFileSync(DB,"utf8"));
const write=d=>fs.writeFileSync(DB,JSON.stringify(d,null,2));

app.disable("x-powered-by");
app.use(express.json({limit:"1mb"}));
app.use(express.urlencoded({extended:true}));
app.use((req,res,next)=>{
  res.setHeader("X-Content-Type-Options","nosniff");
  res.setHeader("X-Frame-Options","DENY");
  res.setHeader("Referrer-Policy","strict-origin-when-cross-origin");
  next();
});
app.use(session({
 secret:process.env.SESSION_SECRET||"CHANGE_THIS_SECRET_BEFORE_DEPLOYING",
 resave:false,saveUninitialized:false,
 cookie:{httpOnly:true,sameSite:"lax",secure:process.env.NODE_ENV==="production",maxAge:14400000}
}));
app.use(express.static(path.join(__dirname,"public")));

const limiter=rateLimit({windowMs:15*60*1000,limit:10,message:{error:"Too many login attempts. Try again later."}});
const auth=(req,res,next)=>req.session.admin?next():res.status(401).json({error:"Unauthorized"});

app.get("/api/site",(req,res)=>res.json(read()));

app.post("/api/quote",(req,res)=>{
 const q=req.body;
 if(!q.name||!q.phone||!q.service)return res.status(400).json({error:"Name, phone and service are required."});
 const d=read();
 const item={id:Date.now(),name:String(q.name).slice(0,120),phone:String(q.phone).slice(0,40),
 location:String(q.location||"").slice(0,120),service:String(q.service).slice(0,120),
 size:String(q.size||"").slice(0,60),budget:String(q.budget||"").slice(0,60),
 requirements:String(q.requirements||"").slice(0,1000),status:"New",createdAt:new Date().toISOString()};
 d.quotes.unshift(item);write(d);
 const msg=`FAMUTECH Quote Request\nName: ${item.name}\nPhone: ${item.phone}\nLocation: ${item.location}\nService: ${item.service}\nSystem: ${item.size}\nBudget: ${item.budget}\nRequirements: ${item.requirements}`;
 res.json({ok:true,whatsapp:`https://wa.me/${d.settings.whatsapp}?text=${encodeURIComponent(msg)}`});
});

app.post("/api/login",limiter,(req,res)=>{
 const {email,password}=req.body;
 if(email!==adminEmail||typeof password!=="string"||!bcrypt.compareSync(password,adminHash))
   return res.status(401).json({error:"Invalid login details"});
 req.session.regenerate(err=>{
   if(err)return res.status(500).json({error:"Login failed"});
   req.session.admin={email:adminEmail};res.json({ok:true});
 });
});
app.post("/api/logout",(req,res)=>req.session.destroy(()=>res.json({ok:true})));
app.get("/api/me",(req,res)=>res.json({authenticated:!!req.session.admin}));
app.get("/api/admin/data",auth,(req,res)=>res.json(read()));
app.put("/api/admin/data",auth,(req,res)=>{
 const d=req.body;
 if(!d?.settings||!Array.isArray(d.packages)||!Array.isArray(d.services))return res.status(400).json({error:"Invalid data"});
 write(d);res.json({ok:true});
});
app.get("/admin",(req,res)=>res.sendFile(path.join(__dirname,"public","admin.html")));
app.listen(PORT,()=>console.log(`FAMUTECH V2: http://localhost:${PORT}`));