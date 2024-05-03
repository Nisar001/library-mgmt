import User from '../models/UserModel.js'
import { comparePassword, hashPassword} from './../helpers/AuthHelper.js';
import JWT from 'jsonwebtoken';

export const registerController = async(req, res) => {
   try {
      const {name, email, password, phone, address, answer} = req.body;
      //validaions
      if(!name){
         return res.send({message: 'Name is Required'})
      }
      if(!email){
         return res.send({message: 'Email is Required'})
      }
      if(!password){
         return res.send({message: 'Password is Required'})
      }
      if(!phone){
         return res.send({message: 'Phone is Required'})
      }
      if(!address){
         return res.send({message: 'Address is Required'})
      }
      if(!answer){
         return res.send({message: 'Answer is Required'})
      }

      //Check User
      const existingUser = await UserModel.findOne({email})
      //Existing User
      if(existingUser){
         return res.status(200).send({
            success: false,
            message: "Already Register Please Login"
         })
      }
      //register user
      const hashedPassword = await hashPassword(password);
      // save
      const user = await new UserModel({
         name, 
         email, 
         phone, 
         address, 
         password:hashedPassword,
         answer,
      }).save();

      res.status(201).send({
         success:true,
         message:"User Register Successfully",
         user
      })
   } catch (error) {
      console.log(error);
      res.status(500).send({
         success:false,
         message:'Error in Registration',
         error
      })
   }
};

// LOGIN POST

export const loginController = async(req, res) => {
   try {
      const {email, password} = req.body;
      // Validation
      if(!email || !password ){
         return res.status(404).send({
            success:false,
            message:'Invalid email or Password'
         })
      }
      // Check USer
      const user = await UserModel.findOne({email});
      if(!user){
         return res.status(404).send({
            success:false,
            message:"Email is nor Register"
         })
      }
      const match = await comparePassword(password, user.password)
      if(!match){
         return res.status(200).send({
            success:false,
            message:'Invalid Password'
         })
      }

      // Token

      const token = await JWT.sign({_id:user._id}, process.env.JWT_SECRET, {
         expiresIn: "2d",
      });
      res.status(200).send({
         success:true,
         message: "Login Successfully",
         user:{
            name: user.name,
            email: user.email,
            phone: user.phone,
            address: user.address,
            role: user.role,
         },
         token,
      })

   } catch (error) {
      console.log(error);
      res.status(500).send({
         success:false,
         message:'Error in Login',
         error
      })
   }
};

export const forgotPasswordController = async(req, res) => {
   try {
      const {email, answer, newPassword} = req.body;
      if(!email){
         res.status(400).send({message: "Email is required"})
      }
      if(!answer){
         res.status(400).send({message: "Answer is required"})
      }
      if(!newPassword){
         res.status(400).send({message: "New Password is required"})
      }
      // Check
      const user = await UserModel.findOne({email, answer});
      // validation
      if(!user){
         return res.status(404).send({
            success: false,
            message: 'Wrong Email or Answer'
         })
      }
      const hashed = await hashPassword(newPassword)
      await UserModel.findByIdAndUpdate(user._id, {password: hashed})
      res.status(200).send({
         success:true,
         message:"Password Reset Successfully",
      });
   } catch (error) {
      console.log(error)
      res.status(500).send({
         success: false,
         message: "Something went Worong",
         error
      })
   }
};

// test controller
export const testController = (req, res) => {
   res.send("Protected Route");
}