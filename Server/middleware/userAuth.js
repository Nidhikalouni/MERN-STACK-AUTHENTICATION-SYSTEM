import jwt from 'jsonwebtoken'

const userAuth = async(req,res,next) =>{
    const {token} = req.cookies;
    if(!token){
    return res.json({success : false, message : 'Not Authorized. Login Again'})
}

try {

    //to decode the token
    const tokenDecode = jwt.verify(token,process.env.JWT_SECRET);

    if(tokenDecode.id){
        req.body = req.body || {}; //  // Ensures req.body is not undefined (If req.body is already defined, keep it as it is.But if it's undefined, assign it an empty object {}.”)
        req.body.userId = tokenDecode.id  //// Store userId for controller use
    }else{
        return res.json({success:false , message: 'Not Authorized. Login Again'})
    }

    next();
    
} catch (error) {
    res.json({success:false , message :error.message});
}

}


export default  userAuth;