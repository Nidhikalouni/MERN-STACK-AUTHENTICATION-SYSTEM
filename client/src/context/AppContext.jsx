import axios from "axios";
import { createContext, useEffect, useState } from "react";
import { toast } from "react-toastify";

export const AppContext = createContext()

export const AppContextProvider = (props)=>{

    axios.defaults.withCredentials = true;

    const backendURL = import.meta.env.VITE_BACKEND_URL
   
    const [isLoggedin , setIsLoggedin] = useState(false)

    const[userData, setUserData] = useState(false)

    //getting authentication state (is user authenticated or not)
    const getAuthState = async()=>{
        try{
            const {data} = await axios.get(backendURL + '/api/auth/is-auth')
            if(data.success){
                setIsLoggedin(true)
                getUserData()
            }
        }catch(error){
              toast.error(error.message)
        }
    }


    //getting userdata
    const getUserData = async()=>{
        try {
          const {data} = await axios.get(backendURL + '/api/user/data')
          data.success ? setUserData(data.userData) : toast.error(data.message)  
        
        } catch (error) {
            toast.error(error.message)
        }
    }

    useEffect(()=>{
        getAuthState();
    },[])

    const value = {
        backendURL,
        isLoggedin, setIsLoggedin,
        userData , setUserData,
        getUserData,



    }

    return(
        <AppContext.Provider value={value}>
            {props.children}
        </AppContext.Provider>
    )
}