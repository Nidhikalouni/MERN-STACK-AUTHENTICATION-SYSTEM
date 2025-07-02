import axios from "axios";
import { createContext, useEffect, useState } from "react";
import { toast } from "react-toastify";

export const AppContext = createContext()

export const AppContextProvider = (props)=>{

    axios.defaults.withCredentials = true;

    const backendURL = import.meta.env.VITE_BACKEND_URL
   
    const [isLoggedin , setIsLoggedin] = useState(false)

    const[userData, setUserData] = useState(false)

    // 1. Authentication Check
const getAuthState = async () => {
  try {
    const { data } = await axios.get(`${backendURL}/api/auth/is-auth`, {
      withCredentials: true
    });
    if (data.success) {
      setIsLoggedin(true);
      getUserData();
    }
  } catch (error) {
    toast.error(error.message);
  }
};

// 2. Get User Data
const getUserData = async () => {
  try {
    const { data } = await axios.get(`${backendURL}/api/user/data`, {
      withCredentials: true
    });
    data.success ? setUserData(data.userData) : toast.error(data.message);
  } catch (error) {
    toast.error(error.message);
  }
};

   
    

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
