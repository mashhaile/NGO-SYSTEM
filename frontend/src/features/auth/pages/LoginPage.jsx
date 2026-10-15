import {
    useState
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    loginThunk
} from "../store";


import {
    selectAuth
} from "../store";


import {
    useNavigate
} from "react-router-dom";


import {
    TextField,
    Button,
    Box,
    Paper,
    Typography,
    Alert
} from "@mui/material";



const LoginPage = ()=>{


const dispatch = useDispatch();

const navigate = useNavigate();


const {
    loading,
    error,
    isAuthenticated
} = useSelector(selectAuth);



const [form,setForm]=useState({

    email:"",
    password:""

});



const handleChange=(e)=>{

setForm({

...form,

[e.target.name]:
e.target.value

});

};



const handleSubmit=(e)=>{

e.preventDefault();


dispatch(
    loginThunk(form)
)
.then((result)=>{

    if(result.meta.requestStatus==="fulfilled"){

        navigate("/");

    }

});


};



return (

<Box

sx={{

height:"100vh",

display:"flex",

justifyContent:"center",

alignItems:"center"

}}

>


<Paper

sx={{

padding:4,

width:400

}}

>


<Typography
variant="h5"
mb={3}
>

NGO SaaS Login

</Typography>



{error &&

<Alert severity="error">

{error}

</Alert>

}



<form onSubmit={handleSubmit}>


<TextField

fullWidth

label="Email"

name="email"

margin="normal"

value={form.email}

onChange={handleChange}

/>



<TextField

fullWidth

label="Password"

name="password"

type="password"

margin="normal"

value={form.password}

onChange={handleChange}

/>



<Button

fullWidth

variant="contained"

type="submit"

disabled={loading}

sx={{mt:2}}

>

{loading ? "Logging in..." : "Login"}

</Button>


</form>


</Paper>


</Box>

);


};


export default LoginPage;