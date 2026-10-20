import {
    useEffect
} from "react";


import {

    Box,

    Button,

    Stack,

    Typography

} from "@mui/material";


import {
    Add
} from "@mui/icons-material";


import {
    useNavigate
} from "react-router-dom";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {

    getEnrollmentsThunk

} from "../store";


import EnrollmentTable
from "../components/EnrollmentTable";







const EnrollmentListPage = ()=>{


const navigate = useNavigate();


const dispatch = useDispatch();





const {

    data=[],

    loading

}

=

useSelector(

    state=>state.enrollments

);









useEffect(()=>{


dispatch(

    getEnrollmentsThunk({

        page:1,

        limit:10

    })

);



},[dispatch]);









return (


<Box>






<Stack sx={{ justifyContent: "space-between", alignItems: "center", mb: 3 }}

direction="row"

>






<Box>


<Typography

variant="h4"

fontWeight="700"

>

Enrollments

</Typography>





<Typography

color="text.secondary"

>

Manage beneficiary program enrollments

</Typography>



</Box>









<Button

variant="contained"

startIcon={<Add/>}

onClick={()=>navigate(

    "/enrollments/create"

)}

>

Create Enrollment

</Button>







</Stack>









<EnrollmentTable


data={data}


loading={loading}


/>









</Box>


);


};




export default EnrollmentListPage;