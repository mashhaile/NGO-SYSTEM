import {
    useEffect
} from "react";


import {
    useNavigate,
    useParams
} from "react-router-dom";


import {
    useDispatch,
    useSelector
} from "react-redux";



import {

    Box,

    Card,

    CardContent,

    Typography,

    Stack,

    Button,

    Divider

} from "@mui/material";



import {
    ArrowBack
} from "@mui/icons-material";



import {
    getEnrollmentByIdThunk
} from "../store";









const EnrollmentDetailsPage = ()=>{


const {

    id

}=useParams();



const navigate = useNavigate();


const dispatch = useDispatch();









const {

    current,

    loading

}

=

useSelector(

    state=>state.enrollments

);









useEffect(()=>{


dispatch(

    getEnrollmentByIdThunk(id)

);



},[dispatch,id]);









if(loading || !current){


return (

<Typography>

Loading...

</Typography>

);


}









return (
    <Box>

        <Stack sx={{ justifyContent: "space-between", alignItems: "center", mb: 3 }}

        direction="row"

        >



        <Typography

        variant="h4"

        sx={{
            fontWeight: "700"
        }}

        >

        Enrollment Details

        </Typography>






        <Button

        variant="outlined"

        startIcon={<ArrowBack/>}

        onClick={()=>navigate("/enrollments")}

        >

        Back

        </Button>






        </Stack>

        <Card>



        <CardContent>



        <Typography
            variant="h6"
            sx={{
                fontWeight: "700",
                mb: 2
            }}>

        Beneficiary Information

        </Typography>





        <Typography>

        Name:

        {" "}

        {

        current.beneficiary?.firstName

        }

        {" "}

        {

        current.beneficiary?.lastName

        }

        </Typography>





        <Typography>

        Beneficiary Number:

        {" "}

        {

        current.beneficiary?.beneficiaryNumber

        }

        </Typography>







        <Divider sx={{my:3}}/>









        <Typography
            variant="h6"
            sx={{
                fontWeight: "700",
                mb: 2
            }}>

        Program Information

        </Typography>







        <Typography>

        Program:

        {" "}

        {

        current.program?.name

        }

        </Typography>





        <Typography>

        Program Code:

        {" "}

        {

        current.program?.programCode

        }

        </Typography>







        <Divider sx={{my:3}}/>








        <Typography
            variant="h6"
            sx={{
                fontWeight: "700",
                mb: 2
            }}>

        Enrollment Information

        </Typography>







        <Typography>

        Status:

        {" "}

        {

        current.status

        }

        </Typography>






        <Typography>

        Enrollment Date:

        {" "}

        {

        current.enrollmentDate

        ?

        new Date(

        current.enrollmentDate

        ).toLocaleDateString()

        :

        "-"

        }

        </Typography>







        <Typography>

        Completion Date:

        {" "}

        {

        current.completionDate

        ?

        new Date(

        current.completionDate

        ).toLocaleDateString()

        :

        "-"

        }

        </Typography>







        <Typography>

        Remarks:

        {" "}

        {

        current.remarks || "-"

        }

        </Typography>







        </CardContent>



        </Card>

    </Box>
);



};






export default EnrollmentDetailsPage;