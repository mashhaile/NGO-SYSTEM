import {
    useNavigate
} from "react-router-dom";


import {
    useState
} from "react";


import {
    useDispatch,
    useSelector
} from "react-redux";


import {
    ArrowBack
} from "@mui/icons-material";


import {
    Snackbar,
    Alert
} from "@mui/material";


import EnrollmentForm
from "../components/EnrollmentForm";


import {
    createEnrollmentThunk
} from "../store";



import {

    PageContainer,

    PageHeader,

    PageCard

} from "../../../components/ui";








const EnrollmentCreatePage = ()=>{


    const navigate = useNavigate();


    const dispatch = useDispatch();




    const {

        loading

    } = useSelector(

        state=>state.enrollments

    );





    const [open,setOpen] = useState(false);

    const [message,setMessage] = useState("");

    const [severity,setSeverity] = useState("success");








    const handleSubmit = async(data)=>{


        try{


            await dispatch(

                createEnrollmentThunk(data)

            ).unwrap();





            setSeverity("success");


            setMessage(

                "Enrollment created successfully"

            );


            setOpen(true);





            setTimeout(()=>{


                navigate("/enrollments");


            },1000);



        }


        catch(error){



            console.error(

                "Create enrollment error:",

                error

            );




            setSeverity("error");



            setMessage(

    error ||

    "Failed to create enrollment"

);



            setOpen(true);



        }



    };











    return (


        <PageContainer>





            <PageHeader


                title="Create Enrollment"


                subtitle="Enroll a beneficiary into a program"


                action={()=>navigate("/enrollments")}


                actionLabel="Back"


                actionIcon={<ArrowBack/>}


            />









            <PageCard>




                <EnrollmentForm


                    onSubmit={handleSubmit}


                    loading={loading}


                />




            </PageCard>









            <Snackbar


                open={open}


                autoHideDuration={4000}


                onClose={()=>setOpen(false)}


                anchorOrigin={{


                    vertical:"top",


                    horizontal:"right"


                }}


            >



                <Alert


                    severity={severity}


                    variant="filled"


                    onClose={()=>setOpen(false)}


                >


                    {message}


                </Alert>



            </Snackbar>







        </PageContainer>


    );


};






export default EnrollmentCreatePage;