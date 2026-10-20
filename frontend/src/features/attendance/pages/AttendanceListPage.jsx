import {
    useEffect
}
from "react";


import {
    useNavigate
}
from "react-router-dom";


import {
    useDispatch,
    useSelector
}
from "react-redux";


import {
    Add,
    Refresh
}
from "@mui/icons-material";


import {
    Button,
    Stack
}
from "@mui/material";


import {
    getAttendancesThunk
}
from "../store";


import AttendanceTable
from "../components/AttendanceTable";


import {

PageContainer,

PageHeader,

PageCard

}
from "../../../components/ui";







const AttendanceListPage=()=>{


const navigate = useNavigate();


const dispatch = useDispatch();




const {

data=[],

loading

}=useSelector(

state=>state.attendance

);









const loadData=()=>{


dispatch(

getAttendancesThunk({

page:1,

limit:100

})

);


};








useEffect(()=>{


loadData();


},[]);









return (


<PageContainer>







<PageHeader



title="Attendance"



subtitle="Manage activity attendance sessions"





action={()=>navigate("/attendance/create")}



actionLabel="Create Attendance"



actionIcon={<Add/>}


/>









<PageCard>





<Stack sx={{ justifyContent: "flex-end", mb: 2 }}

direction="row"

>


<Button


variant="outlined"


startIcon={<Refresh/>}


onClick={loadData}


disabled={loading}


>


Refresh


</Button>



</Stack>









<AttendanceTable



data={data}



loading={loading}



/>







</PageCard>








</PageContainer>


);



};



export default AttendanceListPage;