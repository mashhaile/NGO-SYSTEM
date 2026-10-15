import {
    useEffect,
    useState
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

    Box,

    Button,

    Stack,

    TextField,

    Typography

}
from "@mui/material";


import {
    Add
}
from "@mui/icons-material";


import ActivityTable
from "../components/ActivityTable";


import {
    getActivitiesThunk
}
from "../store";







const ActivityListPage=()=>{



const navigate=useNavigate();


const dispatch=useDispatch();




const {

    data=[],

    loading,

    pagination

}

=
useSelector(

state=>state.activities

);






const [search,setSearch]=useState("");






useEffect(()=>{


dispatch(

getActivitiesThunk({

page:1,

limit:10,

search

})

);



},[dispatch,search]);









return(



<Box>





<Stack


direction="row"


justifyContent="space-between"


alignItems="center"


mb={3}


>



<Box>


<Typography


variant="h4"


fontWeight="700"


>


Activities


</Typography>



<Typography


color="text.secondary"


>


Manage program activities


</Typography>


</Box>









<Button


variant="contained"


startIcon={<Add/>}


onClick={()=>navigate("/activities/create")}


>


Create Activity


</Button>





</Stack>









<Stack


direction={{xs:"column",md:"row"}}


spacing={2}


mb={3}


>



<TextField


label="Search activities"


fullWidth


value={search}


onChange={(e)=>

setSearch(e.target.value)

}


/>



</Stack>









<ActivityTable


data={data}


loading={loading}


/>





</Box>



);



};



export default ActivityListPage;