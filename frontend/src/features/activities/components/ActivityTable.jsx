import {
    DataGrid
}
from "@mui/x-data-grid";


import {

    Box,

    IconButton,

    Chip,

    Tooltip,

    Stack,

    Typography

}
from "@mui/material";


import {

    Visibility,

    Edit,

    Delete

}
from "@mui/icons-material";


import {
    useNavigate
}
from "react-router-dom";


import {
    useDispatch
}
from "react-redux";


import {
    deleteActivityThunk
}
from "../store";





const statusConfig={


    Planned:{
        label:"Planned",
        color:"warning"
    },


    Ongoing:{
        label:"Ongoing",
        color:"info"
    },


    Completed:{
        label:"Completed",
        color:"success"
    },


    Cancelled:{
        label:"Cancelled",
        color:"error"
    }


};









const ActivityTable=({

    data=[],

    loading=false

})=>{


const navigate=useNavigate();


const dispatch=useDispatch();







const handleDelete=(id)=>{


const confirmDelete = window.confirm(

"Are you sure you want to delete this activity?"

);



if(confirmDelete){


dispatch(

deleteActivityThunk(id)

);


}



};










const columns=[



{

field:"activityCode",

headerName:"Code",

width:150,


renderCell:(params)=>(

<Typography

fontWeight="700"

>

{params.value}

</Typography>

)


},







{

field:"name",

headerName:"Activity",

flex:1.5,

minWidth:220,


renderCell:(params)=>(


<Typography>

{params.value}

</Typography>


)


},







{
    field: "project",

    headerName: "Project",

    flex: 1.5,

    minWidth: 230,

    sortable: false,

    renderCell: (params) => {

        const project = params.row.project;

        if (!project) {

            return "-";

        }

        return (

            <Box>

                <Typography
                    fontWeight="700"
                    fontSize="0.9rem"
                >
                    {project.projectCode}
                </Typography>

                <Typography
                    variant="body2"
                    color="text.secondary"
                >
                    {project.name}
                </Typography>

            </Box>

        );

    }

},


{

field:"activityType",

headerName:"Type",

width:170,


renderCell:(params)=>(


<Chip

label={params.value || "-"}

size="small"

/>


)


},







{

field:"participantSource",

headerName:"Participants",

width:190,


renderCell:(params)=>(


<Typography

variant="body2"

>

{params.value || "-"}

</Typography>


)


},







{

field:"targetGroups",

headerName:"Target Groups",

flex:1,

minWidth:220,


renderCell:(params)=>{


const groups=params.value || [];



if(!groups.length)

return "-";



return (

<Stack

direction="row"

spacing={0.5}

flexWrap="wrap"

>


{

groups.slice(0,3).map((item)=>(


<Chip

key={item}

label={item}

size="small"

/>


))

}



{

groups.length > 3 &&

<Chip

label={`+${groups.length-3}`}

size="small"

/>

}



</Stack>

);


}


},







{

field:"activityDate",

headerName:"Date",

width:140,


renderCell:(params)=>(


params.value

?

new Date(params.value)

.toLocaleDateString()

:

"-"


)


},







{

field:"targetParticipants",

headerName:"Target",

width:110


},







{

field:"status",

headerName:"Status",

width:130,


renderCell:(params)=>{


const config =

statusConfig[params.value]

||

{

label:"Unknown",

color:"default"

};



return (

<Chip

label={config.label}

color={config.color}

size="small"

/>

);


}


},







{

field:"actions",

headerName:"Actions",

width:160,


sortable:false,

filterable:false,


renderCell:(params)=>(


<Stack

direction="row"

spacing={0.5}

>





<Tooltip title="View">


<IconButton

color="primary"

onClick={()=>navigate(

`/activities/${params.row._id}`

)}

>

<Visibility/>

</IconButton>


</Tooltip>








<Tooltip title="Edit">


<IconButton

color="secondary"

onClick={()=>navigate(

`/activities/${params.row._id}/edit`

)}

>

<Edit/>

</IconButton>


</Tooltip>








<Tooltip title="Delete">


<IconButton

color="error"

onClick={()=>handleDelete(

params.row._id

)}

>

<Delete/>

</IconButton>


</Tooltip>





</Stack>


)


}



];









return(


<Box


sx={{


height:650,


background:"#fff",


borderRadius:3,


overflow:"hidden"


}}



>



<DataGrid



rows={data}



columns={columns}



loading={loading}



getRowId={(row)=>row._id}



disableRowSelectionOnClick



pageSizeOptions={[10,25,50]}



initialState={{


pagination:{


paginationModel:{


pageSize:10


}


}


}}



sx={{


border:0,



"& .MuiDataGrid-columnHeaders":{

background:"#f7f8fa",

fontWeight:700

},



"& .MuiDataGrid-cell":{

display:"flex",

alignItems:"center"

}



}}



/>



</Box>


);


};



export default ActivityTable;