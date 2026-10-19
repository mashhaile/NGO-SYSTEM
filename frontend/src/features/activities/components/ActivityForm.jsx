import {
    useCallback,
    useEffect,
    useState
} from "react";


import {
    Box,
    Grid,
    TextField,
    MenuItem,
    Button,
    Stack,
    Autocomplete
} from "@mui/material";


import {
    Save
} from "@mui/icons-material";



import {
    getProjectLookupService
}
from "../../projects/services/projectService";


import LocationCascadeFields
from "../../locations/components/LocationCascadeFields";



const ACTIVITY_TYPES = [

    "Training",
    "Workshop",
    "Seminar",
    "Meeting",
    "Conference",
    "Awareness Campaign",
    "Field Visit",
    "Monitoring Visit",
    "Assessment",
    "Distribution",
    "Community Dialogue",
    "Other"

];





const PARTICIPANT_SOURCES = [

    "Enrolled Beneficiaries",
    "Staff",
    "Board Members",
    "Volunteers",
    "Partners",
    "External Participants",
    "Mixed"

];





const TARGET_GROUPS = [

    "Women",
    "Men",
    "Youth",
    "Children",
    "Persons with Disabilities",
    "Farmers",
    "Entrepreneurs",
    "Students",
    "Teachers",
    "Health Workers",
    "Community Leaders",
    "Staff",
    "Board Members",
    "Partners",
    "Government Officials",
    "General Public"

];







const initialState = {


    project:null,

    name:"",

    activityType:"Training",

    participantSource:"Enrolled Beneficiaries",

    targetGroups:[],

    description:"",

    activityDate:"",

    region:"",
    regionCode:"",
    zone:"",
    zoneCode:"",
    woreda:"",
    woredaCode:"",

    location:"",

    facilitator:"",

    targetParticipants:0,

    status:"Planned",

    remarks:""


};








const ActivityForm = ({

    initialData={},

    onSubmit,

    loading=false

})=>{





const [formData,setFormData] = useState(initialState);


const [projects,setProjects] = useState([]);







useEffect(()=>{

    loadProjects();

},[]);










useEffect(()=>{


if(initialData && Object.keys(initialData).length){


setFormData({


    project:
        initialData.project || null,


    name:
        initialData.name || "",


    activityType:
        initialData.activityType || "Training",


    participantSource:
        initialData.participantSource ||
        "Enrolled Beneficiaries",


    targetGroups:
        initialData.targetGroups || [],


    description:
        initialData.description || "",


    activityDate:

        initialData.activityDate

        ?

        initialData.activityDate.substring(0,10)

        :

        "",


    region:
        initialData.region || "",

    regionCode:
        initialData.regionCode || "",

    zone:
        initialData.zone || "",

    zoneCode:
        initialData.zoneCode || "",

    woreda:
        initialData.woreda || "",

    woredaCode:
        initialData.woredaCode || "",


    location:
        initialData.location || "",


    facilitator:
        initialData.facilitator || "",


    targetParticipants:
        initialData.targetParticipants ?? 0,


    status:
        initialData.status || "Planned",


    remarks:
        initialData.remarks || ""

});


}


},[initialData]);









const loadProjects = async()=>{


try{


const response = await getProjectLookupService();


setProjects(

    response.data.data || []

);


}

catch(error){

console.error(

    "PROJECT LOOKUP ERROR",

    error

);

}


};












const handleChange=(field,value)=>{


setFormData({

    ...formData,

    [field]:value

});


};



// location cascade: several fields at once

const changeFields=useCallback((patch)=>{

setFormData(prev=>({

    ...prev,

    ...patch

}));

},[]);









const handleSubmit=(e)=>{


e.preventDefault();



onSubmit({


    project:

        formData.project?._id || null,


    name:
        formData.name,


    activityType:
        formData.activityType,


    participantSource:
        formData.participantSource,


    targetGroups:
        formData.targetGroups,


    description:
        formData.description,


    activityDate:
        formData.activityDate,


    region:
        formData.region,

    regionCode:
        formData.regionCode,

    zone:
        formData.zone,

    zoneCode:
        formData.zoneCode,

    woreda:
        formData.woreda,

    woredaCode:
        formData.woredaCode,


    location:
        formData.location,


    facilitator:
        formData.facilitator,


    targetParticipants:
        Number(formData.targetParticipants),


    status:
        formData.status,


    remarks:
        formData.remarks


});


};









return (

<Box

component="form"

onSubmit={handleSubmit}

>


<Grid

container

spacing={3}

>






<Grid size={12}>


<Autocomplete



options={projects}



value={

projects.find(

(item)=>

item._id === formData.project?._id

)

||

null

}



getOptionLabel={(option)=>

option

?

`${option.projectCode} - ${option.name}`

:

""

}



isOptionEqualToValue={(a,b)=>

a._id===b._id

}



onChange={(e,value)=>

handleChange(

"project",

value

)

}



renderInput={(params)=>(

<TextField

{...params}

label="Project"

required

/>

)}


/>


</Grid>









<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

label="Activity Name"

required

value={formData.name}

onChange={(e)=>

handleChange(

"name",

e.target.value

)

}

/>


</Grid>









<Grid size={{xs:12,md:6}}>


<TextField

select

fullWidth

label="Activity Type"

value={formData.activityType}

onChange={(e)=>

handleChange(

"activityType",

e.target.value

)

}

>


{

ACTIVITY_TYPES.map(item=>(

<MenuItem

key={item}

value={item}

>

{item}

</MenuItem>

))

}


</TextField>


</Grid>









<Grid size={{xs:12,md:6}}>


<TextField

select

fullWidth

label="Participant Source"

value={formData.participantSource}

onChange={(e)=>

handleChange(

"participantSource",

e.target.value

)

}

>


{

PARTICIPANT_SOURCES.map(item=>(

<MenuItem

key={item}

value={item}

>

{item}

</MenuItem>

))

}


</TextField>


</Grid>









<Grid size={{xs:12}}>


<Autocomplete


multiple


options={TARGET_GROUPS}


value={formData.targetGroups}


onChange={(e,value)=>

handleChange(

"targetGroups",

value

)

}


renderInput={(params)=>(

<TextField

{...params}

label="Target Groups"

/>

)}


/>


</Grid>









<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

type="date"

label="Activity Date"

InputLabelProps={{

shrink:true

}}

value={formData.activityDate}

onChange={(e)=>

handleChange(

"activityDate",

e.target.value

)

}

/>


</Grid>









<LocationCascadeFields

value={formData}

onChange={changeFields}

size="medium"

renderItem={(field,key)=>(

<Grid key={key} size={{xs:12,md:6}}>

{field}

</Grid>

)}

/>



<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

label="Venue / Site"

value={formData.location}

onChange={(e)=>

handleChange(

"location",

e.target.value

)

}

/>


</Grid>









<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

label="Facilitator"

value={formData.facilitator}

onChange={(e)=>

handleChange(

"facilitator",

e.target.value

)

}

/>


</Grid>









<Grid size={{xs:12,md:6}}>


<TextField

fullWidth

type="number"

label="Target Participants"

inputProps={{

min:0

}}

value={formData.targetParticipants}

onChange={(e)=>

handleChange(

"targetParticipants",

e.target.value

)

}

/>


</Grid>









<Grid size={{xs:12,md:6}}>


<TextField

select

fullWidth

label="Status"

value={formData.status}

onChange={(e)=>

handleChange(

"status",

e.target.value

)

}

>


<MenuItem value="Planned">

Planned

</MenuItem>


<MenuItem value="Ongoing">

Ongoing

</MenuItem>


<MenuItem value="Completed">

Completed

</MenuItem>


<MenuItem value="Cancelled">

Cancelled

</MenuItem>


</TextField>


</Grid>









<Grid size={12}>


<TextField

fullWidth

multiline

rows={3}

label="Description"

value={formData.description}

onChange={(e)=>

handleChange(

"description",

e.target.value

)

}

/>


</Grid>









<Grid size={12}>


<TextField

fullWidth

multiline

rows={3}

label="Remarks"

value={formData.remarks}

onChange={(e)=>

handleChange(

"remarks",

e.target.value

)

}

/>


</Grid>






</Grid>









<Stack

mt={4}

direction="row"

justifyContent="flex-end"

>


<Button

type="submit"

variant="contained"

startIcon={<Save/>}

disabled={loading}

>


{

loading

?

"Saving..."

:

"Save Activity"

}


</Button>


</Stack>







</Box>

);


};





export default ActivityForm;