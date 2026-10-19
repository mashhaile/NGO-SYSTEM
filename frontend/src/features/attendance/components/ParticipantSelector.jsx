import {
    useCallback,
    useEffect,
    useState
} from "react";


import {
    Box,
    Button,
    TextField,
    Grid,
    Autocomplete,
    MenuItem,
    FormControlLabel,
    Checkbox
} from "@mui/material";


import { Add } from "@mui/icons-material";


import {
    getBeneficiariesLookupService
} from "../../beneficiaries/services/lookupService";


import LocationCascadeFields
from "../../locations/components/LocationCascadeFields";


import {
    getStaffLookupService
} from "../../users/services/lookupService";





const emptyExternal = {

    name:"",
    organizationName:"",
    position:"",
    phone:"",

    gender:"",

    ageGroup:"",

    disabilityStatus:false,

    location:{
        region:"",
        regionCode:"",
        zone:"",
        zoneCode:"",
        woreda:"",
        woredaCode:"",
        kebele:"",
        village:"",
        site:""
    }

};





const ParticipantSelector = ({
    type,
    onAdd
}) => {



const [people,setPeople]=useState([]);


const [selected,setSelected]=useState(null);


const [external,setExternal]=useState(
    emptyExternal
);





useEffect(()=>{


    setSelected(null);

    setPeople([]);

    setExternal(emptyExternal);



    if(type==="Beneficiary")
    {
        loadBeneficiaries();
    }



    if(type==="Staff")
    {
        loadStaff();
    }



},[type]);









const loadBeneficiaries=async()=>{


try{


const data =
await getBeneficiariesLookupService();


setPeople(data || []);


}
catch(error){


console.error(
"Beneficiary lookup error",
error
);


}



};









const loadStaff=async()=>{


try{


const data =
await getStaffLookupService();


setPeople(data || []);


}
catch(error){


console.error(
"Staff lookup error",
error
);


}



};









const updateExternal=(field,value)=>{


setExternal(prev=>({

...prev,

[field]:value

}));


};








// location cascade: several fields at once

const changeLocationFields=useCallback((patch)=>{

setExternal(prev=>({

...prev,

location:{

...prev.location,

...patch

}

}));

},[]);









const addParticipant=()=>{



// ================================
// BENEFICIARY
// ================================

if(type==="Beneficiary"){


if(!selected)
return;



onAdd({

participantType:"Beneficiary",

beneficiary:selected,

staff:null,

board:null,

externalParticipant:null,


gender:selected.gender || null,


ageGroup:selected.ageGroup || null,


disabilityStatus:
selected.disabilityStatus || false,


location:
selected.location || null,


status:"Present",

notes:""


});



}




// ================================
// STAFF
// ================================


else if(type==="Staff"){



if(!selected)
return;



onAdd({

participantType:"Staff",

beneficiary:null,

staff:selected,

board:null,

externalParticipant:null,


gender:selected.gender || null,


ageGroup:selected.ageGroup || null,


disabilityStatus:
selected.disabilityStatus || false,


location:
selected.location || null,


status:"Present",

notes:""


});



}




// ================================
// EXTERNAL
// ================================


else{


if(!external.name.trim())
return;



onAdd({

participantType:type,


beneficiary:null,


staff:null,


board:null,


externalParticipant:{
    ...external
},


gender:
external.gender || null,


ageGroup:
external.ageGroup || null,


disabilityStatus:
external.disabilityStatus || false,


location:
external.location || null,


status:"Present",


notes:""


});



setExternal(emptyExternal);



}



setSelected(null);



};









return (


<Box mb={2}>


<Grid
container
spacing={2}
>





{
(type==="Beneficiary" || type==="Staff") &&

<Grid size={{xs:12,md:10}}>


<Autocomplete


options={people}


value={selected}


isOptionEqualToValue={
(a,b)=>
a?._id===b?._id
}



getOptionLabel={(option)=>{


if(!option)
return "";



if(type==="Staff"){

return (

option.name ||

option.email ||

""

);

}



return (

`${option.beneficiaryNumber || ""} - ${option.firstName || ""} ${option.lastName || ""}`

);


}}



onChange={(e,value)=>
setSelected(value)
}



renderInput={(params)=>(

<TextField

{...params}

label={`Select ${type}`}

/>

)}



/>



</Grid>

}









{
type!=="Beneficiary" &&
type!=="Staff" &&

<>



<Grid size={{xs:12,md:3}}>

<TextField

fullWidth

label="Name"

value={external.name}

onChange={(e)=>
updateExternal(
"name",
e.target.value
)
}

/>

</Grid>





<Grid size={{xs:12,md:3}}>

<TextField

fullWidth

label="Organization"

value={
external.organizationName
}

onChange={(e)=>
updateExternal(
"organizationName",
e.target.value
)
}

/>

</Grid>






<Grid size={{xs:12,md:2}}>

<TextField

fullWidth

label="Position"

value={external.position}

onChange={(e)=>
updateExternal(
"position",
e.target.value
)
}

/>

</Grid>





<Grid size={{xs:12,md:2}}>

<TextField

fullWidth

label="Phone"

value={external.phone}

onChange={(e)=>
updateExternal(
"phone",
e.target.value
)
}

/>

</Grid>





<Grid size={{xs:12,md:2}}>

<TextField

select

fullWidth

label="Gender"

value={
external.gender
}

onChange={(e)=>
updateExternal(
"gender",
e.target.value
)
}

>


<MenuItem value="Male">
Male
</MenuItem>


<MenuItem value="Female">
Female
</MenuItem>

</TextField>


</Grid>





<Grid size={{xs:12,md:2}}>


<TextField

select

fullWidth

label="Age Group"

value={
external.ageGroup
}

onChange={(e)=>
updateExternal(
"ageGroup",
e.target.value
)
}


>


<MenuItem value="Child">
Child
</MenuItem>


<MenuItem value="Youth">
Youth
</MenuItem>


<MenuItem value="Adult">
Adult
</MenuItem>


<MenuItem value="Elderly">
Elderly
</MenuItem>


</TextField>


</Grid>





<LocationCascadeFields

value={external.location}

onChange={changeLocationFields}

size="medium"

renderItem={(field,key)=>(

<Grid key={key} size={{xs:12,md:3}}>

{field}

</Grid>

)}

/>





<Grid size={{xs:12,md:2}}>


<FormControlLabel

control={

<Checkbox

checked={
external.disabilityStatus
}

onChange={(e)=>

updateExternal(

"disabilityStatus",

e.target.checked

)

}

/>

}

label="Disability"

/>


</Grid>


</>

}









<Grid
size={{xs:12,md:2}}
>


<Button

fullWidth

variant="contained"

startIcon={<Add/>}

sx={{
height:"56px"
}}

onClick={addParticipant}

>


Add


</Button>


</Grid>







</Grid>


</Box>


);


};



export default ParticipantSelector;