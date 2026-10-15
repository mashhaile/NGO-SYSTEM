import {
    createSlice
}
from "@reduxjs/toolkit";


import {

    getActivitiesThunk,

    getActivityByIdThunk,

    createActivityThunk,

    updateActivityThunk,

    deleteActivityThunk

}
from "./activityThunks";





const initialState={


    data:[],


    selectedActivity:null,


    loading:false,


    error:null,


    pagination:{


        total:0,


        page:1,


        limit:10,


        pages:0


    }


};







const activitySlice=createSlice({


name:"activities",


initialState,


reducers:{


    clearSelectedActivity:(state)=>{


        state.selectedActivity=null;


    },


    clearActivityError:(state)=>{


        state.error=null;


    }



},





extraReducers:(builder)=>{



builder



// ==============================
// GET ALL
// ==============================


.addCase(

getActivitiesThunk.pending,

(state)=>{

state.loading=true;

}

)



.addCase(

getActivitiesThunk.fulfilled,

(state,action)=>{


state.loading=false;


state.data=

action.payload.data || [];



state.pagination=

action.payload.pagination || state.pagination;



}

)



.addCase(

getActivitiesThunk.rejected,

(state,action)=>{


state.loading=false;


state.error=

action.payload;


}

)








// ==============================
// GET ONE
// ==============================


.addCase(

getActivityByIdThunk.fulfilled,

(state,action)=>{


state.selectedActivity=

action.payload;



}

)








// ==============================
// CREATE
// ==============================


.addCase(

createActivityThunk.fulfilled,

(state,action)=>{


state.data.unshift(

action.payload

);


}

)








// ==============================
// UPDATE
// ==============================


.addCase(

updateActivityThunk.fulfilled,

(state,action)=>{


const index=

state.data.findIndex(

item=>

item._id===action.payload._id

);



if(index!==-1){


state.data[index]=action.payload;


}



}

)








// ==============================
// DELETE
// ==============================


.addCase(

deleteActivityThunk.fulfilled,

(state,action)=>{


state.data=

state.data.filter(

item=>

item._id!==action.payload

);


}

)





}

});







export const {


clearSelectedActivity,

clearActivityError


}
=
activitySlice.actions;





export default activitySlice.reducer;