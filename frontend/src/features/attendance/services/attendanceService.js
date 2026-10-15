import {


getAttendancesApi,

getAttendanceByIdApi,

createAttendanceApi,

updateAttendanceApi,

deleteAttendanceApi,

getAttendanceRecordsApi,

saveAttendanceRecordsApi


}
from "../api/attendanceApi";





export const getAttendancesService=(params)=>{


return getAttendancesApi(params);


};






export const getAttendanceByIdService=(id)=>{


return getAttendanceByIdApi(id);


};






export const createAttendanceService=(data)=>{


return createAttendanceApi(data);


};






export const updateAttendanceService=(id,data)=>{


return updateAttendanceApi(

id,

data

);


};






export const deleteAttendanceService=(id)=>{


return deleteAttendanceApi(id);


};






export const getAttendanceRecordsService=(id)=>{


return getAttendanceRecordsApi(id);


};






export const saveAttendanceRecordsService=(id,data)=>{

    return saveAttendanceRecordsApi(
        id,
        data
    );

};