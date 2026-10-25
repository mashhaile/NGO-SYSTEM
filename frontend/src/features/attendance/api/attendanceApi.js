import axiosClient from "../../../services/axiosClient";



// ==========================================
// GET ALL ATTENDANCE SESSIONS
// ==========================================

export const getAttendancesApi = (params = {}) => {

    return axiosClient.get(
        "/attendance",
        {
            params
        }
    );

};





// ==========================================
// GET SINGLE ATTENDANCE
// ==========================================

export const getAttendanceByIdApi = (id) => {

    return axiosClient.get(
        `/attendance/${id}`
    );

};






// ==========================================
// CREATE ATTENDANCE SESSION
// ==========================================

export const createAttendanceApi = (data) => {

    return axiosClient.post(
        "/attendance",
        data
    );

};






// ==========================================
// UPDATE ATTENDANCE SESSION
// ==========================================

export const updateAttendanceApi = (
    id,
    data
) => {

    return axiosClient.put(
        `/attendance/${id}`,
        data
    );

};







// ==========================================
// DELETE ATTENDANCE SESSION
// ==========================================

export const deleteAttendanceApi = (id) => {

    return axiosClient.delete(
        `/attendance/${id}`
    );

};








// ==========================================
// GET ATTENDANCE RECORDS
// ==========================================

export const getAttendanceRecordsApi = (id) => {

    return axiosClient.get(
        `/attendance/${id}/records`
    );

};








// ==========================================
// SAVE ATTENDANCE RECORDS
// ==========================================

export const saveAttendanceRecordsApi = (
    id,
    records
) => {


    return axiosClient.post(

        `/attendance/${id}/records`,

        // { records, version } or just the records
        Array.isArray(records)
            ? { records }
            : {
                records: Array.isArray(records?.records) ? records.records : [],
                version: records?.version ?? null
            }

    );


};