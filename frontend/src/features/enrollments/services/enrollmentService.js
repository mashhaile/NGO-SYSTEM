import {

    getEnrollmentsApi,

    getEnrollmentByIdApi,

    createEnrollmentApi,

    updateEnrollmentApi,

    deleteEnrollmentApi

} from "../api/enrollmentApi";





// ==========================================
// GET ALL ENROLLMENTS
// ==========================================

export const getEnrollmentsService = async(params)=>{


    return await getEnrollmentsApi(params);


};







// ==========================================
// GET ONE ENROLLMENT
// ==========================================

export const getEnrollmentByIdService = async(id)=>{


    return await getEnrollmentByIdApi(id);


};







// ==========================================
// CREATE ENROLLMENT
// ==========================================

export const createEnrollmentService = async(data)=>{


    return await createEnrollmentApi(data);


};







// ==========================================
// UPDATE ENROLLMENT
// ==========================================

export const updateEnrollmentService = async(

    id,

    data

)=>{


    return await updateEnrollmentApi(

        id,

        data

    );


};







// ==========================================
// DELETE ENROLLMENT
// ==========================================

export const deleteEnrollmentService = async(id)=>{


    return await deleteEnrollmentApi(id);


};
