import {

    getProjectsApi,

    getProjectByIdApi,

    createProjectApi,

    updateProjectApi,

    deleteProjectApi

}
from "../api/projectApi";


import {

    getProjectLookupApi

}
from "../api/lookupApi";




// ==========================================
// GET PROJECTS
// ==========================================

export const getProjectsService = (params)=>{

    return getProjectsApi(params);

};




// ==========================================
// GET PROJECT BY ID
// ==========================================

export const getProjectByIdService = (id)=>{

    return getProjectByIdApi(id);

};




// ==========================================
// CREATE PROJECT
// ==========================================

export const createProjectService = (data)=>{

    return createProjectApi(data);

};




// ==========================================
// UPDATE PROJECT
// ==========================================

export const updateProjectService = (id,data)=>{

    return updateProjectApi(

        id,

        data

    );

};




// ==========================================
// DELETE PROJECT
// ==========================================

export const deleteProjectService = (id)=>{

    return deleteProjectApi(id);

};




// ==========================================
// PROJECT LOOKUP
// ==========================================

export const getProjectLookupService = ()=>{

    return getProjectLookupApi();

};