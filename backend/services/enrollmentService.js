const Enrollment = require("../models/enrollment");

const Beneficiary = require("../models/Beneficiary");

const Program = require("../models/program");

const escapeRegex = require("../utils/escapeRegex");

const {

buildSearch

}=require("../utils/searchBuilder");


const {

getPagination

}=require("../utils/pagination");

const ApiError = require("../utils/apiError");

// The project (or phase) of an enrollment: of this organization,
// and not a main project that has phases (its phases enroll)
const projectOf = async (projectId, organizationId) => {

    if (projectId === undefined || projectId === null || projectId === "") return null;

    if (!require("mongoose").isValidObjectId(projectId)) throw new ApiError("Project not found.", 404);

    const project = await require("../models/Project").findOne({ _id: projectId, organization: organizationId, isDeleted: false }).select("name program parentProject").lean();

    if (!project) throw new ApiError("Project not found.", 404);

    await require("./projectPhases").assertNotMainProject(project._id, organizationId, "the enrollment");

    return project;

};


// ==========================================
// CREATE ENROLLMENT
// ==========================================

const createEnrollment = async(

data,

organizationId,

userId

)=>{


    // =====================================
    // THE PROJECT (or phase) DECIDES THE PROGRAM
    // =====================================

    const project = await projectOf(data.project, organizationId);

    if(project){

        if(data.program && String(data.program) !== String(project.program)){
            throw new ApiError(`${project.name} is not in the program chosen.`, 400);
        }

        data.program = String(project.program);

    }

    if(!data.program){
        throw new ApiError("Choose the project.", 400);
    }


    // =====================================
    // CHECK DUPLICATE ENROLLMENT
    // Same beneficiary cannot enroll twice
    // in the same project (older enrollments
    // without a project: in the same program)
    // =====================================

    const existingEnrollment = await Enrollment.findOne({

        organization: organizationId,

        program: data.program,

        project: project ? project._id : null,

        beneficiary: data.beneficiary,

        isDeleted:false

    });



    if(existingEnrollment){

        throw new ApiError(

            project
                ? `This beneficiary is already enrolled in ${project.name}.`
                : "This beneficiary is already enrolled in this program",

            409

        );

    }




    const enrollment = await Enrollment.create({


        organization:organizationId,


        program:data.program,


        project:project ? project._id : null,


        beneficiary:data.beneficiary,


        enrollmentDate:

        data.enrollmentDate || new Date(),



        status:

        data.status || "Pending",



        completionDate:

        data.completionDate || null,



        exitReason:

        data.exitReason || null,



        remarks:

        data.remarks || null,



        customFields:

        data.customFields || [],



        createdBy:userId


    });






    return Enrollment.findById(

        enrollment._id

    )


    .populate(

        "program",

        "programCode name"

    )


    .populate(

        "project",

        "projectCode name parentProject phaseNumber"

    )


    .populate(

        "beneficiary",

        "beneficiaryNumber firstName lastName gender age phone"

    );


};









// ==========================================
// GET ALL
// ==========================================


const getEnrollments = async(

organizationId,

query={}

)=>{



const {


search,

program,

status,

beneficiary


}=query;





const {

page,

limit,

skip

}=getPagination(query);







const filter={


organization:organizationId,


isDeleted:false


};







// Search matches the beneficiary (name / number), the
// program (name / code) or the enrollment remarks.

const searchText =
String(search || "").trim();

if(searchText.length >= 2){

const regex =
new RegExp(escapeRegex(searchText),"i");

const [beneficiaryIds, programIds] =
await Promise.all([

Beneficiary.find({
organization:organizationId,
$or:[
{firstName:regex},
{lastName:regex},
{beneficiaryNumber:regex}
]
}).distinct("_id"),

Program.find({
organization:organizationId,
$or:[
{name:regex},
{programCode:regex}
]
}).distinct("_id")

]);

filter.$or = [
{beneficiary:{$in:beneficiaryIds}},
{program:{$in:programIds}},
...buildSearch(searchText,["remarks","exitReason"]).$or
];

}







if(program){

filter.program=program;

}

// a project (a main project: the people of its phases)
// "none": older enrollments still without a project
if(query.project === "none"){

filter.project=null;

}
else if(query.project){

filter.project={ $in: await require("./projectPhases").projectAndPhases(query.project, organizationId) };

}






if(status){

filter.status=status;

}






if(beneficiary){

filter.beneficiary=beneficiary;

}









const [


data,


total


]=await Promise.all([





Enrollment.find(filter)



.populate(

"program",

"programCode name"

)

.populate(

"project",

"projectCode name parentProject phaseNumber"

)



.populate(

"beneficiary",

"beneficiaryNumber firstName lastName gender"

)



.sort({

createdAt:-1

})



.skip(skip)



.limit(limit)



.lean(),





Enrollment.countDocuments(filter)



]);









return {


data,


pagination:{


total,


page,


limit,


totalPages:

Math.ceil(total/limit)


}


};




};









// ==========================================
// GET SINGLE
// ==========================================


const getEnrollmentById = async(

id,

organizationId

)=>{





const enrollment =

await Enrollment.findOne({


_id:id,


organization:organizationId,


isDeleted:false


})



.populate(

"program",

"programCode name description status"

)

.populate(

"project",

"projectCode name status startDate endDate parentProject phaseNumber"

)



.populate(

"beneficiary",

"beneficiaryNumber firstName lastName gender age phone"

)



.lean();








if(!enrollment){


throw new Error(

"Enrollment not found"

);


}






return enrollment;



};









// ==========================================
// UPDATE
// ==========================================


const updateEnrollment = async(

id,

data,

organizationId,

userId

)=>{





const enrollment =

await Enrollment.findOne({


_id:id,


organization:organizationId,


isDeleted:false


});







if(!enrollment){


throw new Error(

"Enrollment not found"

);


}







delete data.organization;

delete data.program;

delete data.beneficiary;

if(data.project !== undefined){

    const project = await projectOf(data.project, organizationId);

    if(!project){
        throw new ApiError("Choose the project.", 400);
    }

    if(String(project.program) !== String(enrollment.program)){
        throw new ApiError(`${project.name} is in another program. Enroll the person in it instead.`, 400);
    }

    const taken = await Enrollment.exists({ organization: organizationId, project: project._id, beneficiary: enrollment.beneficiary, isDeleted: false, _id: { $ne: enrollment._id } });

    if(taken){
        throw new ApiError(`This beneficiary is already enrolled in ${project.name}.`, 409);
    }

    data.project = project._id;

}






Object.assign(

enrollment,

data

);






enrollment.updatedBy=userId;






await enrollment.save();






return enrollment;



};









// ==========================================
// DELETE
// ==========================================


const deleteEnrollment = async(

id,

organizationId,

userId

)=>{





const enrollment =

await Enrollment.findOne({


_id:id,


organization:organizationId,


isDeleted:false


});






if(!enrollment){


throw new Error(

"Enrollment not found"

);


}







enrollment.isDeleted=true;


enrollment.deletedAt=new Date();


enrollment.deletedBy=userId;







await enrollment.save();






return enrollment;



};









module.exports={


createEnrollment,


getEnrollments,


getEnrollmentById,


updateEnrollment,


deleteEnrollment


};