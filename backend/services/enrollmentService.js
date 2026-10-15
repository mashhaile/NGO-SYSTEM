const Enrollment = require("../models/enrollment");

const {

buildSearch

}=require("../utils/searchBuilder");


const {

getPagination

}=require("../utils/pagination");

// ==========================================
// CREATE ENROLLMENT
// ==========================================

const createEnrollment = async(

data,

organizationId,

userId

)=>{


    // =====================================
    // CHECK DUPLICATE ENROLLMENT
    // Same beneficiary cannot enroll twice
    // in same program
    // =====================================

    const existingEnrollment = await Enrollment.findOne({

        organization: organizationId,

        program: data.program,

        beneficiary: data.beneficiary,

        isDeleted:false

    });



    if(existingEnrollment){

        throw new Error(

            "This beneficiary is already enrolled in this program"

        );

    }




    const enrollment = await Enrollment.create({


        organization:organizationId,


        program:data.program,


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







Object.assign(

filter,

buildSearch(

search,

[

"remarks",

"exitReason"

]

)

);







if(program){

filter.program=program;

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