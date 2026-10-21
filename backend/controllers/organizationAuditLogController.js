const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const service =
require("../services/auditLogService");




// ==========================================
// Get Organization Audit Logs
// ==========================================

const getAuditLogs = async(
    req,
    res
)=>{

try{


const data =
await service.getAuditLogs({

    ...req.query,

    organizationId:
        req.user.organizationId

});



res.json({

    success:true,

    data

});


}
catch(error){

res.status(getErrorStatus(error)).json({

    success:false,

    message:getErrorMessage(error)

});

}

};




// ==========================================
// Get Details
// ==========================================

const getAuditLogDetails = async(
    req,
    res
)=>{

try{


const log =
await service.getAuditLogById(
    req.params.id
);



if(!log){

return res.status(404).json({

    success:false,

    message:
    "Audit log not found"

});

}



// Extra tenant protection

if(
String(
    log.organizationId?._id ||
    log.organizationId
)
!== 
String(req.user.organizationId)
){

return res.status(403).json({

    success:false,

    message:
    "Access denied"

});

}



res.json({

success:true,

data:log

});


}
catch(error){

res.status(getErrorStatus(error)).json({

success:false,

message:getErrorMessage(error)

});

}

};



module.exports={

getAuditLogs,

getAuditLogDetails

};