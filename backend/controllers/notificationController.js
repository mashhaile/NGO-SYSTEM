const {
    getErrorStatus,
    getErrorMessage
} = require("../utils/errorStatus");

const service =
require("../services/notificationService");




// ==========================================
// Get My Notifications
// ==========================================

const getMyNotifications = async (
    req,
    res
) => {

    try {


        const data =
            await service.getUserNotifications(

                req.user.userId,

                req.user.organizationId,

                req.query

            );



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
// Get Organization Notifications
// ==========================================

const getOrganizationNotifications =
async (

    req,

    res

) => {

    try {


        const data =
            await service.getOrganizationNotifications(

                req.user.organizationId,

                req.query

            );



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
// Mark Notification Read
// ==========================================

const markAsRead = async (

    req,

    res

) => {

    try {


        const data =
            await service.markAsRead(

                req.params.id,

                req.user.userId

            );



        res.json({

            success:true,

            message:
            "Notification marked as read",

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
// Unread Count
// ==========================================

const getUnreadCount = async (

    req,

    res

) => {

    try {


        const data =
            await service.getUnreadCount(

                req.user.userId

            );



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




module.exports = {


    getMyNotifications,

    getOrganizationNotifications,

    markAsRead,

    getUnreadCount


};