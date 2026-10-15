const notificationService =
require("./notificationService");

const User =
require("../models/User");

const {
    ROLES
} =
require("../config/constants");





// ==========================================
// Notify Organization Admins
// ==========================================

const notifyOrganizationAdmins = async (

    organizationId,

    title,

    message,

    type = "organization",

    createdBy = null,

    referenceId = null

) => {


   const admins =
    await User.find({

        organization:
            organizationId,

        role:
            ROLES.ORG_ADMIN,

        status:"active"

    });



    const notifications = [];



    for(
        const admin of admins
    ){


        const notification =
            await notificationService.createNotification({

                organization:
                    organizationId,

                user:
                    admin._id,

                title,

                message,

                type,

                createdBy,

                referenceId

            });



        notifications.push(
            notification
        );


    }



    return notifications;

};





module.exports = {

    notifyOrganizationAdmins

};