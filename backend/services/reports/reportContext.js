const Organization = require("../../models/Organization");
const User = require("../../models/User");


const buildReportContext = async (req) => {


    if (!req.user) {

        throw new Error(
            "No authenticated user found"
        );

    }


    const organizationId =
        req.user.organizationId;



    const user =
        await User.findById(
            req.user.userId
        )
        .select(
            "firstName lastName role organization"
        );



    const organization =
        await Organization.findById(
            organizationId
        )
        .select(
            "name logo address"
        );



    return {

        organizationId,

        userId:
            req.user.userId,

        role:
            req.user.role,

        user,

        organization

    };

};


module.exports = {
    buildReportContext
};