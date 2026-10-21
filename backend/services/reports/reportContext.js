const Organization = require("../../models/organization");
const User = require("../../models/user");
const rolePermissions = require("../../constants/rolepermissions");


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

        // So individual reports can require a permission
        // (finance reports need budget.read)
        permissions:
            rolePermissions[req.user.role] || [],

        user,

        organization

    };

};


module.exports = {
    buildReportContext
};