const donationTraceService =
    require("../services/donationTraceService");

const {
    buildDonationStatementPdf
} = require("../services/donationStatementPdf");


// ==========================================
// DONATION TRACE CONTROLLER
// ==========================================

// Staff see names only with beneficiary.read.

const canSeeNames = (user) => {

    const permissions =
        user?.permissions || [];

    return (
        permissions.includes("*") ||
        permissions.includes("beneficiary.read")
    );

};


const getDonationTrace = async (req, res, next) => {

    try {

        const trace =
            await donationTraceService.getDonationTrace(
                req.params.id,
                req.user.organizationId,
                {
                    includeNames: canSeeNames(req.user)
                }
            );

        res.json({
            success: true,
            data: trace
        });

    }
    catch (error) {
        next(error);
    }

};


const getDonorTrace = async (req, res, next) => {

    try {

        const trace =
            await donationTraceService.getDonorTrace(
                req.params.id,
                req.user.organizationId
            );

        res.json({
            success: true,
            data: trace
        });

    }
    catch (error) {
        next(error);
    }

};


const getUntracedSpending = async (req, res, next) => {

    try {

        const result =
            await donationTraceService.getUntracedSpending(
                req.user.organizationId,
                req.query
            );

        res.json({
            success: true,
            data: result
        });

    }
    catch (error) {
        next(error);
    }

};


const downloadDonationStatement = async (req, res, next) => {

    try {

        const {
            buffer,
            fileName
        } = await buildDonationStatementPdf(
            req.params.id,
            req.user.organizationId
        );

        res.setHeader(
            "Content-Type",
            "application/pdf"
        );

        res.setHeader(
            "Content-Disposition",
            `attachment; filename="${fileName}"`
        );

        res.send(buffer);

    }
    catch (error) {
        next(error);
    }

};


module.exports = {
    getDonationTrace,
    getDonorTrace,
    getUntracedSpending,
    downloadDonationStatement
};
