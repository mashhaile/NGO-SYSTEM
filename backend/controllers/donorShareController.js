const donorShareService =
    require("../services/donorShareService");

const {
    buildDonationStatementPdf
} = require("../services/donationStatementPdf");


// ==========================================
// STAFF
// ==========================================

const createShareLink = async (req, res, next) => {

    try {

        const result =
            await donorShareService.createShareLink(
                req.user.organizationId,
                req.user.userId,
                req.body
            );

        res.status(201).json({
            success: true,
            message: "Share link created. Copy it now: it will not be shown again.",
            data: result
        });

    }
    catch (error) {
        next(error);
    }

};


const listShareLinks = async (req, res, next) => {

    try {

        const links =
            await donorShareService.listShareLinks(
                req.user.organizationId,
                req.query.donor
            );

        res.json({
            success: true,
            data: links
        });

    }
    catch (error) {
        next(error);
    }

};


const revokeShareLink = async (req, res, next) => {

    try {

        const link =
            await donorShareService.revokeShareLink(
                req.user.organizationId,
                req.params.id,
                req.user.userId
            );

        res.json({
            success: true,
            message: "Share link revoked.",
            data: link
        });

    }
    catch (error) {
        next(error);
    }

};


// ==========================================
// PUBLIC (no account)
// ==========================================

const getPublicView = async (req, res, next) => {

    try {

        const view =
            await donorShareService.getPublicView(
                req.params.token,
                req.get("user-agent")
            );

        res.set("Cache-Control", "no-store");

        res.set("X-Robots-Tag", "noindex, nofollow");

        res.json({
            success: true,
            data: view
        });

    }
    catch (error) {
        next(error);
    }

};


const downloadPublicStatement = async (req, res, next) => {

    try {

        const link =
            await donorShareService.assertDonationInScope(
                req.params.token,
                req.params.donationId
            );

        const {
            buffer,
            fileName
        } = await buildDonationStatementPdf(
            req.params.donationId,
            link.organization
        );

        res.set("Cache-Control", "no-store");

        res.setHeader("Content-Type", "application/pdf");

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
    createShareLink,
    listShareLinks,
    revokeShareLink,
    getPublicView,
    downloadPublicStatement
};
