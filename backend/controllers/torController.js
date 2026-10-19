const torService =
    require("../services/torService");

const subscriptionService =
    require("../services/subscriptionService");


// ==========================================
// TERMS OF REFERENCE CONTROLLER
// ==========================================

const createTor = async (req, res, next) => {

    try {

        const tor =
            await torService.createTor(
                req.body,
                req.user.organizationId,
                req.user.userId
            );

        res.status(201).json({
            success: true,
            message: "Terms of reference created successfully",
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const getTors = async (req, res, next) => {

    try {

        const result =
            await torService.getTors(
                req.user.organizationId,
                req.query
            );

        res.json({
            success: true,
            ...result
        });

    }
    catch (error) {
        next(error);
    }

};


const getTorById = async (req, res, next) => {

    try {

        const tor =
            await torService.getTorById(
                req.params.id,
                req.user.organizationId
            );

        res.json({
            success: true,
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const updateTor = async (req, res, next) => {

    try {

        const tor =
            await torService.updateTor(
                req.params.id,
                req.body,
                req.user.organizationId,
                req.user.userId
            );

        res.json({
            success: true,
            message: "Terms of reference updated successfully",
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const deleteTor = async (req, res, next) => {

    try {

        await torService.deleteTor(
            req.params.id,
            req.user.organizationId,
            req.user.userId
        );

        res.json({
            success: true,
            message: "Terms of reference deleted successfully"
        });

    }
    catch (error) {
        next(error);
    }

};


const submitTor = async (req, res, next) => {

    try {

        const tor =
            await torService.submitTor(
                req.params.id,
                req.user.organizationId,
                req.user.userId
            );

        res.json({
            success: true,
            message: "Terms of reference submitted for approval",
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const approveTor = async (req, res, next) => {

    try {

        const tor =
            await torService.approveTor(
                req.params.id,
                req.user.organizationId,
                req.user.userId,
                req.body.comment
            );

        res.json({
            success: true,
            message: "Terms of reference approved",
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const returnTor = async (req, res, next) => {

    try {

        const tor =
            await torService.returnTor(
                req.params.id,
                req.user.organizationId,
                req.user.userId,
                req.body.comment
            );

        res.json({
            success: true,
            message: "Terms of reference returned for revision",
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const createActivityFromTor = async (req, res, next) => {

    try {

        // Same plan limit as creating an activity directly.

        await subscriptionService.checkResourceLimit(
            req.user.organizationId,
            "activities"
        );

        const result =
            await torService.createActivityFromTor(
                req.params.id,
                req.user.organizationId,
                req.user.userId
            );

        res.status(201).json({
            success: true,
            message: "Activity created from the approved TOR",
            data: result
        });

    }
    catch (error) {
        next(error);
    }

};


const linkActivity = async (req, res, next) => {

    try {

        const tor =
            await torService.linkActivity(
                req.params.id,
                req.user.organizationId,
                req.user.userId,
                req.body.activity
            );

        res.json({
            success: true,
            message: "Activity linked to the TOR",
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const updateLinkedActivity = async (req, res, next) => {

    try {

        const tor =
            await torService.updateLinkedActivity(
                req.params.id,
                req.user.organizationId,
                req.user.userId,
                req.body
            );

        res.json({
            success: true,
            message: "Activity updated",
            data: tor
        });

    }
    catch (error) {
        next(error);
    }

};


const downloadTorPdf = async (req, res, next) => {

    try {

        const {
            buffer,
            fileName
        } = await torService.buildTorPdf(
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
    createTor,
    getTors,
    getTorById,
    updateTor,
    deleteTor,
    submitTor,
    approveTor,
    returnTor,
    createActivityFromTor,
    linkActivity,
    updateLinkedActivity,
    downloadTorPdf
};
