const budgetService = require("../services/budgetService");

const revisionService = require("../services/budgetRevisionService");


// Thin handlers: errors go to the central error handler,
// which picks the HTTP status (utils/errorStatus).

const handle = (run, { status = 200, message }) =>
    async (req, res, next) => {
        try {
            const data = await run(req);
            res.status(status).json({
                success: true,
                message,
                ...(data && data.pagination ? data : { data })
            });
        }
        catch (error) {
            next(error);
        }
    };


const org = (req) => req.user.organizationId;
const user = (req) => req.user.userId;


module.exports = {

    getBudgets: handle(
        req => budgetService.getBudgets(org(req), req.query),
        { message: "Budgets fetched successfully" }
    ),

    getBudgetedTargets: handle(
        req => budgetService.getBudgetedTargets(org(req)),
        { message: "Programs and projects with a budget" }
    ),

    getBudgetById: handle(
        req => budgetService.getBudgetById(req.params.id, org(req)),
        { message: "Budget fetched successfully" }
    ),

    createBudget: handle(
        req => budgetService.createBudget(req.body, org(req), user(req)),
        { status: 201, message: "Budget created successfully" }
    ),

    updateBudget: handle(
        req => budgetService.updateBudget(req.params.id, req.body, org(req), user(req)),
        { message: "Budget updated successfully" }
    ),

    deleteBudget: handle(
        async req => {
            await budgetService.deleteBudget(req.params.id, org(req), user(req));
            return null;
        },
        { message: "Budget deleted successfully" }
    ),

    submitBudget: handle(
        req => budgetService.submitBudget(req.params.id, org(req), user(req)),
        { message: "Budget submitted for approval" }
    ),

    approveBudget: handle(
        req => budgetService.approveBudget(req.params.id, org(req), user(req), req.body.comment),
        { message: "Budget approved" }
    ),

    returnBudget: handle(
        req => budgetService.returnBudget(req.params.id, org(req), user(req), req.body.comment),
        { message: "Budget returned for changes" }
    ),

    // Revisions of approved budgets

    startRevision: handle(
        req => revisionService.startRevision(req.params.id, org(req), user(req)),
        { status: 201, message: "Revision started" }
    ),

    updateRevision: handle(
        req => revisionService.updateRevision(req.params.id, req.body, org(req), user(req)),
        { message: "Revision saved" }
    ),

    cancelRevision: handle(
        req => revisionService.cancelRevision(req.params.id, org(req), user(req)),
        { message: "Revision cancelled" }
    ),

    submitRevision: handle(
        req => revisionService.submitRevision(req.params.id, org(req), user(req)),
        { message: "Revision submitted for approval" }
    ),

    approveRevision: handle(
        req => revisionService.approveRevision(req.params.id, org(req), user(req), req.body.comment),
        { message: "Revision approved" }
    ),

    returnRevision: handle(
        req => revisionService.returnRevision(req.params.id, org(req), user(req), req.body.comment),
        { message: "Revision returned for changes" }
    )

};
