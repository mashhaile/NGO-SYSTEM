const budgetService = require("../services/budgetService");


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
    )

};
