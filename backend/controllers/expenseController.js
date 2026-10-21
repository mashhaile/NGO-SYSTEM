const expenseService = require("../services/expenseService");


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

    getExpenses: handle(
        req => expenseService.getExpenses(org(req), req.query),
        { message: "Expenses fetched successfully" }
    ),

    getExpenseById: handle(
        req => expenseService.getExpenseById(req.params.id, org(req)),
        { message: "Expense fetched successfully" }
    ),

    createExpense: handle(
        req => expenseService.createExpense(req.body, org(req), user(req)),
        { status: 201, message: "Expense recorded" }
    ),

    updateExpense: handle(
        req => expenseService.updateExpense(req.params.id, req.body, org(req), user(req)),
        { message: "Expense updated" }
    ),

    deleteExpense: handle(
        async req => {
            await expenseService.deleteExpense(req.params.id, org(req), user(req));
            return null;
        },
        { message: "Expense deleted" }
    ),

    submitExpense: handle(
        req => expenseService.submitExpense(req.params.id, org(req), user(req)),
        { message: "Expense submitted for approval" }
    ),

    approveExpense: handle(
        req => expenseService.approveExpense(req.params.id, org(req), user(req), req.body),
        { message: "Expense approved" }
    ),

    returnExpense: handle(
        req => expenseService.returnExpense(req.params.id, org(req), user(req), req.body.comment),
        { message: "Expense returned for changes" }
    ),

    voidExpense: handle(
        req => expenseService.voidExpense(req.params.id, org(req), user(req), req.body.comment),
        { message: "Expense voided" }
    )

};
