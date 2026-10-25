const { getErrorStatus, getErrorMessage } = require("../utils/errorStatus");
const roleService = require("../services/roleService");

// GET /roles, POST /roles, PUT /roles/:id, DELETE /roles/:id
const respond = (status, handler) => async (req, res) => {
    try {
        res.status(status).json({ success: true, data: await handler(req) });
    }
    catch (error) {
        res.status(getErrorStatus(error)).json({ success: false, message: getErrorMessage(error) });
    }
};

module.exports = {
    listRoles: respond(200, req => roleService.listRoles(req.user.organizationId)),
    createRole: respond(201, req => roleService.createRole(req.user.organizationId, req.body || {}, req.user.userId)),
    updateRole: respond(200, req => roleService.updateRole(req.user.organizationId, req.params.id, req.body || {}, req.user.userId)),
    deleteRole: respond(200, req => roleService.deleteRole(req.user.organizationId, req.params.id, req.user.userId))
};
