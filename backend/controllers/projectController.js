const projectService =
    require("../services/projectService");

const subscriptionService =
    require("../services/subscriptionService");



// ==========================================
// CREATE PROJECT
// ==========================================

const createProject = async (req, res) => {

    try {

        const organizationId =
            req.user.organizationId;


        // ==========================================
        // CHECK PROJECT LIMIT
        // ==========================================

        await subscriptionService.checkResourceLimit(

            organizationId,

            "projects"

        );


        // ==========================================
        // CREATE
        // ==========================================

        const project =
            await projectService.createProject(

                req.body,

                organizationId,

                req.user.userId

            );


        res.status(201).json({

            success: true,

            message:
                "Project created successfully",

            data:
                project

        });

    }

    catch (error) {

        console.error(

            "CREATE PROJECT ERROR:",

            error

        );


        res.status(

            error.statusCode || 400

        ).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// GET PROJECTS
// ==========================================

const getProjects = async (req, res) => {

    try {

        const result =
            await projectService.getProjects(

                req.user.organizationId,

                req.query

            );


        res.json({

            success: true,

            ...result

        });

    }

    catch (error) {

        res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// GET SINGLE PROJECT
// ==========================================

const getProjectById = async (req, res) => {

    try {

        const project =
            await projectService.getProjectById(

                req.params.id,

                req.user.organizationId

            );


        if (!project) {

            return res.status(404).json({

                success: false,

                message:
                    "Project not found"

            });

        }


        res.json({

            success: true,

            data:
                project

        });

    }

    catch (error) {

        res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// UPDATE PROJECT
// ==========================================

const updateProject = async (req, res) => {

    try {

        const project =
            await projectService.updateProject(

                req.params.id,

                req.body,

                req.user.organizationId,

                req.user.userId

            );


        if (!project) {

            return res.status(404).json({

                success: false,

                message:
                    "Project not found"

            });

        }


        res.json({

            success: true,

            message:
                "Project updated successfully",

            data:
                project

        });

    }

    catch (error) {

        res.status(400).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// DELETE PROJECT
// ==========================================

const deleteProject = async (req, res) => {

    try {

        const project =
            await projectService.deleteProject(

                req.params.id,

                req.user.organizationId,

                req.user.userId

            );


        if (!project) {

            return res.status(404).json({

                success: false,

                message:
                    "Project not found"

            });

        }


        res.json({

            success: true,

            message:
                "Project deleted successfully"

        });

    }

    catch (error) {

        res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// PROJECT LOOKUP
// Used by Activity creation
// ==========================================

const getProjectLookup = async (req, res) => {

    try {

        const projects =
            await projectService.getProjectLookup(

                req.user.organizationId

            );


        res.json({

            success: true,

            data:
                projects

        });

    }

    catch (error) {

        res.status(500).json({

            success: false,

            message:
                error.message

        });

    }

};



// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createProject,

    getProjects,

    getProjectById,

    updateProject,

    deleteProject,

    getProjectLookup

};