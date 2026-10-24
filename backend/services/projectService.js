const ApiError = require("../utils/apiError");
const escapeRegex = require("../utils/escapeRegex");
const Project =
    require("../models/Project");

const Program =
    require("../models/program");

const Donor =
    require("../models/donor");

const User =
    require("../models/user");

const mongoose =
    require("mongoose");

const {
    USER_STATUS
} = require("../config/constants");


// =====================================================
// OBJECT ID VALIDATION
// =====================================================

const {
    getBudgetFigures
} = require("./budgetFigures");


// Adds the budget from the Budgets module (the only source of
// budget numbers) to lean project objects.
const withBudgets = async (organizationId, projects) => {

    const figures =
        await getBudgetFigures(
            organizationId,
            { projectIds: projects.map(project => project._id) }
        );

    return projects.map(project => ({
        ...project,
        budget: figures.projects[String(project._id)] || null
    }));

};


const phases = require("./projectPhases");


const isValidObjectId = (value) => {

    return mongoose.Types.ObjectId.isValid(value);

};


// =====================================================
// CREATE PROJECT
// =====================================================

const createProject = async (
    data,
    organizationId,
    userId
) => {

    // =================================================
    // A PHASE OF A MAIN PROJECT (its program)
    // =================================================
    const parent =
        await phases.resolveParent(data.parentProject, organizationId);
    if (parent) {
        data.program = String(parent.program);
        await phases.checkPhaseDates({ parent, startDate: data.startDate, endDate: data.endDate, organizationId });
    }
    // =================================================
    // VERIFY PROGRAM
    // =================================================
    if (
        !data.program ||
        !isValidObjectId(data.program)
    ) {

        throw new Error(
            "Invalid program."
        );

    }


    const program =
        await Program.findOne({

            _id:
                data.program,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!program) {

        throw new Error(
            "Program not found."
        );

    }


    // =================================================
    // VERIFY DONOR
    // =================================================

    let donorId = null;


    if (data.donor) {

        if (
            !isValidObjectId(data.donor)
        ) {

            throw new Error(
                "Invalid donor."
            );

        }


        const donor =
            await Donor.findOne({

                _id:
                    data.donor,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!donor) {

            throw new Error(
                "Donor not found."
            );

        }


        donorId =
            donor._id;

    }


    // =================================================
    // VERIFY PROJECT MANAGER
    // =================================================

    let projectManagerId = null;


    if (data.projectManager) {

        if (
            !isValidObjectId(
                data.projectManager
            )
        ) {

            throw new Error(
                "Invalid project manager."
            );

        }


        const user =
            await User.findOne({

                _id:
                    data.projectManager,

                organization:
                    organizationId,

                status:
                    USER_STATUS.ACTIVE

            });


        if (!user) {

            throw new Error(
                "Project manager not found."
            );

        }


        projectManagerId =
            user._id;

    }


    // =================================================
    // GENERATE PROJECT CODE
    // =================================================

    const totalProjects =
        await Project.countDocuments({

            organization:
                organizationId,

            program:
                data.program,

            isDeleted:
                false

        });


    const projectCode =
        `${program.programCode}-PRJ-${String(
            totalProjects + 1
        ).padStart(3, "0")}`;


    // =================================================
    // CREATE PROJECT
    // =================================================

    const project =
        await Project.create({

            organization:
                organizationId,

            program:
                data.program,

            projectCode,

            name:
                data.name,

            description:
                data.description || null,

            donor:
                donorId,

            projectManager:
                projectManagerId,

            startDate:
                data.startDate,

            endDate:
                data.endDate,

            status:
                data.status || "Draft",
            parentProject:
                parent ? parent._id : null,
            phaseNumber:
                parent ? await phases.nextPhaseNumber(parent._id, organizationId) : null,
            createdBy:
                userId
        });
    return project;

};


// =====================================================
// GET PROJECTS
// =====================================================

const getProjects = async (
    organizationId,
    query = {}
) => {

    const {

        search = "",

        page = 1,

        limit = 10,

        program,

        donor,

        status

    } = query;


    const filter = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    // =================================================
    // PROGRAM FILTER
    // =================================================

    if (program) {

        if (
            !isValidObjectId(program)
        ) {

            throw new Error(
                "Invalid program."
            );

        }


        filter.program =
            program;

    }


    // =================================================
    // DONOR FILTER
    // =================================================

    if (donor) {

        if (
            !isValidObjectId(donor)
        ) {

            throw new Error(
                "Invalid donor."
            );

        }


        filter.donor =
            donor;

    }


    // =================================================
    // PHASES OF A MAIN PROJECT
    // =================================================
    if (query.parentProject && isValidObjectId(query.parentProject)) {
        filter.parentProject =
            query.parentProject;
    }
    // =================================================
    // STATUS FILTER
    // =================================================
    if (status) {

        filter.status =
            status;

    }


    // =================================================
    // SEARCH
    // =================================================

    if (search) {

        filter.$or = [

            {

                projectCode: {

                    $regex:
                        escapeRegex(search),

                    $options:
                        "i"

                }

            },

            {

                name: {

                    $regex:
                        escapeRegex(search),

                    $options:
                        "i"

                }

            }

        ];

    }


    // =================================================
    // PAGINATION
    // =================================================

    const pageNumber =
        Math.max(
            Number(page) || 1,
            1
        );


    const limitNumber =
        Math.min(

            Math.max(
                Number(limit) || 10,
                1
            ),

            100

        );


    const skip =
        (pageNumber - 1)
        *
        limitNumber;


    // =================================================
    // QUERY
    // =================================================

    const [
        projects,
        total
    ] =
        await Promise.all([

            Project.find(filter)
                .populate(
                    "program",
                    "programCode name"
                )
                .populate(
                    "parentProject",
                    "projectCode name"
                )

                .populate(
                    "donor",
                    "name organizationName"
                )

                .populate(
                    "projectManager",
                    "name email role status"
                )

                .sort({
                    createdAt:
                        -1
                })

                .skip(skip)

                .limit(limitNumber)

                .lean(),


            Project.countDocuments(
                filter
            )

        ]);


    return {

        data:
            await withBudgets(organizationId, projects),

        pagination: {

            total,

            page:
                pageNumber,

            limit:
                limitNumber,

            pages:
                Math.ceil(
                    total /
                    limitNumber
                )

        }

    };

};


// =====================================================
// GET SINGLE PROJECT
// =====================================================

const getProjectById = async (
    id,
    organizationId
) => {

    if (
        !isValidObjectId(id)
    ) {

        throw new Error(
            "Invalid project ID."
        );

    }


    const project =
        await Project.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        })

            .populate(
                "program",
                "programCode name"
            )

            .populate(
                "donor",
                "name organizationName"
            )

            .populate(
                "projectManager",
                "name email role status"
            )

            .lean();

    if (!project) return null;
    const [result] =
        await withBudgets(organizationId, [project]);
    if (project.parentProject) {
        result.parentProject =
            await Project.findById(project.parentProject).select("projectCode name startDate endDate").lean();
    }
    result.phases =
        await withBudgets(organizationId, await phases.phasesOf(project._id, organizationId));
    return result;

};


// =====================================================
// UPDATE PROJECT
// =====================================================

const updateProject = async (
    id,
    data,
    organizationId,
    userId
) => {

    if (
        !isValidObjectId(id)
    ) {

        throw new Error(
            "Invalid project ID."
        );

    }


    // =================================================
    // FIND EXISTING PROJECT
    // =================================================

    const project =
        await Project.findOne({

            _id:
                id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!project) {
        throw new Error(
            "Project not found."
        );
    }
    // =================================================
    // MAIN PROJECT (a phase of it)
    // =================================================
    let newParent = undefined;
    if (data.parentProject !== undefined) {
        newParent =
            await phases.resolveParent(data.parentProject, organizationId, { selfId: project._id });
        // a phase is in its main project's program
        if (newParent) data.program = String(newParent.program);
    }
    // =================================================
    // PROGRAM
    // =================================================

    if (
        data.program !== undefined &&
        data.program !== null &&
        data.program !== ""
    ) {

        if (
            !isValidObjectId(
                data.program
            )
        ) {

            throw new Error(
                "Invalid program."
            );

        }


        const program =
            await Program.findOne({

                _id:
                    data.program,

                organization:
                    organizationId,

                isDeleted:
                    false

            });


        if (!program) {

            throw new Error(
                "Program not found."
            );

        }


        const programChanged =
            String(project.program) !==
            String(program._id);


        if (programChanged) {

            // Not once budgets, deliveries ... are recorded under
            // its current program (see parentChangeGuard)
            await require("./parentChangeGuard")
                .assertProjectCanChangeProgram(project._id, organizationId);

            const totalProjects =
                await Project.countDocuments({

                    organization:
                        organizationId,

                    program:
                        program._id,

                    isDeleted:
                        false

                });


            project.program =
                program._id;


            project.projectCode =
                `${program.programCode}-PRJ-${String(
                    totalProjects + 1
                ).padStart(3, "0")}`;

        }

    }


    // =================================================
    // DONOR
    // =================================================

    if (
        data.donor !== undefined
    ) {

        if (
            data.donor === null ||
            data.donor === ""
        ) {

            project.donor =
                null;

        }
        else {

            if (
                !isValidObjectId(
                    data.donor
                )
            ) {

                throw new Error(
                    "Invalid donor."
                );

            }


            const donor =
                await Donor.findOne({

                    _id:
                        data.donor,

                    organization:
                        organizationId,

                    isDeleted:
                        false

                });


            if (!donor) {

                throw new Error(
                    "Donor not found."
                );

            }


            project.donor =
                donor._id;

        }

    }


    // =================================================
    // PROJECT MANAGER
    // =================================================

    if (
        data.projectManager !== undefined
    ) {

        if (
            data.projectManager === null ||
            data.projectManager === ""
        ) {

            project.projectManager =
                null;

        }
        else {

            if (
                !isValidObjectId(
                    data.projectManager
                )
            ) {

                throw new Error(
                    "Invalid project manager."
                );

            }


            const user =
                await User.findOne({

                    _id:
                        data.projectManager,

                    organization:
                        organizationId,

                    status:
                        USER_STATUS.ACTIVE

                });


            if (!user) {

                throw new Error(
                    "Project manager not found."
                );

            }


            project.projectManager =
                user._id;

        }

    }


    // =================================================
    // OPTIONAL FIELDS
    // =================================================

    if (
        data.name !== undefined
    ) {

        project.name =
            data.name;

    }


    if (
        data.description !== undefined
    ) {

        project.description =
            data.description;

    }


    if (
        data.status !== undefined
    ) {

        project.status =
            data.status;

    }


    if (
        data.startDate !== undefined
    ) {

        project.startDate =
            data.startDate;

    }


    if (
        data.endDate !== undefined
    ) {

        project.endDate =
            data.endDate;

    }


    // =================================================
    // PHASES: inside the main project, not overlapping
    // =================================================
    if (newParent !== undefined) {
        const before = project.parentProject ? String(project.parentProject) : null;
        project.parentProject = newParent ? newParent._id : null;
        if (!newParent) project.phaseNumber = null;
        else if (before !== String(newParent._id)) project.phaseNumber = await phases.nextPhaseNumber(newParent._id, organizationId);
    }
    if (project.parentProject) {
        const parent = newParent || await Project.findById(project.parentProject).lean();
        if (parent) await phases.checkPhaseDates({ parent, startDate: project.startDate, endDate: project.endDate, selfId: project._id, organizationId });
    }
    else {
        await phases.assertCoversPhases(project, organizationId);
    }
    // =================================================
    // AUDIT
    // =================================================
    project.updatedBy =
        userId;


    // =================================================
    // SAVE
    // =================================================

    await project.save();


    // =================================================
    // RETURN POPULATED PROJECT
    // =================================================

    return Project.findOne({

        _id:
            project._id,

        organization:
            organizationId

    })

        .populate(
            "program",
            "programCode name"
        )

        .populate(
            "donor",
            "name organizationName"
        )

        .populate(
            "projectManager",
            "name email role status"
        );

};


// =====================================================
// DELETE PROJECT
// =====================================================

const deleteProject = async (
    id,
    organizationId,
    userId
) => {

    if (
        !isValidObjectId(id)
    ) {

        throw new Error(
            "Invalid project ID."
        );

    }


    const projectPhases =
        await phases.phasesOf(id, organizationId);
    if (projectPhases.length) {
        throw new ApiError(
            `This project has ${projectPhases.length} phase${projectPhases.length === 1 ? "" : "s"}. Delete or move the phases first.`,
            409
        );
    }
    const project =
        await Project.findOneAndUpdate(
            {
                _id:
                    id,
                organization:
                    organizationId,
                isDeleted:
                    false
            },
            {
                isDeleted:
                    true,

                deletedAt:
                    new Date(),

                deletedBy:
                    userId

            },

            {

                new:
                    true

            }

        );


    if (!project) {

        throw new Error(
            "Project not found."
        );

    }


    return project;

};


// =====================================================
// PROJECT LOOKUP
// =====================================================

const getProjectLookup =
    async (
        organizationId
    ) => {

        return Project.find({

            organization:
                organizationId,

            isDeleted:
                false

        })

            .select(
                "_id projectCode name program parentProject phaseNumber startDate endDate"
            )

            .sort({

                name:
                    1

            });

    };

// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    createProject,

    getProjects,

    getProjectById,

    updateProject,

    deleteProject,

    getProjectLookup

};