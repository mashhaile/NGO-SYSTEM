const {
    createCustomField,
    getCustomFields,
    getCustomFieldById,
    updateCustomField,
    deleteCustomField
} = require("../services/customFieldService");


// ==========================================
// CREATE CUSTOM FIELD
// ==========================================

const createCustomFieldController = async (
    req,
    res
) => {

    try {

        const field = await createCustomField(
            req.body,
            req.user.organizationId,
            req.user.userId
        );

        res.status(201).json({

            success: true,

            message: "Custom field created successfully",

            data: field

        });

    }
    catch (error) {

        res.status(400).json({

            success: false,

            message: error.message

        });

    }

};


// ==========================================
// GET CUSTOM FIELDS BY MODULE
// ==========================================

const getCustomFieldsController = async (
    req,
    res
) => {

    try {

        const fields = await getCustomFields(

            req.user.organizationId,

            req.params.module

        );

        res.json({

            success: true,

            message: "Custom fields fetched successfully",

            data: fields

        });

    }
    catch (error) {

        res.status(500).json({

            success: false,

            message: error.message

        });

    }

};


// ==========================================
// GET CUSTOM FIELD BY ID
// ==========================================

const getCustomFieldByIdController = async (
    req,
    res
) => {

    try {

        const field = await getCustomFieldById(

            req.params.id,

            req.user.organizationId

        );

        if (!field) {

            return res.status(404).json({

                success: false,

                message: "Custom field not found"

            });

        }

        res.json({

            success: true,

            message: "Custom field fetched successfully",

            data: field

        });

    }
    catch (error) {

        res.status(500).json({

            success: false,

            message: error.message

        });

    }

};


// ==========================================
// UPDATE CUSTOM FIELD
// ==========================================

const updateCustomFieldController = async (
    req,
    res
) => {

    try {

        const field = await updateCustomField(

            req.params.id,

            req.body,

            req.user.organizationId,

            req.user.userId

        );

        res.json({

            success: true,

            message: "Custom field updated successfully",

            data: field

        });

    }
    catch (error) {

        res.status(400).json({

            success: false,

            message: error.message

        });

    }

};


// ==========================================
// DELETE CUSTOM FIELD
// ==========================================

const deleteCustomFieldController = async (
    req,
    res
) => {

    try {

        await deleteCustomField(

            req.params.id,

            req.user.organizationId

        );

        res.json({

            success: true,

            message: "Custom field deleted successfully"

        });

    }
    catch (error) {

        res.status(400).json({

            success: false,

            message: error.message

        });

    }

};


// ==========================================
// EXPORT
// ==========================================

module.exports = {

    createCustomFieldController,

    getCustomFieldsController,

    getCustomFieldByIdController,

    updateCustomFieldController,

    deleteCustomFieldController

};
