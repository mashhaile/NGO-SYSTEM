const mongoose = require("mongoose");


// =====================================================
// QUERY HELPER
// =====================================================

const queryHelper = async ({
    model,
    organizationId,
    reqQuery = {},
    searchableFields = [],
    populate = null,
    statusConfig = null
}) => {

    // =====================================================
    // PAGINATION
    // =====================================================

    const page =
        Math.max(
            parseInt(reqQuery.page, 10) || 1,
            1
        );

    const limit =
        Math.max(
            parseInt(reqQuery.limit, 10) || 10,
            1
        );

    const skip =
        (page - 1) * limit;


    // =====================================================
    // SEARCH
    // =====================================================

    const search =
        typeof reqQuery.search === "string"
            ? reqQuery.search.trim()
            : "";


    // =====================================================
    // SORT
    // =====================================================

    const sortBy =
        reqQuery.sortBy ||
        "createdAt";

    const order =
        reqQuery.order === "asc"
            ? 1
            : -1;


    // =====================================================
    // BASE FILTER
    // =====================================================

    const baseFilter = {

        organization:
            organizationId,

        isDeleted:
            false

    };


    // =====================================================
    // MAIN FILTER
    // =====================================================

    const filter = {

        ...baseFilter

    };


    // =====================================================
    // QUERY FILTERS
    // =====================================================

    const excludedQueryFields = [

        "page",
        "limit",
        "search",
        "sortBy",
        "order"

    ];


    Object.keys(reqQuery).forEach(
        key => {

            if (
                excludedQueryFields.includes(key)
            ) {

                return;

            }


            const value =
                reqQuery[key];


            // =================================================
            // IGNORE EMPTY VALUES
            // =================================================

            if (
                value === undefined ||
                value === null ||
                value === ""
            ) {

                return;

            }


            // =================================================
            // LOGICAL OPERATORS
            // =================================================

            if (
                key === "$or" ||
                key === "$and"
            ) {

                if (
                    Array.isArray(value)
                ) {

                    filter[key] =
                        value;

                }

                return;

            }


            // =================================================
            // ARRAY FILTER
            // =================================================

            if (
                Array.isArray(value)
            ) {

                const values =
                    value.filter(
                        item =>
                            item !== undefined &&
                            item !== null &&
                            item !== ""
                    );


                if (
                    values.length > 0
                ) {

                    filter[key] = {

                        $in:
                            values

                    };

                }

                return;

            }


            // =================================================
            // COMMA-SEPARATED FILTER
            // =================================================

            if (
                typeof value === "string" &&
                value.includes(",")
            ) {

                const values =
                    value
                        .split(",")
                        .map(
                            item =>
                                item.trim()
                        )
                        .filter(
                            Boolean
                        );


                if (
                    values.length > 1
                ) {

                    filter[key] = {

                        $in:
                            values

                    };

                    return;

                }

            }


            // =================================================
            // NORMAL EXACT FILTER
            // =================================================

            filter[key] =
                value;

        }
    );


    // =====================================================
    // SEARCH
    // =====================================================

    if (
        search &&
        searchableFields.length > 0
    ) {

        const searchConditions = [];


        searchableFields.forEach(
            field => {

                const schemaPath =
                    model.schema.path(field);


                if (
                    !schemaPath
                ) {

                    return;

                }


                // =============================================
                // STRING
                // =============================================

                if (
                    schemaPath.instance === "String"
                ) {

                    searchConditions.push({

                        [field]: {

                            $regex:
                                search,

                            $options:
                                "i"

                        }

                    });

                }


                // =============================================
                // OBJECT ID
                // =============================================

                else if (
                    schemaPath.instance === "ObjectId"
                ) {

                    if (
                        mongoose.Types.ObjectId.isValid(
                            search
                        )
                    ) {

                        searchConditions.push({

                            [field]:
                                new mongoose.Types.ObjectId(
                                    search
                                )

                        });

                    }

                }


                // =============================================
                // NUMBER
                // =============================================

                else if (
                    schemaPath.instance === "Number"
                ) {

                    const number =
                        Number(search);


                    if (
                        !Number.isNaN(number)
                    ) {

                        searchConditions.push({

                            [field]:
                                number

                        });

                    }

                }


                // =============================================
                // BOOLEAN
                // =============================================

                else if (
                    schemaPath.instance === "Boolean"
                ) {

                    const normalized =
                        search.toLowerCase();


                    if (
                        normalized === "true" ||
                        normalized === "false"
                    ) {

                        searchConditions.push({

                            [field]:
                                normalized === "true"

                        });

                    }

                }


                // =============================================
                // DATE
                // =============================================

                else if (
                    schemaPath.instance === "Date"
                ) {

                    const parsedDate =
                        new Date(search);


                    if (
                        !Number.isNaN(
                            parsedDate.getTime()
                        )
                    ) {

                        const startOfDay =
                            new Date(
                                parsedDate
                            );

                        startOfDay.setHours(
                            0,
                            0,
                            0,
                            0
                        );


                        const endOfDay =
                            new Date(
                                parsedDate
                            );

                        endOfDay.setHours(
                            23,
                            59,
                            59,
                            999
                        );


                        searchConditions.push({

                            [field]: {

                                $gte:
                                    startOfDay,

                                $lte:
                                    endOfDay

                            }

                        });

                    }

                }

            }
        );


        // =====================================================
        // APPLY SEARCH
        // =====================================================

        if (
            searchConditions.length > 0
        ) {

            filter.$and = [

                ...(filter.$and || []),

                {

                    $or:
                        searchConditions

                }

            ];

        }

    }


    // =====================================================
    // BUILD QUERY
    // =====================================================

    let query =
        model
            .find(filter)
            .sort({

                [sortBy]:
                    order

            })
            .skip(skip)
            .limit(limit);


    // =====================================================
    // POPULATE
    // =====================================================

    if (
        populate
    ) {

        query =
            query.populate(
                populate
            );

    }


    // =====================================================
    // EXECUTE QUERY
    // =====================================================

    const data =
        await query;


    // =====================================================
    // TOTAL RECORDS
    // =====================================================

    const totalRecords =
        await model.countDocuments(
            filter
        );


 // =====================================================
// STATUS COUNTS
// =====================================================

let totalActive = 0;
let totalInactive = 0;


// =====================================================
// BUILD STATUS COUNT FILTER
// =====================================================
//
// IMPORTANT:
//
// totalRecords:
//     Uses the COMPLETE filter including status.
//
// totalActive / totalInactive:
//     Use the same organization and direct filters,
//     but NEVER use the requested status.
//
// DO NOT copy:
//     status
//     $and
//     $or
//
// This prevents the status counters from being limited
// by the current status/search query.
//
// =====================================================

const statusCountFilter = {

    organization:
        organizationId,

    isDeleted:
        false

};


// =====================================================
// COPY ONLY DIRECT FILTERS
// =====================================================

Object.keys(filter).forEach(
    key => {

        // ---------------------------------------------
        // NEVER COPY STATUS
        // ---------------------------------------------

        if (
            key === "status"
        ) {

            return;

        }


        // ---------------------------------------------
        // NEVER COPY LOGICAL SEARCH CONDITIONS
        // ---------------------------------------------

        if (
            key === "$and" ||
            key === "$or"
        ) {

            return;

        }


        statusCountFilter[key] =
            filter[key];

    }
);


// =====================================================
// DETECT STATUS TYPE
// =====================================================

let statusType =
    statusConfig?.type || null;


if (
    !statusType &&
    model.schema &&
    model.schema.path("status")
) {

    const statusSchemaType =
        model.schema.path("status");


    if (
        statusSchemaType.instance === "String"
    ) {

        statusType =
            "string";

    }
    else if (
        statusSchemaType.instance === "ObjectId"
    ) {

        statusType =
            "lookup";

    }

}


// =====================================================
// STRING STATUS
// =====================================================

if (
    statusType === "string"
) {

    totalActive =
        await model.countDocuments({

            ...statusCountFilter,

            status:
                "Active"

        });


    totalInactive =
        await model.countDocuments({

            ...statusCountFilter,

            status:
                "Inactive"

        });

}


// =====================================================
// LOOKUP STATUS
// =====================================================

else if (
    statusType === "lookup"
) {

    const Lookup =
        require("../models/Lookup");


    const lookupType =
        statusConfig?.lookupType;


    if (
        !lookupType
    ) {

        console.warn(
            `queryHelper: lookup status configured for ${model.modelName}, but lookupType is missing.`
        );

    }
    else {

        // =============================================
        // ACTIVE LOOKUP
        // =============================================

        const activeLookup =
            await Lookup.findOne({

                organization:
                    organizationId,

                type:
                    lookupType,

                $or: [

                    {
                        name:
                            "Active"
                    },

                    {
                        value:
                            "Active"
                    },

                    {
                        code:
                            "ACTIVE"
                    },

                    {
                        code:
                            "Active"
                    }

                ]

            })
            .select("_id")
            .lean();


        // =============================================
        // INACTIVE LOOKUP
        // =============================================

        const inactiveLookup =
            await Lookup.findOne({

                organization:
                    organizationId,

                type:
                    lookupType,

                $or: [

                    {
                        name:
                            "Inactive"
                    },

                    {
                        value:
                            "Inactive"
                    },

                    {
                        code:
                            "INACTIVE"
                    },

                    {
                        code:
                            "Inactive"
                    }

                ]

            })
            .select("_id")
            .lean();


        // =============================================
        // ACTIVE COUNT
        // =============================================

        if (
            activeLookup
        ) {

            totalActive =
                await model.countDocuments({

                    ...statusCountFilter,

                    status:
                        activeLookup._id

                });

        }


        // =============================================
        // INACTIVE COUNT
        // =============================================

        if (
            inactiveLookup
        ) {

            totalInactive =
                await model.countDocuments({

                    ...statusCountFilter,

                    status:
                        inactiveLookup._id

                });

        }

    }

}


// =====================================================
// PAGINATION
// =====================================================

const totalPages =
    Math.ceil(
        totalRecords /
        limit
    );


// =====================================================
// FINAL RESULT
// =====================================================

return {

    data,

    pagination: {

        page,

        limit,

        totalRecords,

        totalActive,

        totalInactive,

        totalPages,

        hasNextPage:
            page <
            totalPages,

        hasPreviousPage:
            page > 1

    }

};


// =====================================================
// CLOSE QUERY HELPER
// =====================================================

};


// =====================================================
// EXPORT
// =====================================================

module.exports =
    queryHelper;