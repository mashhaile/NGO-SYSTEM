import {
    useCallback,
    useMemo
} from "react";


import {
    Box,
    Autocomplete,
    TextField
} from "@mui/material";


import {
    PageCard,
    FormSection,
    FormGrid,
    FormActions,
    AppTextField,
    AppSelect,
    AppDatePicker,
    AppButton
} from "../../../components/ui";


import ServiceDeliveryItems
    from "./serviceDeliveryItems";


import LocationCascadeFields
    from "../../locations/components/LocationCascadeFields";


import ServiceDeliveryAllocations
    from "./serviceDeliveryAllocations";

import { dayOf, rangeHint } from "../../../utils/date";
import { useModuleOn } from "../../../utils/modules";


// =====================================================
// OBJECT ID DETECTION
// =====================================================

const isObjectIdLike = (
    value
) => {

    return (
        typeof value === "string" &&
        /^[a-fA-F0-9]{24}$/.test(
            value
        )
    );

};


// =====================================================
// NORMALIZE LOOKUP VALUE
// =====================================================

const normalizeLookupValue = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "object"
    ) {

        if (
            value?.beneficiary
        ) {

            return normalizeLookupValue(
                value.beneficiary
            );

        }


        if (
            value?._id !== undefined &&
            value?._id !== null &&
            value?._id !== ""
        ) {

            return String(
                value._id
            );

        }


        if (
            value?.id !== undefined &&
            value?.id !== null &&
            value?.id !== ""
        ) {

            return String(
                value.id
            );

        }


        if (
            value?.value !== undefined &&
            value?.value !== null &&
            value?.value !== ""
        ) {

            if (
                typeof value.value === "object"
            ) {

                return normalizeLookupValue(
                    value.value
                );

            }


            return String(
                value.value
            );

        }


        return "";

    }


    return String(
        value
    );

};


// =====================================================
// NORMALIZE LOOKUP LABEL
// =====================================================

const normalizeLookupLabel = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "object"
    ) {

        if (
            value?.label !== undefined &&
            value?.label !== null &&
            value?.label !== ""
        ) {

            return String(
                value.label
            );

        }


        if (
            value?.name !== undefined &&
            value?.name !== null &&
            value?.name !== ""
        ) {

            return String(
                value.name
            );

        }


        if (
            value?.text !== undefined &&
            value?.text !== null &&
            value?.text !== ""
        ) {

            return String(
                value.text
            );

        }


        if (
            value?.value !== undefined &&
            value?.value !== null &&
            value?.value !== ""
        ) {

            if (
                typeof value.value === "object"
            ) {

                return normalizeLookupLabel(
                    value.value
                );

            }


            const primitiveValue =
                String(
                    value.value
                );


            if (
                !isObjectIdLike(
                    primitiveValue
                )
            ) {

                return primitiveValue;

            }

        }


        return "";

    }


    const primitiveValue =
        String(
            value
        );


    if (
        isObjectIdLike(
            primitiveValue
        )
    ) {

        return "";

    }


    return primitiveValue;

};


// =====================================================
// NORMALIZE LOOKUP CODE
// =====================================================

const normalizeLookupCode = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "object"
    ) {

        if (
            value?.code !== undefined &&
            value?.code !== null &&
            value?.code !== ""
        ) {

            return String(
                value.code
            );

        }


        if (
            value?.unitCode !== undefined &&
            value?.unitCode !== null &&
            value?.unitCode !== ""
        ) {

            return String(
                value.unitCode
            );

        }


        if (
            value?.lookupCode !== undefined &&
            value?.lookupCode !== null &&
            value?.lookupCode !== ""
        ) {

            return String(
                value.lookupCode
            );

        }


        if (
            value?.value !== undefined &&
            typeof value.value === "object"
        ) {

            return normalizeLookupCode(
                value.value
            );

        }


        return "";

    }


    return "";

};


// =====================================================
// NORMALIZE LOOKUP SEMANTIC TYPE
// =====================================================

const normalizeSemanticType = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "object"
    ) {

        if (
            value?.semanticType !== undefined &&
            value?.semanticType !== null &&
            value?.semanticType !== ""
        ) {

            return String(
                value.semanticType
            ).toLowerCase();

        }


        if (
            value?.metadata?.semanticType !== undefined &&
            value?.metadata?.semanticType !== null &&
            value?.metadata?.semanticType !== ""
        ) {

            return String(
                value.metadata.semanticType
            ).toLowerCase();

        }


        if (
            value?.value !== undefined &&
            typeof value.value === "object"
        ) {

            return normalizeSemanticType(
                value.value
            );

        }


        return "";

    }


    return String(
        value
    ).toLowerCase();

};


// =====================================================
// NORMALIZE LOOKUP OPTIONS
// =====================================================

const normalizeOptions = (
    items
) => {

    if (
        !Array.isArray(
            items
        )
    ) {

        return [];

    }


    const normalized = [];


    items.forEach(
        (item) => {

            if (
                !item ||
                item?.active === false
            ) {

                return;

            }


            const source =
                item;


            const rawValue =
                source?.value !== undefined &&
                source?.value !== null &&
                typeof source.value === "object"
                    ? source.value
                    : source;


            const id =
                normalizeLookupValue(
                    source?._id ??
                    source?.id ??
                    (
                        typeof source?.value !== "object"
                            ? source?.value
                            : undefined
                    ) ??
                    rawValue
                );


            const label =
                normalizeLookupLabel(
                    source
                ) ||
                normalizeLookupLabel(
                    rawValue
                );


            if (
                !id ||
                !label
            ) {

                return;

            }


            const code =
                normalizeLookupCode(
                    source
                ) ||
                normalizeLookupCode(
                    rawValue
                );


            const semanticType =
                normalizeSemanticType(
                    source
                ) ||
                normalizeSemanticType(
                    rawValue
                );


            const normalizedOption = {

                ...source,

                value:
                    String(
                        id
                    ),

                label:
                    String(
                        label
                    ),

                _id:
                    String(
                        id
                    ),

                id:
                    String(
                        id
                    ),

                code,

                unitCode:
                    source?.unitCode ??
                    rawValue?.unitCode ??
                    code,

                lookupCode:
                    source?.lookupCode ??
                    rawValue?.lookupCode ??
                    code,

                semanticType,

                original:
                    source

            };


            normalized.push(
                normalizedOption
            );

        }
    );


    const seen =
        new Set();


    return normalized.filter(
        (option) => {

            const key =
                String(
                    option.value
                );


            if (
                seen.has(
                    key
                )
            ) {

                return false;

            }


            seen.add(
                key
            );


            return true;

        }
    );

};


// =====================================================
// GET RELATED ID
// =====================================================

const getRelatedId = (
    item,
    field
) => {

    if (
        !item
    ) {

        return "";

    }


    return normalizeLookupValue(
        item?.[field]
    );

};


// =====================================================
// NORMALIZE BENEFICIARY RECORD
// =====================================================

const normalizeBeneficiaryRecord = (
    value
) => {

    if (
        value === undefined ||
        value === null ||
        value === ""
    ) {

        return null;

    }


    if (
        typeof value === "string"
    ) {

        return {

            beneficiary:
                value,

            enrollment:
                null,

            status:
                "Received",

            quantity:
                null,

            remarks:
                "",

            allocations:
                []

        };

    }


    const beneficiaryId =
        normalizeLookupValue(
            value?.beneficiary ??
            value
        );


    if (
        !beneficiaryId
    ) {

        return null;

    }


    const allocations =
        Array.isArray(
            value?.allocations
        )
            ? value.allocations
                .map(
                    (allocation) => {

                        if (
                            !allocation
                        ) {

                            return null;

                        }


                        // ---------------------------------
                        // SERVICE ITEM ID
                        // ---------------------------------

                        const serviceItem =
                            normalizeLookupValue(
                                allocation?.serviceItem
                            );


                        if (
                            !serviceItem
                        ) {

                            return null;

                        }


                        // ---------------------------------
                        // DETAIL ITEM ID
                        //
                        // IMPORTANT:
                        // Preserve detailItem so that
                        // beneficiary allocations can be
                        // attached to supporting detail
                        // items instead of only the parent
                        // service item.
                        // ---------------------------------

                        const detailItem =
                            normalizeLookupValue(
                                allocation?.detailItem
                            ) || null;


                        // ---------------------------------
                        // ALLOCATION VALUES
                        // ---------------------------------

                        const quantity =
                            Number(
                                allocation?.quantity ?? 0
                            );


                        const allocatedValue =
                            Number(
                                allocation?.allocatedValue ?? 0
                            );


                        return {

                            serviceItem,

                            detailItem,

                            quantity:
                                Number.isFinite(
                                    quantity
                                )
                                    ? quantity
                                    : 0,

                            allocatedValue:
                                Number.isFinite(
                                    allocatedValue
                                )
                                    ? allocatedValue
                                    : 0,

                            remarks:
                                typeof allocation?.remarks ===
                                "string"
                                    ? allocation.remarks
                                    : ""

                        };

                    }
                )
                .filter(
                    Boolean
                )
            : [];


    const rawQuantity =
        value?.quantity;


    const quantity =
        rawQuantity === undefined ||
        rawQuantity === null ||
        rawQuantity === ""
            ? null
            : Number(
                rawQuantity
            );


    return {

        beneficiary:
            beneficiaryId,

        enrollment:
            normalizeLookupValue(
                value?.enrollment
            ) || null,

        status:
            value?.status ||
            "Received",

        quantity:
            Number.isFinite(
                quantity
            )
                ? quantity
                : null,

        remarks:
            value?.remarks ||
            "",

        allocations

    };

};


// =====================================================
// NORMALIZE ALLOCATION BEHAVIOR
// =====================================================

const normalizeAllocationBehavior = (
    value
) => {

    const normalized =
        String(
            value ||
            ""
        )
            .trim()
            .toUpperCase();


    if (
        normalized ===
        "PARTICIPATION"
    ) {

        return "PARTICIPATION";

    }


    return "CONSUMPTION";

};


// =====================================================
// SERVICE DELIVERY FORM
// =====================================================

const ServiceDeliveryForm = ({

    formData,

    setFormData,

    beneficiaries = [],

    programs = [],

    projects = [],

    activities = [],

    activityRuns = [],

    serviceCategories = [],

    units = [],

    onSubmit,

    onProgramChange,

    loading = false

}) => {


    // =================================================
    // SAFE VALUES
    // =================================================

    const programValue =
        normalizeLookupValue(
            formData?.program
        );


    const projectValue =
        normalizeLookupValue(
            formData?.project
        );


    const activityValue =
        normalizeLookupValue(
            formData?.activity
        );


    const activityRunValue =
        normalizeLookupValue(
            formData?.activityRun
        );


    const recipientType =
        formData?.recipientType ||
        "Individual";


    const recipientName =
        typeof formData?.recipientName ===
        "string"
            ? formData.recipientName
            : "";


    const requiresRecipientName =
        recipientType ===
            "Household" ||
        recipientType ===
            "Group / Community" ||
        recipientType ===
            "Institution";


    // =================================================
    // ALLOWED ALLOCATION METHODS
    // =================================================

    const allowedAllocationMethods =
        useMemo(
            () => {

                switch (
                    recipientType
                ) {

                    case "Individual":

                        return [
                            {
                                value:
                                    "Individual",
                                label:
                                    "Individual"
                            },
                            {
                                value:
                                    "Shared",
                                label:
                                    "Shared"
                            }
                        ];


                    // a household, group or institution receives as a
                    // whole (the server applies the same rule)
                    case "Household":
                        return [
                            {
                                value:
                                    "Group",
                                label:
                                    "To the household as a whole"
                            }
                        ];
                    case "Group / Community":
                        return [
                            {
                                value:
                                    "Group",
                                label:
                                    "To the group as a whole"
                            }
                        ];
                    case "Institution":
                        return [
                            {
                                value:
                                    "Unallocated",
                                label:
                                    "To the institution as a whole"
                            }
                        ];
                    default:

                        return [];

                }

            },
            [
                recipientType
            ]
        );


    // =================================================
    // SAFE / VALID ALLOCATION METHOD
    // =================================================

    const allowedAllocationValues =
        useMemo(
            () =>
                allowedAllocationMethods.map(
                    (option) =>
                        option.value
                ),
            [
                allowedAllocationMethods
            ]
        );


    const defaultAllocationMethod =
        allowedAllocationMethods[0]?.value ||
        "";


    const allocationMethod =
        allowedAllocationValues.includes(
            formData?.allocationMethod
        )
            ? formData.allocationMethod
            : defaultAllocationMethod;


    // =================================================
    // NORMALIZED UNIT OPTIONS
    // =================================================

    const unitOptions =
        useMemo(
            () =>
                normalizeOptions(
                    units
                ),
            [
                units
            ]
        );


    // =================================================
    // SERVICE CATEGORY OPTIONS
    // =================================================

    const serviceCategoryOptions =
        useMemo(
            () =>
                normalizeOptions(
                    serviceCategories
                ),
            [
                serviceCategories
            ]
        );


    // =================================================
    // FILTER PROJECTS BY PROGRAM
    // =================================================

    const filteredProjects =
        useMemo(
            () => {

                if (
                    !programValue
                ) {

                    return [];

                }


                return (
                    Array.isArray(
                        projects
                    )
                        ? projects
                        : []
                ).filter(
                    (project) => {

                        const projectProgram =
                            getRelatedId(
                                project,
                                "program"
                            );


                        return (
                            projectProgram ===
                            programValue
                        );

                    }
                );

            },
            [
                projects,
                programValue
            ]
        );


    // =================================================
    // FILTER ACTIVITIES BY PROJECT
    // =================================================

    const filteredActivities =
        useMemo(
            () => {

                if (
                    !projectValue
                ) {

                    return [];

                }


                return (
                    Array.isArray(
                        activities
                    )
                        ? activities
                        : []
                ).filter(
                    (activity) => {

                        const activityProject =
                            getRelatedId(
                                activity,
                                "project"
                            );


                        return (
                            activityProject ===
                            projectValue
                        );

                    }
                );

            },
            [
                activities,
                projectValue
            ]
        );


    // =================================================
    // FILTER ACTIVITY RUNS BY ACTIVITY
    // =================================================

    const filteredActivityRuns =
        useMemo(
            () => {

                if (
                    !activityValue
                ) {

                    return [];

                }


                return (
                    Array.isArray(
                        activityRuns
                    )
                        ? activityRuns
                        : []
                ).filter(
                    (activityRun) => {

                        const runActivity =
                            getRelatedId(
                                activityRun,
                                "activity"
                            );


                        return (
                            runActivity ===
                            activityValue
                        );

                    }
                );

            },
            [
                activityRuns,
                activityValue
            ]
        );


    // =================================================
    // BENEFICIARY OPTIONS
    // =================================================

    const beneficiaryOptions =
        useMemo(
            () => {

                if (
                    !Array.isArray(
                        beneficiaries
                    )
                ) {

                    return [];

                }


                const options =
                    beneficiaries
                        .map(
                            (record) => {

                                if (
                                    !record
                                ) {

                                    return null;

                                }


                                const nestedBeneficiary =
                                    record?.beneficiary &&
                                    typeof record.beneficiary === "object"
                                        ? record.beneficiary
                                        : null;


                                const beneficiaryId =
                                    nestedBeneficiary?._id ??
                                    nestedBeneficiary?.id ??
                                    (
                                        typeof record?.beneficiary === "string"
                                            ? record.beneficiary
                                            : null
                                    ) ??
                                    (
                                        typeof record?.beneficiary === "object"
                                            ? null
                                            : record?.beneficiary
                                    ) ??
                                    record?.beneficiaryId ??
                                    record?.value ??
                                    record?.id ??
                                    record?._id ??
                                    "";


                                const normalizedId =
                                    normalizeLookupValue(
                                        beneficiaryId
                                    );


                                if (
                                    !normalizedId
                                ) {

                                    return null;

                                }


                                const fullName =
                                    nestedBeneficiary?.fullName ||
                                    record?.fullName ||
                                    [
                                        nestedBeneficiary?.firstName ||
                                            record?.firstName,
                                        nestedBeneficiary?.middleName ||
                                            record?.middleName,
                                        nestedBeneficiary?.lastName ||
                                            record?.lastName
                                    ]
                                        .filter(Boolean)
                                        .join(" ");


                                const label =
                                    fullName ||
                                    nestedBeneficiary?.beneficiaryNumber ||
                                    record?.beneficiaryNumber ||
                                    nestedBeneficiary?.name ||
                                    record?.name ||
                                    record?.label ||
                                    "";


                                if (
                                    !label
                                ) {

                                    return null;

                                }


                                const enrollmentId =
                                    normalizeLookupValue(
                                        record?.enrollment
                                    ) ||
                                    (
                                        record?.enrollment?._id
                                            ? String(
                                                record.enrollment._id
                                            )
                                            : null
                                    ) ||
                                    null;


                                return {

                                    value:
                                        String(
                                            normalizedId
                                        ),

                                    label:
                                        String(
                                            label
                                        ),

                                    _id:
                                        String(
                                            normalizedId
                                        ),

                                    id:
                                        String(
                                            normalizedId
                                        ),

                                    enrollment:
                                        enrollmentId,

                                    original:
                                        record

                                };

                            }
                        )
                        .filter(
                            Boolean
                        );


                const seen =
                    new Set();


                return options.filter(
                    (option) => {

                        const id =
                            String(
                                option.value
                            );


                        if (
                            seen.has(
                                id
                            )
                        ) {

                            return false;

                        }


                        seen.add(
                            id
                        );


                        return true;

                    }
                );

            },
            [
                beneficiaries
            ]
        );


    // =================================================
    // SELECTED BENEFICIARIES
    //
    // IMPORTANT:
    // Do NOT keep a second local state copy.
    // formData.beneficiaries is the single source
    // of truth for the Autocomplete.
    // =================================================

    const selectedBeneficiaryOptions =
        useMemo(
            () => {

                const records =
                    Array.isArray(
                        formData?.beneficiaries
                    )
                        ? formData.beneficiaries
                        : [];


                if (
                    records.length === 0
                ) {

                    return [];

                }


                return records
                    .map(
                        (record) => {

                            const normalized =
                                normalizeBeneficiaryRecord(
                                    record
                                );


                            if (
                                !normalized?.beneficiary
                            ) {

                                return null;

                            }


                            const beneficiaryId =
                                String(
                                    normalized.beneficiary
                                );


                            const existingOption =
                                beneficiaryOptions.find(
                                    (option) =>
                                        String(
                                            option?.value
                                        ) ===
                                        beneficiaryId
                                );


                            if (
                                existingOption
                            ) {

                                return existingOption;

                            }


                            // Keep the selected beneficiary visible
                            // even while the lookup list is loading.
                            return {

                                value:
                                    beneficiaryId,

                                label:
                                    beneficiaryId,

                                _id:
                                    beneficiaryId,

                                id:
                                    beneficiaryId,

                                enrollment:
                                    normalized.enrollment ||
                                    null,

                                original:
                                    record

                            };

                        }
                    )
                    .filter(
                        Boolean
                    );

            },
            [
                formData?.beneficiaries,
                beneficiaryOptions
            ]
        );


    // =================================================
    // PROGRAM OPTIONS
    // =================================================

    const programOptions =
        useMemo(
            () => {

                if (
                    !Array.isArray(
                        programs
                    )
                ) {

                    return [];

                }


                return programs
                    .map(
                        (program) => {

                            const value =
                                normalizeLookupValue(
                                    program?._id ??
                                    program?.id ??
                                    program?.value
                                );


                            const label =
                                normalizeLookupLabel(
                                    program
                                ) ||
                                normalizeLookupLabel(
                                    program?.value
                                );


                            return {

                                value,

                                label

                            };

                        }
                    )
                    .filter(
                        (option) =>
                            option.value &&
                            option.label
                    );

            },
            [
                programs
            ]
        );


    // the activity / run fields belong to the activities module
    const activitiesOn = useModuleOn("activities");


    // a delivery under a project is dated inside it: its
    // dates are shown under the delivery date
    const projectForDates =
        projectValue
            ? (Array.isArray(projects) ? projects : []).find(project => String(project?._id || project?.id) === String(projectValue)) || null
            : null;


    // =================================================
    // PROJECT OPTIONS
    // =================================================

    const projectOptions =
        useMemo(
            () =>
                filteredProjects
                    .map(
                        (project) => {

                            const value =
                                normalizeLookupValue(
                                    project?._id ??
                                    project?.id ??
                                    project?.value
                                );


                            const label =
                                normalizeLookupLabel(
                                    project
                                ) ||
                                normalizeLookupLabel(
                                    project?.value
                                );


                            return {

                                value,

                                label

                            };

                        }
                    )
                    .filter(
                        (option) =>
                            option.value &&
                            option.label
                    ),
            [
                filteredProjects
            ]
        );


    // =================================================
    // ACTIVITY OPTIONS
    // =================================================

    const activityOptions =
        useMemo(
            () =>
                filteredActivities
                    .map(
                        (activity) => {

                            const value =
                                normalizeLookupValue(
                                    activity?._id ??
                                    activity?.id ??
                                    activity?.value
                                );


                            const label =
                                normalizeLookupLabel(
                                    activity
                                ) ||
                                normalizeLookupLabel(
                                    activity?.value
                                );


                            return {

                                value,

                                label

                            };

                        }
                    )
                    .filter(
                        (option) =>
                            option.value &&
                            option.label
                    ),
            [
                filteredActivities
            ]
        );


    // =================================================
    // ACTIVITY RUN OPTIONS
    // =================================================

    const activityRunOptions =
        useMemo(
            () =>
                filteredActivityRuns
                    .map(
                        (activityRun) => {

                            const value =
                                normalizeLookupValue(
                                    activityRun?._id ??
                                    activityRun?.id ??
                                    activityRun?.value
                                );


                            const label =
                                normalizeLookupLabel(
                                    activityRun
                                ) ||
                                normalizeLookupLabel(
                                    activityRun?.runCode
                                ) ||
                                normalizeLookupLabel(
                                    activityRun?.value
                                );


                            return {

                                value,

                                label

                            };

                        }
                    )
                    .filter(
                        (option) =>
                            option.value &&
                            option.label
                    ),
            [
                filteredActivityRuns
            ]
        );


    // =================================================
    // FIELD CHANGE
    // =================================================

    const handleChange = (
        field,
        value
    ) => {

        setFormData(
            (prev) => ({

                ...prev,

                [field]:
                    value

            })
        );

    };


    // Location cascade: several fields at once.

    const handleLocationChange = useCallback(
        (patch) => {

            setFormData(
                (prev) => ({
                    ...prev,
                    ...patch
                })
            );

        },
        [setFormData]
    );


    // =====================================================
    // RECIPIENT TYPE CHANGE
    // =====================================================

    const handleRecipientTypeChange = (
        value
    ) => {

        const nextRecipientType =
            value ||
            "Individual";


        let nextAllocationMethod;


        switch (
            nextRecipientType
        ) {

            case "Individual":

                nextAllocationMethod =
                    "Individual";

                break;


            case "Household":

                nextAllocationMethod =
                    "Group";

                break;


            case "Group / Community":

                nextAllocationMethod =
                    "Group";

                break;


            case "Institution":

                nextAllocationMethod =
                    "Unallocated";

                break;


            default:

                nextAllocationMethod =
                    "Individual";

        }


        setFormData(
            (prev) => {

                const currentRecipientType =
                    prev?.recipientType ||
                    "Individual";


                const currentAllocationMethod =
                    prev?.allocationMethod ||
                    "";


                const recipientChanged =
                    currentRecipientType !==
                    nextRecipientType;


                const allocationChanged =
                    currentAllocationMethod !==
                    nextAllocationMethod;


                if (
                    !recipientChanged &&
                    !allocationChanged
                ) {

                    return prev;

                }


                return {

                    ...prev,

                    recipientType:
                        nextRecipientType,

                    recipientName:
                        recipientChanged
                            ? ""
                            : prev?.recipientName || "",

                    allocationMethod:
                        nextAllocationMethod,

                    // Always clear beneficiary-specific
                    // values when recipient/allocation changes.
                    beneficiaries:
                        [],

                    beneficiary:
                        "",

                    enrollment:
                        null

                };

            }
        );

    };


    // =====================================================
    // ALLOCATION METHOD CHANGE
    // =====================================================

    const handleAllocationMethodChange = (
        value
    ) => {

        const nextAllocationMethod =
            value ||
            "";


        if (
            !allowedAllocationValues.includes(
                nextAllocationMethod
            )
        ) {

            return;

        }


        setFormData(
            (prev) => {

                const currentAllocationMethod =
                    prev?.allocationMethod ||
                    "";


                if (
                    currentAllocationMethod ===
                    nextAllocationMethod
                ) {

                    return prev;

                }


                return {

                    ...prev,

                    allocationMethod:
                        nextAllocationMethod,

                    beneficiaries:
                        [],

                    beneficiary:
                        "",

                    enrollment:
                        null

                };

            }
        );

    };


    // =====================================================
    // BENEFICIARY CHANGE
    // =====================================================

    const handleBeneficiaryChange = (
        _event,
        selectedOptions
    ) => {

        const selected =
            Array.isArray(
                selectedOptions
            )
                ? selectedOptions
                : [];


        setFormData(
            (prev) => {

                const existingRecords =
                    Array.isArray(
                        prev?.beneficiaries
                    )
                        ? prev.beneficiaries
                        : [];


                const existingMap =
                    new Map();


                existingRecords.forEach(
                    (item) => {

                        const record =
                            normalizeBeneficiaryRecord(
                                item
                            );


                        if (
                            record?.beneficiary
                        ) {

                            existingMap.set(
                                String(
                                    record.beneficiary
                                ),
                                record
                            );

                        }

                    }
                );


                const normalized =
                    selected
                        .map(
                            (option) => {

                                const id =
                                    normalizeLookupValue(
                                        option?.value ??
                                        option?._id ??
                                        option?.id
                                    );


                                if (
                                    !id
                                ) {

                                    return null;

                                }


                                const existing =
                                    existingMap.get(
                                        String(
                                            id
                                        )
                                    );


                                if (
                                    existing
                                ) {

                                    // IMPORTANT:
                                    // Keep existing allocations intact,
                                    // including detailItem allocations.
                                    return existing;

                                }


                                return {

                                    beneficiary:
                                        String(
                                            id
                                        ),

                                    enrollment:
                                        normalizeLookupValue(
                                            option?.enrollment
                                        ) || null,

                                    status:
                                        "Received",

                                    quantity:
                                        null,

                                    remarks:
                                        "",

                                    allocations:
                                        []

                                };

                            }
                        )
                        .filter(
                            Boolean
                        );


                return {

                    ...prev,

                    beneficiaries:
                        normalized

                };

            }
        );

    };


    // =================================================
    // PROGRAM CHANGE
    // =================================================

    const handleProgramChange = (
        value
    ) => {

        const programId =
            normalizeLookupValue(
                value
            );


        setFormData(
            (prev) => ({

                ...prev,

                program:
                    programId,

                beneficiaries:
                    [],

                beneficiary:
                    "",

                enrollment:
                    null,

                project:
                    "",

                activity:
                    "",

                activityRun:
                    ""

            })
        );


        if (
            typeof onProgramChange ===
            "function"
        ) {

            onProgramChange(
                programId
            );

        }

    };


    // =================================================
    // PROJECT CHANGE
    // =================================================

    const handleProjectChange = (
        value
    ) => {

        const projectId =
            normalizeLookupValue(
                value
            );


        setFormData(
            (prev) => ({

                ...prev,

                project:
                    projectId,

                activity:
                    "",

                activityRun:
                    ""

            })
        );

    };


    // =================================================
    // ACTIVITY CHANGE
    // =================================================

    const handleActivityChange = (
        value
    ) => {

        const activityId =
            normalizeLookupValue(
                value
            );


        setFormData(
            (prev) => ({

                ...prev,

                activity:
                    activityId,

                activityRun:
                    ""

            })
        );

    };


    // =================================================
    // SUBMIT
    // =================================================

    const submitHandler = async (
        event
    ) => {

        event?.preventDefault?.();


        // =====================================================
        // SAFE ITEMS
        // =====================================================

        const items =
            Array.isArray(
                formData?.items
            )
                ? formData.items
                : [];


        // =====================================================
        // VALIDATION
        // =====================================================

        // =====================================================
        // MANDATORY FIELDS
        //
        // Everything missing is listed at once, so Save never
        // just does nothing.
        // =====================================================

        const missing = [];

        const filled = (value) =>
            Boolean(
                normalizeLookupValue(value)
            );

        const positive = (value) =>
            value !== "" &&
            value !== null &&
            value !== undefined &&
            Number.isFinite(Number(value)) &&
            Number(value) > 0;

        if (!formData?.recipientType) missing.push("Recipient Type");
        if (!formData?.allocationMethod) missing.push("Allocation Method");
        if (!filled(formData?.program)) missing.push("Program");
        if (!formData?.deliveryDate) missing.push("Service Delivery Date");

        if (
            requiresRecipientName &&
            !String(formData?.recipientName || "").trim()
        ) {
            missing.push("Recipient Name");
        }

        if (
            formData?.recipientType === "Individual" &&
            formData?.allocationMethod !== "Unallocated" &&
            !(Array.isArray(formData?.beneficiaries) && formData.beneficiaries.length)
        ) {
            missing.push("Beneficiaries (at least one person)");
        }

        if (items.length === 0) {
            missing.push("At least one service item");
        }

        items.forEach((item, index) => {

            const label = `Service Item ${index + 1}`;

            if (!filled(item?.serviceCategory)) missing.push(`${label}: Service Category`);
            if (!filled(item?.serviceType)) missing.push(`${label}: Service Type`);
            if (!positive(item?.quantity)) missing.push(`${label}: Quantity (more than 0)`);
            if (!filled(item?.unit)) missing.push(`${label}: Unit`);

            if (
                item?.unitCost === "" ||
                item?.unitCost === null ||
                item?.unitCost === undefined ||
                !Number.isFinite(Number(item.unitCost)) ||
                Number(item.unitCost) < 0
            ) {
                missing.push(`${label}: Unit Cost`);
            }

            (Array.isArray(item?.detailItems) ? item.detailItems : []).forEach((detail, detailIndex) => {
                const detailLabel = `${label}, Detail Item ${detailIndex + 1}`;
                if (!String(detail?.name || "").trim()) missing.push(`${detailLabel}: Name`);
                if (!positive(detail?.quantity)) missing.push(`${detailLabel}: Quantity (more than 0)`);
                if (!filled(detail?.unit)) missing.push(`${detailLabel}: Unit`);
                if (normalizeLookupValue(detail?.allocationUnit) && !positive(detail?.allocationConversionFactor)) {
                    missing.push(`${detailLabel}: conversion (more than 0)`);
                }
            });

        });

        if (
            missing.length > 0
        ) {

            window.alert(
                "Please complete these required fields:\n\n- " +
                missing.join("\n- ")
            );

            return;

        }


        if (
            !formData?.recipientType
        ) {

            return;

        }


        if (
            formData?.recipientType === "Individual" &&
            (
                !Array.isArray(
                    beneficiaries
                ) ||
                beneficiaries.length === 0
            )
        ) {

            return;

        }


        if (
            items.length === 0
        ) {

            return;

        }


        // Individual allocation: everyone gets their own share
        // (the server refuses it otherwise)
        if (
            formData?.recipientType === "Individual" &&
            formData?.allocationMethod === "Individual" &&
            Array.isArray(
                formData?.beneficiaries
            )
        ) {

            // The people on THIS delivery (the beneficiaries
            // prop is the whole picker list)
            const chosen =
                formData.beneficiaries;

            const withoutShare =
                chosen.filter(
                    beneficiary =>
                        !(Array.isArray(beneficiary?.allocations) ? beneficiary.allocations : [])
                            .some(
                                allocation =>
                                    Number(allocation?.quantity || 0) > 0 ||
                                    Number(allocation?.allocatedValue || 0) > 0
                            )
                );

            if (
                withoutShare.length > 0
            ) {

                window.alert(
                    `With individual allocation every beneficiary needs a share: ${withoutShare.length} of ${chosen.length} have none.\n\n` +
                    "Give them a share, or choose shared allocation."
                );

                return;

            }

            // Money (cash, fees) is shared out in full; goods
            // may have stock left over
            for (
                const [itemIndex, item] of items.entries()
            ) {

                const unit =
                    unitOptions.find(
                        option =>
                            String(option?.value) ===
                            String(normalizeLookupValue(item?.unit))
                    );

                const isMoney =
                    unit?.semanticType === "monetary" ||
                    ["ETB", "BIRR", "USD", "EUR"].includes(
                        String(unit?.code || unit?.label || "").toUpperCase()
                    );

                if (!isMoney) continue;

                const itemId =
                    String(normalizeLookupValue(item?._id ?? item?.id));

                const cost =
                    Number(item?.quantity || 0) *
                    Number(item?.unitCost || 0);

                const given =
                    chosen.reduce(
                        (sum, beneficiary) =>
                            sum +
                            (Array.isArray(beneficiary?.allocations) ? beneficiary.allocations : [])
                                .filter(allocation => String(normalizeLookupValue(allocation?.serviceItem)) === itemId)
                                .reduce((total, allocation) => total + Number(allocation?.allocatedValue || 0), 0),
                        0
                    );

                if (
                    Math.abs(cost - given) > 0.01
                ) {

                    const amount = (value) =>
                        value.toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 });

                    window.alert(
                        `Service Item ${itemIndex + 1} is ${amount(cost)} in money, but the shares add up to ${amount(given)}.\n\n` +
                        `With individual allocation the whole amount must be shared out (${amount(cost - given)} is left with no one).`
                    );

                    return;

                }

            }

        }


        for (
            const item of items
        ) {

            if (
                !item?.serviceCategory ||
                !item?.serviceType ||
                !item?.unit
            ) {

                return;

            }


            const quantity =
                Number(
                    item?.quantity ??
                    0
                );


            if (
                !Number.isFinite(
                    quantity
                ) ||
                quantity <= 0
            ) {

                return;

            }


            const unitCost =
                Number(
                    item?.unitCost ??
                    0
                );


            if (
                !Number.isFinite(
                    unitCost
                ) ||
                unitCost < 0
            ) {

                return;

            }

        }


        // =====================================================
        // DETAIL ITEM VALIDATION
        //
        // IMPORTANT BUSINESS RULE:
        //
        // The combined value of detail items belonging
        // to one parent service item must NEVER exceed
        // the parent service item's actual total cost.
        //
        // Parent total:
        // quantity × unitCost
        //
        // Detail total:
        // quantity × unitCost
        //
        // Detail totals may be less than the parent total.
        // They do NOT have to equal the parent total.
        // =====================================================

        for (
            let itemIndex = 0;
            itemIndex < items.length;
            itemIndex += 1
        ) {

            const item =
                items[itemIndex];


            const parentQuantity =
                Number(
                    item?.quantity ??
                    0
                );


            const parentUnitCost =
                Number(
                    item?.unitCost ??
                    0
                );


            const parentTotal =
                (
                    Number.isFinite(
                        parentQuantity
                    ) &&
                    parentQuantity > 0
                        ? parentQuantity
                        : 0
                ) *
                (
                    Number.isFinite(
                        parentUnitCost
                    ) &&
                    parentUnitCost >= 0
                        ? parentUnitCost
                        : 0
                );


            const detailItems =
                Array.isArray(
                    item?.detailItems
                )
                    ? item.detailItems
                    : [];


            let detailTotal =
                0;


            for (
                const detail of detailItems
            ) {

                if (
                    !detail
                ) {

                    continue;

                }


                const detailQuantity =
                    Number(
                        detail?.quantity ??
                        0
                    );


                const detailUnitCost =
                    Number(
                        detail?.unitCost ??
                        0
                    );


                const safeDetailQuantity =
                    Number.isFinite(
                        detailQuantity
                    ) &&
                    detailQuantity > 0
                        ? detailQuantity
                        : 0;


                const safeDetailUnitCost =
                    Number.isFinite(
                        detailUnitCost
                    ) &&
                    detailUnitCost >= 0
                        ? detailUnitCost
                        : 0;


                detailTotal +=
                    safeDetailQuantity *
                    safeDetailUnitCost;

            }


            // The breakdown must add up to the item's cost
            // (a cent of tolerance for rounding)
            const comparisonTolerance =
                0.01;

            if (
                detailItems.length > 0 &&
                Math.abs(
                    detailTotal -
                    parentTotal
                ) >
                comparisonTolerance
            ) {

                const serviceNumber =
                    itemIndex + 1;

                const formatAmount = (value) =>
                    value.toLocaleString(
                        "en-US",
                        {
                            minimumFractionDigits: 2,
                            maximumFractionDigits: 2
                        }
                    );

                window.alert(
                    `Service Item ${serviceNumber}: the detail items must add up to the item's total cost.\n\n` +
                    `Service item total: ${formatAmount(parentTotal)}\n` +
                    `Detail items total: ${formatAmount(detailTotal)}\n\n` +
                    `Adjust the detail quantities or unit costs so the two are equal.`
                );

                return;

            }

        }


        // =====================================================
        // NORMALIZE ITEMS
        // =====================================================

        const normalizedItems =
            items.map(
                (item) => {

                    const quantity =
                        Number(
                            item?.quantity ??
                            1
                        );


                    const unitCost =
                        Number(
                            item?.unitCost ??
                            0
                        );


                    const normalizedDetailItems =
                        Array.isArray(
                            item?.detailItems
                        )
                            ? item.detailItems
                                .map(
                                    (detail) => {

                                        if (
                                            !detail
                                        ) {

                                            return null;

                                        }


                                        const detailQuantity =
                                            Number(
                                                detail?.quantity ??
                                                1
                                            );


                                        const detailUnitCost =
                                            Number(
                                                detail?.unitCost ??
                                                0
                                            );


                                        const safeQuantity =
                                            Number.isFinite(
                                                detailQuantity
                                            ) &&
                                            detailQuantity > 0
                                                ? detailQuantity
                                                : 1;


                                        const safeUnitCost =
                                            Number.isFinite(
                                                detailUnitCost
                                            ) &&
                                            detailUnitCost >= 0
                                                ? detailUnitCost
                                                : 0;


                                        const normalizedDetail = {

                                            name:
                                                typeof detail?.name ===
                                                "string"
                                                    ? detail.name.trim()
                                                    : "",

                                            quantity:
                                                safeQuantity,

                                            unit:
                                                normalizeLookupValue(
                                                    detail?.unit
                                                ) ||
                                                null,

                                            // Given out in another unit (1 Sack = 50 Kg)
                                            allocationUnit:
                                                normalizeLookupValue(
                                                    detail?.allocationUnit
                                                ) ||
                                                null,

                                            allocationConversionFactor:
                                                normalizeLookupValue(detail?.allocationUnit) &&
                                                Number(detail?.allocationConversionFactor) > 0
                                                    ? Number(detail.allocationConversionFactor)
                                                    : 1,

                                            unitCost:
                                                safeUnitCost,

                                            totalCost:
                                                safeQuantity *
                                                safeUnitCost

                                        };


                                        // Preserve detail _id
                                        const detailId =
                                            normalizeLookupValue(
                                                detail?._id ??
                                                detail?.id
                                            );


                                        if (
                                            detailId
                                        ) {

                                            normalizedDetail._id =
                                                detailId;

                                        }


                                        return normalizedDetail;

                                    }
                                )
                                .filter(
                                    Boolean
                                )
                            : [];


                    const normalizedItem = {

                        serviceCategory:
                            normalizeLookupValue(
                                item?.serviceCategory
                            ),

                        serviceType:
                            normalizeLookupValue(
                                item?.serviceType
                            ),

                        // ---------------------------------
                        // ALLOCATION BEHAVIOR
                        //
                        // This is inherited from the
                        // selected Service Type by
                        // ServiceDeliveryItems.
                        //
                        // The fallback keeps older/new
                        // items compatible.
                        // ---------------------------------

                        allocationBehavior:
                            normalizeAllocationBehavior(
                                item?.allocationBehavior
                            ),

                        quantity:
                            Number.isFinite(
                                quantity
                            ) &&
                            quantity > 0
                                ? quantity
                                : 1,

                        unit:
                            normalizeLookupValue(
                                item?.unit
                            ),

                        unitCost:
                            Number.isFinite(
                                unitCost
                            ) &&
                            unitCost >= 0
                                ? unitCost
                                : 0,

                        // ---------------------------------
                        // DONOR
                        // ---------------------------------

                        donor:
                            normalizeLookupValue(
                                item?.donor
                            ) ||
                            null,

                        // ---------------------------------
                        // DONATION
                        // ---------------------------------

                        donation:
                            normalizeLookupValue(
                                item?.donation
                            ) ||
                            null,

                        // ---------------------------------
                        // CURRENCY (ETB, or USD at a rate)
                        // ---------------------------------

                        currency:
                            item?.currency || "ETB",
                        exchangeRate:
                            item?.exchangeRate ?? null,
                        donationRate:
                            Number(item?.donationRate) > 0 ? Number(item.donationRate) : null,
                        // bought with this expense (not charged twice)
                        paidByExpense:
                            normalizeLookupValue(
                                item?.paidByExpense
                            ) ||
                            null,
                        separateFromExpenses:
                            Array.isArray(item?.separateFromExpenses)
                                ? item.separateFromExpenses.map(value => normalizeLookupValue(value)).filter(Boolean)
                                : [],

                        // ---------------------------------
                        // DETAIL ITEMS
                        // ---------------------------------

                        detailItems:
                            normalizedDetailItems,

                        remarks:
                            item?.remarks ||
                            ""

                    };


                    // Preserve parent service item _id
                    const itemId =
                        normalizeLookupValue(
                            item?._id ??
                            item?.id
                        );


                    if (
                        itemId
                    ) {

                        normalizedItem._id =
                            itemId;

                    }


                    return normalizedItem;

                }
            );


        // =====================================================
        // NORMALIZE BENEFICIARIES
        //
        // IMPORTANT:
        // Preserve detailItem on every allocation.
        // =====================================================

        const normalizedBeneficiaries =
            Array.isArray(
                formData?.beneficiaries
            )
                ? formData.beneficiaries
                    .map(
                        normalizeBeneficiaryRecord
                    )
                    .filter(
                        Boolean
                    )
                : [];


        // =====================================================
        // BUILD PAYLOAD
        // =====================================================

        const payload = {

            recipientType:
                formData?.recipientType ||
                "",

            recipientName:
                formData?.recipientName ||
                "",

            allocationMethod:
                formData?.allocationMethod ||
                "",

            beneficiaries:
                normalizedBeneficiaries,

            program:
                normalizeLookupValue(
                    formData?.program
                ) ||
                null,

            project:
                normalizeLookupValue(
                    formData?.project
                ) ||
                null,

            activity:
                normalizeLookupValue(
                    formData?.activity
                ) ||
                null,

            activityRun:
                normalizeLookupValue(
                    formData?.activityRun
                ) ||
                null,

            deliveryDate:
                formData?.deliveryDate ||
                null,

            region:
                formData?.region ||
                "",

            regionCode:
                formData?.regionCode ||
                "",

            zone:
                formData?.zone ||
                "",

            zoneCode:
                formData?.zoneCode ||
                "",

            woreda:
                formData?.woreda ||
                "",

            woredaCode:
                formData?.woredaCode ||
                "",

            deliveryLocation:
                formData?.deliveryLocation ||
                "",

            status:
                formData?.status ||
                "Delivered",

            // ---------------------------------
            // Legacy / top-level donation
            // ---------------------------------
            donation:
                normalizeLookupValue(
                    formData?.donation
                ) ||
                null,

            items:
                normalizedItems,

            beneficiary:
                normalizeLookupValue(
                    formData?.beneficiary
                ) ||
                null,

            enrollment:
                normalizeLookupValue(
                    formData?.enrollment
                ) ||
                null,

            fundingSource:
                normalizeLookupValue(
                    formData?.fundingSource
                ) ||
                null,

            deliveredBy:
                normalizeLookupValue(
                    formData?.deliveredBy
                ) ||
                null,

            documents:
                Array.isArray(
                    formData?.documents
                )
                    ? formData.documents
                    : []

        };


        // =====================================================
        // DEBUG
        // =====================================================



        // =====================================================
        // SUBMIT
        // =====================================================

        await onSubmit(
            payload
        );

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Box

            component="form"

            noValidate

            onSubmit={
                submitHandler
            }

            sx={{
                width: "100%"
            }}

        >

            <PageCard>

                <FormSection
                    title="Service Delivery Information"
                >

                    <FormGrid>

                        <AppSelect

                            label="Recipient Type"

                            required

                            value={
                                recipientType
                            }

                            placeholder="Select Recipient Type"

                            options={[
                                {
                                    value:
                                        "Individual",
                                    label:
                                        "Individual"
                                },
                                {
                                    value:
                                        "Household",
                                    label:
                                        "Household"
                                },
                                {
                                    value:
                                        "Group / Community",
                                    label:
                                        "Group / Community"
                                },
                                {
                                    value:
                                        "Institution",
                                    label:
                                        "Institution"
                                }
                            ]}

                            onChange={
                                (e) =>
                                    handleRecipientTypeChange(
                                        e.target.value
                                    )
                            }

                        />


                        {
                            requiresRecipientName && (

                                <AppTextField

                                    label={
                                        recipientType ===
                                            "Group / Community"
                                            ? "Group / Community Name"
                                            : recipientType ===
                                                "Institution"
                                                ? "Institution Name"
                                                : "Household Name / Identifier"
                                    }

                                    required

                                    fullWidth

                                    value={
                                        recipientName
                                    }

                                    placeholder={
                                        recipientType ===
                                            "Group / Community"
                                            ? "Enter group or community name"
                                            : recipientType ===
                                                "Institution"
                                                ? "Enter institution name"
                                                : "Enter household name or identifier"
                                    }

                                    onChange={
                                        (e) =>
                                            handleChange(
                                                "recipientName",
                                                e.target.value
                                            )
                                    }

                                />

                            )
                        }


                        <AppSelect

                            label="Allocation Method"

                            required

                            value={
                                allocationMethod
                            }

                            placeholder="Select Allocation Method"

                            options={
                                allowedAllocationMethods
                            }

                            onChange={
                                (e) =>
                                    handleAllocationMethodChange(
                                        e.target.value
                                    )
                            }

                        />


                        <AppSelect

                            label="Program"

                            required

                            value={
                                programValue
                            }

                            placeholder="Select Program"

                            options={
                                programOptions
                            }

                            onChange={
                                (e) =>
                                    handleProgramChange(
                                        e.target.value
                                    )
                            }

                        />


                        {/* =================================================
                            BENEFICIARIES
                            ================================================= */}

                        <Autocomplete

                            multiple

                            fullWidth

                            disablePortal

                            options={
                                beneficiaryOptions
                            }

                            value={
                                selectedBeneficiaryOptions
                            }

                            disabled={
                                allocationMethod ===
                                "Unallocated"
                            }

                            filterSelectedOptions

                            getOptionLabel={
                                (option) =>
                                    String(
                                        option?.label ||
                                        ""
                                    )
                            }

                            isOptionEqualToValue={
                                (
                                    option,
                                    value
                                ) =>
                                    String(
                                        option?.value ||
                                        ""
                                    ) ===
                                    String(
                                        value?.value ||
                                        ""
                                    )
                            }

                            onChange={
                                (
                                    event,
                                    newValue
                                ) => {

                                    handleBeneficiaryChange(
                                        event,
                                        newValue
                                    );

                                }
                            }

                            renderOption={
                                (
                                    props,
                                    option
                                ) => (

                                    <li
                                        {...props}
                                        key={
                                            String(
                                                option.value
                                            )
                                        }
                                    >

                                        {
                                            option.label
                                        }

                                    </li>

                                )
                            }

                            renderInput={
                                (params) => (

                                    <TextField
                                        {...params}

                                        label="Beneficiaries"
                                        required={
                                            formData?.recipientType === "Individual"
                                        }

                                        placeholder={
                                            allocationMethod === "Unallocated"
                                                ? "No people are listed for an institution"
                                                : allocationMethod === "Group"
                                                ? "Optional: list the members"
                                                : "Search and select beneficiaries"
                                        }

                                    />

                                )
                            }

                        />


                        <AppSelect

                            label="Project"

                            value={
                                projectValue
                            }

                            placeholder={
                                programValue
                                    ? "Select Project"
                                    : "Select Program First"
                            }

                            disabled={
                                !programValue
                            }

                            options={
                                projectOptions
                            }

                            onChange={
                                (e) =>
                                    handleProjectChange(
                                        e.target.value
                                    )
                            }

                        />


                        {/* activity and run: only with the activities module */}
                        {activitiesOn && (
                        <AppSelect

                            label="Activity"

                            value={
                                activityValue
                            }

                            placeholder={
                                projectValue
                                    ? "Select Activity"
                                    : "Select Project First"
                            }

                            disabled={
                                !projectValue
                            }

                            options={
                                activityOptions
                            }

                            onChange={
                                (e) =>
                                    handleActivityChange(
                                        e.target.value
                                    )
                            }

                        />
                        )}


                        {activitiesOn && (
                        <AppSelect

                            label="Activity Run"

                            value={
                                activityRunValue
                            }

                            placeholder={
                                activityValue
                                    ? "Select Activity Run"
                                    : "Select Activity First"
                            }

                            disabled={
                                !activityValue
                            }

                            options={
                                activityRunOptions
                            }

                            onChange={
                                (e) =>
                                    handleChange(
                                        "activityRun",
                                        e.target.value
                                    )
                            }

                        />
                        )}


                        <AppDatePicker

                            label="Service Delivery Date"

                            required

                            helperText={rangeHint("project", projectForDates?.startDate, projectForDates?.endDate)}

                            minDate={dayOf(projectForDates?.startDate)}

                            maxDate={dayOf(projectForDates?.endDate)}

                            value={
                                formData?.deliveryDate ||
                                null
                            }

                            onChange={
                                (value) =>
                                    handleChange(
                                        "deliveryDate",
                                        value
                                    )
                            }

                        />

                    </FormGrid>


                </FormSection>

            </PageCard>



            {/* =================================================
                DELIVERY LOCATION
                ================================================= */}

            <PageCard>

                <FormSection
                    title="Delivery Location"
                >

                    <FormGrid>

                        <LocationCascadeFields
                            value={formData || {}}
                            onChange={handleLocationChange}
                        />

                        <AppTextField
                            label="Venue / Site"
                            placeholder="e.g. Kebele 05 health post"
                            value={
                                formData?.deliveryLocation ||
                                ""
                            }
                            onChange={
                                (e) =>
                                    handleChange(
                                        "deliveryLocation",
                                        e.target.value
                                    )
                            }
                        />

                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                SERVICE ITEMS
                ================================================= */}

            <PageCard>

                <FormSection
                    title="Service Items"
                >

                    <ServiceDeliveryItems

                        items={
                            Array.isArray(
                                formData?.items
                            )
                                ? formData.items
                                : []
                        }

                        setItems={
                            (updater) =>
                                setFormData(
                                    (prev) => {

                                        const currentItems =
                                            Array.isArray(
                                                prev?.items
                                            )
                                                ? prev.items
                                                : [];


                                        const nextItems =
                                            typeof updater ===
                                            "function"
                                                ? updater(
                                                    currentItems
                                                )
                                                : updater;


                                        return {

                                            ...prev,

                                            items:
                                                Array.isArray(
                                                    nextItems
                                                )
                                                    ? nextItems
                                                    : currentItems

                                        };

                                    }
                                )
                        }

                        serviceCategories={
                            serviceCategoryOptions
                        }
                        units={
                            unitOptions
                        }
                        project={
                            formData?.project
                        }
                        // the work the donations must be allowed to pay for
                        work={{
                            program: formData?.program || "",
                            project: formData?.project || "",
                            activity: formData?.activity || "",
                            activityRun: formData?.activityRun || "",
                            parentProject:
                                (projects || []).find(item => String(item?._id) === String(formData?.project))?.parentProject || ""
                        }}
                    />

                </FormSection>

            </PageCard>


            {/* =================================================
                INDIVIDUAL BENEFICIARY ALLOCATION
                ================================================= */}

            {
                (
                    allocationMethod === "Individual" ||
                    (
                        allocationMethod === "Shared" &&
                        selectedBeneficiaryOptions.length > 0
                    )
                ) && (

                    <PageCard>

                        <FormSection
                            title="Beneficiary Allocation"
                        >

                            <ServiceDeliveryAllocations

                                items={
                                    Array.isArray(
                                        formData?.items
                                    )
                                        ? formData.items
                                        : []
                                }

                                beneficiaries={
                                    Array.isArray(
                                        formData?.beneficiaries
                                    )
                                        ? formData.beneficiaries
                                        : []
                                }

                                beneficiaryOptions={
                                    beneficiaryOptions
                                }

                                unitOptions={
                                    unitOptions
                                }

                                allocationMethod={
                                    allocationMethod
                                }

                                setFormData={
                                    setFormData
                                }

                            />

                        </FormSection>

                    </PageCard>

                )
            }


            {/* =================================================
                STATUS
                ================================================= */}

            <PageCard>

                <FormSection
                    title="Status"
                >

                    <FormGrid
                        columns={1}
                    >

                        <AppSelect

                            label="Status"

                            required

                            value={
                                formData?.status ||
                                "Delivered"
                            }

                            placeholder="Select Status"

                            options={[
                                {
                                    value:
                                        "Delivered",
                                    label:
                                        "Delivered"
                                },
                                {
                                    value:
                                        "Cancelled",
                                    label:
                                        "Cancelled"
                                }
                            ]}

                            helperText={
                                formData?.status ===
                                "Cancelled"
                                    ? "Cancelled deliveries are kept for audit but excluded from reports. To edit it later, set it back to Delivered."
                                    : ""
                            }

                            onChange={
                                (e) =>
                                    handleChange(
                                        "status",
                                        e.target.value
                                    )
                            }

                        />

                    </FormGrid>

                </FormSection>

            </PageCard>


            {/* =================================================
                FORM ACTIONS
                ================================================= */}

            <FormActions>

                <AppButton

                    type="submit"

                    variant="contained"

                    size="large"

                    disabled={
                        loading
                    }

                >

                    {
                        loading
                            ? "Saving..."
                            : "Save Service Delivery"
                    }

                </AppButton>

            </FormActions>

        </Box>

    );

};


export default ServiceDeliveryForm;