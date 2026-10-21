const ExcelJS = require("exceljs");
const PDFDocument = require("pdfkit");
const { Parser } = require("json2csv");

const {
    formatDeliveryLocation
} = require("./helpers");

// =====================================================
// CONSTANTS
// =====================================================

const COMPANY_NAME = "NGO SaaS";

const PLATFORM_NAME =
    "NGO SaaS Management Platform";

const SYSTEM_NAME =
    "NGO Management System";

const DEFAULT_PAGE_MARGIN = 45;

const MAX_PDF_DETAIL_ROWS = 100;

const MAX_PDF_TABLE_ROWS = 100;

const EXCEL_MAX_CELL_LENGTH = 32000;

const PDF_COLORS = {
    text: "#1F2937",
    muted: "#6B7280",
    border: "#D1D5DB",
    light: "#F3F4F6",
    lighter: "#F9FAFB",
    heading: "#111827",
    accent: "#374151",
    white: "#FFFFFF"
};


// =====================================================
// GENERAL HELPERS
// =====================================================

const isNil = (value) => {
    return (
        value === null ||
        value === undefined
    );
};


const isDate = (value) => {
    return (
        value instanceof Date &&
        !Number.isNaN(
            value.getTime()
        )
    );
};


const isObjectId = (value) => {
    if (!value) {
        return false;
    }

    if (
        value._bsontype === "ObjectId" ||
        value._bsontype === "ObjectID"
    ) {
        return true;
    }

    if (
        typeof value.toHexString === "function"
    ) {
        try {
            const hex =
                value.toHexString();

            return (
                typeof hex === "string" &&
                /^[a-fA-F0-9]{24}$/.test(hex)
            );
        }
        catch (error) {
            return false;
        }
    }

    return false;
};


const objectIdToString = (value) => {
    if (!value) {
        return "";
    }

    if (
        typeof value.toHexString === "function"
    ) {
        try {
            return value.toHexString();
        }
        catch (error) {
            return String(value);
        }
    }

    return String(value);
};


const formatDate = (value) => {
    if (isNil(value) || value === "") {
        return "—";
    }

    const date =
        isDate(value)
            ? value
            : new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleDateString(
        "en-US",
        {
            month: "short",
            day: "2-digit",
            year: "numeric"
        }
    );
};


const formatDateTime = (value) => {
    if (isNil(value) || value === "") {
        return "—";
    }

    const date =
        isDate(value)
            ? value
            : new Date(value);

    if (
        Number.isNaN(
            date.getTime()
        )
    ) {
        return String(value);
    }

    return date.toLocaleString(
        "en-US",
        {
            month: "short",
            day: "2-digit",
            year: "numeric",
            hour: "2-digit",
            minute: "2-digit"
        }
    );
};


const formatNumber = (value) => {
    if (
        typeof value === "number" &&
        Number.isFinite(value)
    ) {
        return value.toLocaleString(
            "en-US"
        );
    }

    if (
        typeof value === "string" &&
        value.trim() !== "" &&
        !Number.isNaN(
            Number(value)
        )
    ) {
        return Number(value).toLocaleString(
            "en-US"
        );
    }

    if (isNil(value)) {
        return "—";
    }

    return String(value);
};


const formatCurrency = (value) => {
    if (
        isNil(value) ||
        value === ""
    ) {
        return "ETB 0.00";
    }

    const numericValue =
        Number(value);

    if (
        Number.isNaN(
            numericValue
        )
    ) {
        return String(value);
    }

    return `ETB ${numericValue.toLocaleString(
        "en-US",
        {
            minimumFractionDigits: 2,
            maximumFractionDigits: 2
        }
    )}`;
};


const formatCurrencyShort = (value) => {
    if (
        isNil(value) ||
        value === ""
    ) {
        return "ETB 0";
    }

    const numericValue =
        Number(value);

    if (
        Number.isNaN(
            numericValue
        )
    ) {
        return String(value);
    }

    return `ETB ${numericValue.toLocaleString(
        "en-US",
        {
            minimumFractionDigits: 0,
            maximumFractionDigits: 2
        }
    )}`;
};


const formatBoolean = (value) => {
    if (value === true) {
        return "Yes";
    }

    if (value === false) {
        return "No";
    }

    return "—";
};


const formatLabel = (value) => {
    if (!value) {
        return "";
    }

    return String(value)
        .replace(
            /([a-z])([A-Z])/g,
            "$1 $2"
        )
        .replace(
            /[_-]+/g,
            " "
        )
        .replace(
            /\s+/g,
            " "
        )
        .trim()
        .replace(
            /\b\w/g,
            character =>
                character.toUpperCase()
        );
};


// =====================================================
// VALUE RESOLUTION
// =====================================================

const getReadableId = (
    object,
    possibleKeys = []
) => {
    if (
        !object ||
        typeof object !== "object"
    ) {
        return "";
    }

    for (
        const key of possibleKeys
    ) {
        const value =
            object[key];

        if (
            !isNil(value) &&
            typeof value !== "object"
        ) {
            return String(value);
        }

        if (
            isObjectId(value)
        ) {
            return objectIdToString(
                value
            );
        }
    }

    return "";
};


const getDisplayName = (
    object,
    fallback = ""
) => {
    if (isNil(object)) {
        return fallback;
    }

    if (
        typeof object === "string" ||
        typeof object === "number"
    ) {
        return String(object);
    }

    if (
        typeof object !== "object"
    ) {
        return fallback;
    }

    const directKeys = [
        "displayName",
        "name",
        "fullName",
        "enterpriseName",
        "programName",
        "projectName",
        "activityName",
        "activityRunName",
        "serviceTypeName",
        "serviceCategoryName",
        "label",
        "title",
        "value"
    ];

    for (
        const key of directKeys
    ) {
        const value =
            object[key];

        if (
            typeof value === "string" &&
            value.trim() !== ""
        ) {
            return value;
        }
    }

    if (
        object.firstName ||
        object.middleName ||
        object.lastName
    ) {
        return [
            object.firstName,
            object.middleName,
            object.lastName
        ]
            .filter(Boolean)
            .join(" ");
    }

    return fallback;
};


const getBusinessCode = (
    object,
    keys = []
) => {
    if (!object) {
        return "";
    }

    if (
        typeof object === "string"
    ) {
        return object;
    }

    for (
        const key of keys
    ) {
        if (
            object[key] !== undefined &&
            object[key] !== null &&
            object[key] !== ""
        ) {
            const value =
                object[key];

            if (
                isObjectId(value)
            ) {
                continue;
            }

            if (
                typeof value !== "object"
            ) {
                return String(value);
            }
        }
    }

    return "";
};


// =====================================================
// TEXT NORMALIZATION
// =====================================================

const formatArrayForCell = (
    value
) => {
    if (
        !Array.isArray(value)
    ) {
        return "";
    }

    return value
        .map(item => {
            if (isNil(item)) {
                return "";
            }

            if (
                typeof item === "string" ||
                typeof item === "number"
            ) {
                return String(item);
            }

            if (
                isObjectId(item)
            ) {
                return objectIdToString(
                    item
                );
            }

            if (
                typeof item === "object"
            ) {
                return (
                    getDisplayName(
                        item
                    ) ||
                    getBusinessCode(
                        item,
                        [
                            "code",
                            "number",
                            "id"
                        ]
                    )
                );
            }

            return String(item);
        })
        .filter(Boolean)
        .join(", ");
};


const normalizeTextValue = (
    value
) => {
    if (isNil(value)) {
        return "—";
    }

    if (isDate(value)) {
        return formatDate(value);
    }

    if (isObjectId(value)) {
        return objectIdToString(value);
    }

    if (
        Array.isArray(value)
    ) {
        return (
            formatArrayForCell(value) ||
            "—"
        );
    }

    if (
        typeof value === "object"
    ) {
        const displayName =
            getDisplayName(
                value
            );

        if (displayName) {
            return displayName;
        }

        const code =
            getBusinessCode(
                value,
                [
                    "beneficiaryNumber",
                    "enterpriseNumber",
                    "deliveryNumber",
                    "programCode",
                    "projectCode",
                    "activityCode",
                    "runCode",
                    "code",
                    "number"
                ]
            );

        if (code) {
            return code;
        }

        return Object.entries(
            value
        )
            .map(
                ([key, childValue]) =>
                    `${formatLabel(key)}: ${normalizeTextValue(childValue)}`
            )
            .join(" | ");
    }

    if (
        typeof value === "boolean"
    ) {
        return formatBoolean(
            value
        );
    }

    return String(value);
};


const truncateCellValue = (
    value
) => {
    const text =
        String(value || "");

    if (
        text.length <=
        EXCEL_MAX_CELL_LENGTH
    ) {
        return text;
    }

    return (
        text.substring(
            0,
            EXCEL_MAX_CELL_LENGTH - 3
        ) +
        "..."
    );
};


const normalizeExcelValue = (
    value,
    key = ""
) => {
    if (isNil(value)) {
        return "";
    }

    if (isDate(value)) {
        return value;
    }

    if (isObjectId(value)) {
        return objectIdToString(
            value
        );
    }

    if (
        Array.isArray(value)
    ) {
        return truncateCellValue(
            formatArrayForCell(
                value
            )
        );
    }

    if (
        typeof value === "object"
    ) {
        const displayName =
            getDisplayName(
                value
            );

        if (displayName) {
            return truncateCellValue(
                displayName
            );
        }

        const code =
            getBusinessCode(
                value,
                [
                    "beneficiaryNumber",
                    "enterpriseNumber",
                    "deliveryNumber",
                    "programCode",
                    "projectCode",
                    "activityCode",
                    "runCode",
                    "code",
                    "number"
                ]
            );

        if (code) {
            return truncateCellValue(
                code
            );
        }

        return truncateCellValue(
            Object.entries(value)
                .map(
                    ([childKey, childValue]) =>
                        `${formatLabel(childKey)}: ${normalizeTextValue(childValue)}`
                )
                .join(" | ")
        );
    }

    if (
        typeof value === "boolean"
    ) {
        return value
            ? "Yes"
            : "No";
    }

    if (
        typeof value === "number"
    ) {
        return value;
    }

    return truncateCellValue(
        String(value)
    );
};


const normalizeObjectForExcel = (
    object
) => {
    const result = {};

    if (
        !object ||
        typeof object !== "object"
    ) {
        return result;
    }

    Object.entries(
        object
    ).forEach(
        ([key, value]) => {
            result[key] =
                normalizeExcelValue(
                    value,
                    key
                );
        }
    );

    return result;
};


// =====================================================
// REPORT TYPE
// =====================================================

const isBeneficiaryReport = (
    report
) => {
    const identity = [
        report?.reportName,
        report?.name,
        report?.code,
        report?.title
    ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

    return identity.includes(
        "beneficiary"
    );
};


// =====================================================
// BENEFICIARY RESOLUTION
// =====================================================

const getBeneficiaryNumber = (
    beneficiary
) => {
    return getBusinessCode(
        beneficiary,
        [
            "beneficiaryNumber",
            "beneficiaryNo",
            "number"
        ]
    );
};


const getBeneficiaryName = (
    beneficiary
) => {
    return getDisplayName(
        beneficiary,
        "—"
    );
};


// =====================================================
// ENTERPRISE RESOLUTION
// =====================================================

const resolveMembershipEnterprise = (
    membership
) => {
    return (
        membership?.enterprise ||
        membership?.enterpriseData ||
        membership?.enterpriseDetails ||
        membership?.enterpriseInfo ||
        null
    );
};


const getEnterpriseName = (
    enterprise,
    membership = null
) => {
    if (
        !enterprise &&
        !membership
    ) {
        return "—";
    }

    if (
        typeof enterprise === "string"
    ) {
        return enterprise;
    }

    if (enterprise) {
        const name =
            enterprise.name ||
            enterprise.enterpriseName ||
            enterprise.title ||
            enterprise.displayName;

        if (name) {
            return name;
        }
    }

    return (
        membership?.enterpriseName ||
        membership?.enterpriseTitle ||
        membership?.name ||
        enterprise?.enterpriseCode ||
        enterprise?.code ||
        enterprise?._id ||
        membership?.enterpriseCode ||
        membership?.enterpriseId ||
        "—"
    );
};


const getEnterpriseCode = (
    enterprise,
    membership = null
) => {
    return (
        getBusinessCode(
            enterprise,
            [
                "enterpriseCode",
                "enterpriseNumber",
                "code",
                "number",
                "registrationNumber",
                "identifier"
            ]
        ) ||
        getBusinessCode(
            membership,
            [
                "enterpriseCode",
                "enterpriseNumber",
                "code",
                "number",
                "enterpriseId"
            ]
        ) ||
        "—"
    );
};


// =====================================================
// PROGRAM RESOLUTION
// =====================================================

const resolveEnrollmentProgram = (
    enrollment
) => {
    return (
        enrollment?.program ||
        enrollment?.programData ||
        enrollment?.programDetails ||
        null
    );
};


const getProgramCode = (
    program,
    source = null
) => {
    return (
        getBusinessCode(
            program,
            [
                "programCode",
                "code",
                "programNumber"
            ]
        ) ||
        getBusinessCode(
            source,
            [
                "programCode",
                "code",
                "programNumber"
            ]
        ) ||
        "—"
    );
};


const getProgramName = (
    program,
    source = null
) => {
    if (
        typeof program === "string"
    ) {
        return program;
    }

    return (
        getDisplayName(
            program
        ) ||
        source?.programName ||
        source?.programTitle ||
        "—"
    );
};


// =====================================================
// PROGRAM LIST
// =====================================================

const getBeneficiaryPrograms = (
    beneficiary
) => {
    if (!beneficiary) {
        return [];
    }

    const directPrograms =
        Array.isArray(
            beneficiary.programs
        )
            ? beneficiary.programs
            : [];

    const enrollmentPrograms =
        Array.isArray(
            beneficiary.enrollments
        )
            ? beneficiary.enrollments
                .map(
                    enrollment =>
                        resolveEnrollmentProgram(
                            enrollment
                        )
                )
                .filter(Boolean)
            : [];

    const allPrograms = [
        ...directPrograms,
        ...enrollmentPrograms
    ];

    const getProgramId = (
        program
    ) => {
        if (
            !program ||
            typeof program === "string"
        ) {
            return "";
        }

        return String(
            program._id ||
            program.id ||
            program.programId ||
            ""
        ).trim();
    };

    const getName = (
        program
    ) => {
        return getProgramName(
            program
        )
            .trim()
            .toLowerCase();
    };

    const getCode = (
        program
    ) => {
        return getProgramCode(
            program
        )
            .trim()
            .toLowerCase();
    };

    const getKey = (
        program
    ) => {
        const id =
            getProgramId(
                program
            );

        if (id) {
            return `id:${id}`;
        }

        const code =
            getCode(
                program
            );

        if (code && code !== "—") {
            return `code:${code}`;
        }

        const name =
            getName(
                program
            );

        if (name && name !== "—") {
            return `name:${name}`;
        }

        return "";
    };

    const map =
        new Map();

    allPrograms.forEach(
        program => {
            if (!program) {
                return;
            }

            const key =
                getKey(
                    program
                );

            if (!key) {
                return;
            }

            const existing =
                map.get(key);

            if (!existing) {
                map.set(
                    key,
                    program
                );

                return;
            }

            const existingName =
                getName(existing);

            const currentName =
                getName(program);

            if (
                currentName &&
                !existingName
            ) {
                map.set(
                    key,
                    program
                );
            }
        }
    );

    return Array.from(
        map.values()
    );
};


// =====================================================
// SERVICE RESOLUTION
// =====================================================

const resolveServiceEntry = (
    entry
) => {
    if (
        !entry ||
        typeof entry !== "object"
    ) {
        return null;
    }

    return (
        entry.serviceDelivery ||
        entry.service ||
        entry.delivery ||
        entry
    );
};


const resolveServiceProgram = (
    service,
    beneficiary = null
) => {
    const directProgram =
        service?.program ||
        service?.enrollment?.program ||
        service?.programData ||
        service?.programDetails ||
        null;

    if (directProgram) {
        return directProgram;
    }

    const hierarchyProgram =
        service?.activityRun?.program ||
        service?.activity?.program ||
        service?.project?.program ||
        null;

    if (hierarchyProgram) {
        return hierarchyProgram;
    }

    const programs =
        getBeneficiaryPrograms(
            beneficiary
        );

    return programs[0] || null;
};


const resolveServiceProject = (
    service
) => {
    return (
        service?.project ||
        service?.activity?.project ||
        service?.activityRun?.project ||
        null
    );
};


const resolveServiceActivity = (
    service
) => {
    return (
        service?.activity ||
        service?.activityRun?.activity ||
        null
    );
};


const resolveServiceActivityRun = (
    service
) => {
    return (
        service?.activityRun ||
        null
    );
};


const getServiceItems = (
    service
) => {
    if (
        Array.isArray(
            service?.items
        )
    ) {
        return service.items;
    }

    return [];
};


const getServiceTypes = (
    service
) => {
    const values = [];

    const add = (
        value
    ) => {
        if (
            isNil(value) ||
            value === ""
        ) {
            return;
        }

        let text =
            normalizeTextValue(
                value
            );

        if (
            value &&
            typeof value === "object"
        ) {
            text =
                getDisplayName(
                    value,
                    text
                );
        }

        if (
            text &&
            text !== "—" &&
            !values.includes(text)
        ) {
            values.push(
                text
            );
        }
    };

    add(
        service?.serviceType
    );

    if (
        Array.isArray(
            service?.serviceTypes
        )
    ) {
        service.serviceTypes.forEach(
            add
        );
    }

    getServiceItems(
        service
    ).forEach(
        item => {
            add(
                item?.serviceType
            );

            add(
                item?.service
            );

            add(
                item?.type
            );

            add(
                item?.serviceName
            );
        }
    );

    return values;
};


const getServiceTotal = (
    service
) => {
    if (
        service?.totalAmount !== undefined &&
        service?.totalAmount !== null
    ) {
        return Number(
            service.totalAmount
        ) || 0;
    }

    if (
        service?.totalValue !== undefined &&
        service?.totalValue !== null
    ) {
        return Number(
            service.totalValue
        ) || 0;
    }

    if (
        service?.supportValue !== undefined &&
        service?.supportValue !== null
    ) {
        return Number(
            service.supportValue
        ) || 0;
    }

    const items =
        getServiceItems(
            service
        );

    return items.reduce(
        (
            total,
            item
        ) => {
            const itemTotal =
                Number(
                    item?.totalCost
                );

            if (
                Number.isFinite(
                    itemTotal
                )
            ) {
                return (
                    total +
                    itemTotal
                );
            }

            const quantity =
                Number(
                    item?.quantity
                ) || 0;

            const unitCost =
                Number(
                    item?.unitCost
                ) || 0;

            return (
                total +
                (
                    quantity *
                    unitCost
                )
            );
        },
        0
    );
};


// =====================================================
// BENEFICIARY SERVICE LIST
// =====================================================

const getBeneficiaryServices = (
    beneficiary
) => {
    if (
        Array.isArray(
            beneficiary?.services
        )
    ) {
        return beneficiary.services;
    }

    if (
        Array.isArray(
            beneficiary?.servicesReceived
        )
    ) {
        return beneficiary.servicesReceived;
    }

    return [];
};


// =====================================================
// BENEFICIARY EXCEL ROWS
// =====================================================

const normalizeBeneficiaryRows = (
    details = []
) => {
    return details.map(
        beneficiary => {
            return {
                "Beneficiary No.":
                    getBeneficiaryNumber(
                        beneficiary
                    ),

                "Beneficiary":
                    getBeneficiaryName(
                        beneficiary
                    ),

                "Gender":
                    normalizeTextValue(
                        beneficiary.gender
                    ),

                "Date of Birth":
                    formatDate(
                        beneficiary.dateOfBirth
                    ),

                "Age":
                    normalizeExcelValue(
                        beneficiary.age
                    ),

                "Education":
                    normalizeTextValue(
                        beneficiary.educationLevel
                    ),

                "Occupation":
                    normalizeTextValue(
                        beneficiary.occupation
                    ),

                "Marital Status":
                    normalizeTextValue(
                        beneficiary.maritalStatus
                    ),

                "Disability":
                    normalizeTextValue(
                        beneficiary.disabilityType
                    ),

                "Vulnerable Groups":
                    formatArrayForCell(
                        beneficiary.vulnerableGroups
                    ),

                "Status":
                    normalizeTextValue(
                        beneficiary.status
                    ),

                "Country":
                    normalizeTextValue(
                        beneficiary.country ||
                        beneficiary.location?.country
                    ),

                "Region":
                    normalizeTextValue(
                        beneficiary.region ||
                        beneficiary.location?.region
                    ),

                "Zone":
                    normalizeTextValue(
                        beneficiary.zone ||
                        beneficiary.location?.zone
                    ),

                "Woreda":
                    normalizeTextValue(
                        beneficiary.woreda ||
                        beneficiary.location?.woreda
                    ),

                "Kebele":
                    normalizeTextValue(
                        beneficiary.kebele ||
                        beneficiary.location?.kebele
                    ),

                "Address":
                    normalizeTextValue(
                        beneficiary.address ||
                        beneficiary.location?.address
                    ),

                "Phone":
                    normalizeTextValue(
                        beneficiary.phone
                    ),

                "Alternative Phone":
                    normalizeTextValue(
                        beneficiary.alternativePhone
                    ),

                "Email":
                    normalizeTextValue(
                        beneficiary.email
                    )
            };
        }
    );
};


// =====================================================
// ENTERPRISE EXCEL ROWS
// =====================================================

const normalizeEnterpriseRows = (
    details = []
) => {
    const rows = [];

    details.forEach(
        beneficiary => {
            const memberships =
                Array.isArray(
                    beneficiary.enterprises
                )
                    ? beneficiary.enterprises
                    : [];

            memberships.forEach(
                membership => {
                    const enterprise =
                        resolveMembershipEnterprise(
                            membership
                        );

                    rows.push({
                        "Beneficiary No.":
                            getBeneficiaryNumber(
                                beneficiary
                            ),

                        "Beneficiary":
                            getBeneficiaryName(
                                beneficiary
                            ),

                        "Enterprise":
                            getEnterpriseName(
                                enterprise,
                                membership
                            ),

                        "Enterprise Code":
                            getEnterpriseCode(
                                enterprise,
                                membership
                            ),

                        "Enterprise Type":
                            normalizeTextValue(
                                membership.enterpriseType ||
                                enterprise?.enterpriseType
                            ),

                        "Ownership Type":
                            normalizeTextValue(
                                membership.ownershipType ||
                                enterprise?.ownershipType
                            ),

                        "Business Sector":
                            normalizeTextValue(
                                membership.businessSector ||
                                enterprise?.businessSector
                            ),

                        "Membership Role":
                            normalizeTextValue(
                                membership.memberRole
                            ),

                        "Joined Date":
                            formatDate(
                                membership.joinedDate
                            ),

                        "Left Date":
                            formatDate(
                                membership.leftDate
                            ),

                        "Status":
                            normalizeTextValue(
                                membership.status
                            )
                    });
                }
            );
        }
    );

    return rows;
};


// =====================================================
// ENROLLMENT EXCEL ROWS
// =====================================================

const normalizeEnrollmentRows = (
    details = []
) => {
    const rows = [];

    details.forEach(
        beneficiary => {
            const enrollments =
                Array.isArray(
                    beneficiary.enrollments
                )
                    ? beneficiary.enrollments
                    : [];

            enrollments.forEach(
                enrollment => {
                    const program =
                        resolveEnrollmentProgram(
                            enrollment
                        );

                    rows.push({
                        "Beneficiary No.":
                            getBeneficiaryNumber(
                                beneficiary
                            ),

                        "Beneficiary":
                            getBeneficiaryName(
                                beneficiary
                            ),

                        "Date":
                            formatDate(
                                enrollment.enrollmentDate
                            ),

                        "Program":
                            getProgramName(
                                program,
                                enrollment
                            ),

                        "Program Code":
                            getProgramCode(
                                program,
                                enrollment
                            ),

                        "Status":
                            normalizeTextValue(
                                enrollment.status
                            ),

                        "Completion Date":
                            formatDate(
                                enrollment.completionDate
                            ),

                        "Exit Reason":
                            normalizeTextValue(
                                enrollment.exitReason
                            ),

                        "Remarks":
                            normalizeTextValue(
                                enrollment.remarks
                            )
                    });
                }
            );
        }
    );

    return rows;
};


// =====================================================
// SERVICE EXCEL ROWS
// =====================================================

const normalizeServiceRows = (
    details = []
) => {
    const rows = [];

    details.forEach(
        beneficiary => {
            const services =
                getBeneficiaryServices(
                    beneficiary
                );

            services.forEach(
                serviceEntry => {
                    const service =
                        resolveServiceEntry(
                            serviceEntry
                        );

                    if (!service) {
                        return;
                    }

                    const program =
                        resolveServiceProgram(
                            service,
                            beneficiary
                        );

                    const project =
                        resolveServiceProject(
                            service
                        );

                    const activity =
                        resolveServiceActivity(
                            service
                        );

                    const activityRun =
                        resolveServiceActivityRun(
                            service
                        );

                    const serviceTypes =
                        getServiceTypes(
                            service
                        );

                    const items =
                        getServiceItems(
                            service
                        );

                    if (
                        items.length
                    ) {
                        items.forEach(
                            item => {
                                rows.push({
                                    "Beneficiary No.":
                                        getBeneficiaryNumber(
                                            beneficiary
                                        ),

                                    "Beneficiary":
                                        getBeneficiaryName(
                                            beneficiary
                                        ),

                                    "Delivery No.":
                                        getBusinessCode(
                                            service,
                                            [
                                                "deliveryNumber"
                                            ]
                                        ) ||
                                        getBusinessCode(
                                            serviceEntry,
                                            [
                                                "deliveryNumber"
                                            ]
                                        ),

                                    "Delivery Date":
                                        formatDate(
                                            service.deliveryDate ||
                                            serviceEntry.deliveryDate
                                        ),

                                    "Program":
                                        getProgramName(
                                            program,
                                            service
                                        ),

                                    "Program Code":
                                        getProgramCode(
                                            program,
                                            service
                                        ),

                                    "Project":
                                        getDisplayName(
                                            project,
                                            "—"
                                        ),

                                    "Project Code":
                                        getBusinessCode(
                                            project,
                                            [
                                                "projectCode",
                                                "code"
                                            ]
                                        ) || "—",

                                    "Activity":
                                        getDisplayName(
                                            activity,
                                            "—"
                                        ),

                                    "Activity Code":
                                        getBusinessCode(
                                            activity,
                                            [
                                                "activityCode",
                                                "code"
                                            ]
                                        ) || "—",

                                    "Activity Run":
                                        getDisplayName(
                                            activityRun,
                                            "—"
                                        ),

                                    "Activity Run Code":
                                        getBusinessCode(
                                            activityRun,
                                            [
                                                "runCode",
                                                "code"
                                            ]
                                        ) || "—",

                                    "Service Category":
                                        normalizeTextValue(
                                            item.serviceCategory
                                        ),

                                    "Service Type":
                                        normalizeTextValue(
                                            item.serviceType
                                        ),

                                    "Item / Remarks":
                                        normalizeTextValue(
                                            item.remarks ||
                                            item.description ||
                                            item.item ||
                                            item.itemName
                                        ),

                                    "Quantity":
                                        Number(
                                            item.quantity
                                        ) || 0,

                                    "Unit":
                                        normalizeTextValue(
                                            item.unit
                                        ),

                                    "Unit Cost":
                                        Number(
                                            item.unitCost
                                        ) || 0,

                                    "Total Cost":
                                        Number(
                                            item.totalCost
                                        ) ||
                                        (
                                            (
                                                Number(
                                                    item.quantity
                                                ) || 0
                                            ) *
                                            (
                                                Number(
                                                    item.unitCost
                                                ) || 0
                                            )
                                        ),

                                    "Location":
                                        normalizeTextValue(
                                            formatDeliveryLocation(service) ||
                                            formatDeliveryLocation(serviceEntry)
                                        ),

                                    "Status":
                                        normalizeTextValue(
                                            service.status ||
                                            serviceEntry.status
                                        ),

                                    "Service Types":
                                        serviceTypes.join(
                                            ", "
                                        )
                                });
                            }
                        );
                    }
                    else {
                        rows.push({
                            "Beneficiary No.":
                                getBeneficiaryNumber(
                                    beneficiary
                                ),

                            "Beneficiary":
                                getBeneficiaryName(
                                    beneficiary
                                ),

                            "Delivery No.":
                                getBusinessCode(
                                    service,
                                    [
                                        "deliveryNumber"
                                    ]
                                ) ||
                                getBusinessCode(
                                    serviceEntry,
                                    [
                                        "deliveryNumber"
                                    ]
                                ),

                            "Delivery Date":
                                formatDate(
                                    service.deliveryDate ||
                                    serviceEntry.deliveryDate
                                ),

                            "Program":
                                getProgramName(
                                    program,
                                    service
                                ),

                            "Program Code":
                                getProgramCode(
                                    program,
                                    service
                                ),

                            "Project":
                                getDisplayName(
                                    project,
                                    "—"
                                ),

                            "Project Code":
                                getBusinessCode(
                                    project,
                                    [
                                        "projectCode",
                                        "code"
                                    ]
                                ) || "—",

                            "Activity":
                                getDisplayName(
                                    activity,
                                    "—"
                                ),

                            "Activity Code":
                                getBusinessCode(
                                    activity,
                                    [
                                        "activityCode",
                                        "code"
                                    ]
                                ) || "—",

                            "Activity Run":
                                getDisplayName(
                                    activityRun,
                                    "—"
                                ),

                            "Activity Run Code":
                                getBusinessCode(
                                    activityRun,
                                    [
                                        "runCode",
                                        "code"
                                    ]
                                ) || "—",

                            "Service Category":
                                "—",

                            "Service Type":
                                serviceTypes.join(
                                    ", "
                                ) || "—",

                            "Item / Remarks":
                                "—",

                            "Quantity":
                                0,

                            "Unit":
                                "—",

                            "Unit Cost":
                                0,

                            "Total Cost":
                                getServiceTotal(
                                    service
                                ),

                            "Location":
                                normalizeTextValue(
                                    formatDeliveryLocation(service) ||
                                    formatDeliveryLocation(serviceEntry)
                                ),

                            "Status":
                                normalizeTextValue(
                                    service.status ||
                                    serviceEntry.status
                                ),

                            "Service Types":
                                serviceTypes.join(
                                    ", "
                                ) || "—"
                        });
                    }
                }
            );
        }
    );

    return rows;
};


// =====================================================
// GENERIC DETAILS
// =====================================================

const normalizeGenericRows = (
    details = []
) => {
    return details.map(
        row =>
            normalizeObjectForExcel(
                row
            )
    );
};


// =====================================================
// EXCEL STYLE HELPERS
// =====================================================

const styleWorksheetTitle = (
    worksheet,
    title
) => {
    worksheet.mergeCells(
        "A1:F1"
    );

    const cell =
        worksheet.getCell(
            "A1"
        );

    cell.value =
        title;

    cell.font = {
        name: "Arial",
        size: 16,
        bold: true
    };

    cell.alignment = {
        vertical: "middle",
        horizontal: "left"
    };

    worksheet.getRow(
        1
    ).height = 28;
};


const styleHeaderRow = (
    row
) => {
    row.font = {
        name: "Arial",
        bold: true,
        size: 10
    };

    row.alignment = {
        vertical: "middle",
        horizontal: "left",
        wrapText: true
    };

    row.height = 24;

    row.eachCell(
        cell => {
            cell.border = {
                top: {
                    style: "thin"
                },
                left: {
                    style: "thin"
                },
                bottom: {
                    style: "thin"
                },
                right: {
                    style: "thin"
                }
            };
        }
    );
};


const styleBodyRows = (
    worksheet,
    startRow = 2
) => {
    worksheet.eachRow(
        (
            row,
            rowNumber
        ) => {
            if (
                rowNumber <
                startRow
            ) {
                return;
            }

            row.font = {
                name: "Arial",
                size: 9
            };

            row.alignment = {
                vertical: "top",
                wrapText: true
            };

            row.eachCell(
                cell => {
                    cell.border = {
                        top: {
                            style: "hair"
                        },
                        left: {
                            style: "hair"
                        },
                        bottom: {
                            style: "hair"
                        },
                        right: {
                            style: "hair"
                        }
                    };
                }
            );
        }
    );
};


const autoFitColumns = (
    worksheet,
    maximumWidth = 42
) => {
    // An empty sheet (e.g. a report with no charts) has no columns
    if (!Array.isArray(worksheet.columns)) {
        return;
    }

    worksheet.columns.forEach(
        column => {
            let maxLength = 10;

            column.eachCell(
                {
                    includeEmpty: false
                },
                cell => {
                    let value =
                        cell.value;

                    if (
                        value instanceof Date
                    ) {
                        value =
                            formatDate(
                                value
                            );
                    }

                    const length =
                        String(
                            value ?? ""
                        ).length;

                    if (
                        length >
                        maxLength
                    ) {
                        maxLength =
                            length;
                    }
                }
            );

            column.width =
                Math.min(
                    Math.max(
                        maxLength + 2,
                        12
                    ),
                    maximumWidth
                );
        }
    );
};


// =====================================================
// EXCEL TABLE SHEET
// =====================================================

const addTableSheet = (
    workbook,
    sheetName,
    rows
) => {
    if (
        !Array.isArray(rows) ||
        rows.length === 0
    ) {
        return null;
    }

    const safeSheetName =
        String(
            sheetName
        )
            .substring(
                0,
                31
            );

    const worksheet =
        workbook.addWorksheet(
            safeSheetName
        );

    const columns =
        Object.keys(
            rows[0]
        );

    // Readable headings ("budgetCode" -> "Budget Code"); date
    // columns shown as dates, not serial numbers / timestamps
    const isDateColumn = (key) =>
        rows.some(row => isDate(row[key])) &&
        rows.every(row => isNil(row[key]) || row[key] === "" || isDate(row[key]));

    worksheet.columns =
        columns.map(
            key => ({
                header: /[a-z][A-Z]|^[a-z]/.test(key) ? formatLabel(key) : key,
                key,
                width: 20,
                ...(isDateColumn(key) ? { style: { numFmt: "yyyy-mm-dd" } } : {})
            })
        );

    rows.forEach(
        row => {
            const normalizedRow =
                {};

            columns.forEach(
                key => {
                    normalizedRow[key] =
                        normalizeExcelValue(
                            row[key],
                            key
                        );
                }
            );

            worksheet.addRow(
                normalizedRow
            );
        }
    );

    styleHeaderRow(
        worksheet.getRow(
            1
        )
    );

    styleBodyRows(
        worksheet,
        2
    );

    worksheet.views = [
        {
            state: "frozen",
            ySplit: 1
        }
    ];

    worksheet.autoFilter = {
        from: {
            row: 1,
            column: 1
        },
        to: {
            row:
                worksheet.rowCount,
            column:
                columns.length
        }
    };

    autoFitColumns(
        worksheet
    );

    return worksheet;
};


// =====================================================
// REPORT PERIOD
// =====================================================

const buildReportPeriodText = (
    report
) => {
    if (
        report?.period
    ) {
        return normalizeTextValue(
            report.period
        );
    }

    if (
        report?.filters
    ) {
        const filters =
            report.filters;

        const values = [];

        if (
            filters.startDate
        ) {
            values.push(
                `From ${formatDate(filters.startDate)}`
            );
        }

        if (
            filters.endDate
        ) {
            values.push(
                `To ${formatDate(filters.endDate)}`
            );
        }

        if (
            filters.year
        ) {
            values.push(
                `Year ${filters.year}`
            );
        }

        if (
            filters.month
        ) {
            values.push(
                `Month ${filters.month}`
            );
        }

        if (
            filters.quarter
        ) {
            values.push(
                `Quarter ${filters.quarter}`
            );
        }

        if (
            filters.half
        ) {
            values.push(
                `Half ${filters.half}`
            );
        }

        if (
            values.length
        ) {
            return values.join(
                " | "
            );
        }
    }

    return "Selected reporting period";
};


// =====================================================
// EXCEL SUMMARY
// =====================================================

const createSummarySheet = (
    workbook,
    report,
    context
) => {
    const worksheet =
        workbook.addWorksheet(
            "Summary"
        );

    const organizationName =
        context.organization?.name ||
        "—";

    worksheet.mergeCells(
        "A1:D1"
    );

    worksheet.getCell(
        "A1"
    ).value =
        PLATFORM_NAME;

    worksheet.getCell(
        "A1"
    ).font = {
        name: "Arial",
        size: 18,
        bold: true
    };

    worksheet.mergeCells(
        "A2:D2"
    );

    worksheet.getCell(
        "A2"
    ).value =
        SYSTEM_NAME;

    worksheet.getCell(
        "A2"
    ).font = {
        name: "Arial",
        size: 13,
        bold: true
    };

    worksheet.addRow([]);

    worksheet.addRow([
        "Report",
        report.title ||
        "NGO Report"
    ]);

    worksheet.addRow([
        "Organization",
        organizationName
    ]);

    worksheet.addRow([
        "Generated Date",
        new Date()
    ]);

    worksheet.addRow([
        "Reporting Period",
        buildReportPeriodText(
            report
        )
    ]);

    worksheet.addRow([]);

    worksheet.addRow([
        "Report Summary",
        ""
    ]);

    styleHeaderRow(
        worksheet.getRow(
            worksheet.rowCount
        )
    );

    worksheet.addRow([
        "Metric",
        "Value"
    ]);

    styleHeaderRow(
        worksheet.getRow(
            worksheet.rowCount
        )
    );

    if (
        report.summary &&
        typeof report.summary === "object"
    ) {
        Object.entries(
            report.summary
        ).forEach(
            ([key, value]) => {
                worksheet.addRow([
                    formatLabel(
                        key
                    ),
                    normalizeExcelValue(
                        value,
                        key
                    )
                ]);
            }
        );
    }

    worksheet.getColumn(
        1
    ).width = 38;

    worksheet.getColumn(
        2
    ).width = 55;

    worksheet.getColumn(
        3
    ).width = 20;

    worksheet.getColumn(
        4
    ).width = 20;

    worksheet.eachRow(
        row => {
            row.font = {
                name: "Arial",
                size: 10
            };

            row.alignment = {
                vertical: "top",
                wrapText: true
            };
        }
    );

    worksheet.eachRow(
        row => {
            row.eachCell(
                cell => {
                    if (
                        cell.value instanceof Date
                    ) {
                        cell.numFmt =
                            "dd-mmm-yyyy";
                    }
                }
            );
        }
    );

    return worksheet;
};


// =====================================================
// EXCEL STATISTICS / CHART DATA
// =====================================================

const createChartsSheet = (
    workbook,
    report
) => {
    if (
        !report.charts ||
        typeof report.charts !== "object"
    ) {
        return null;
    }

    const worksheet =
        workbook.addWorksheet(
            "Charts"
        );

    Object.entries(
        report.charts
    ).forEach(
        ([name, data]) => {
            worksheet.addRow([
                formatLabel(name)
            ]);

            const titleRow =
                worksheet.getRow(
                    worksheet.rowCount
                );

            titleRow.font = {
                name: "Arial",
                size: 12,
                bold: true
            };

            if (
                Array.isArray(data) &&
                data.length
            ) {
                const columns =
                    Object.keys(
                        data[0]
                    );

                worksheet.addRow(
                    columns
                );

                styleHeaderRow(
                    worksheet.getRow(
                        worksheet.rowCount
                    )
                );

                data.forEach(
                    item => {
                        worksheet.addRow(
                            columns.map(
                                key =>
                                    normalizeExcelValue(
                                        item[key],
                                        key
                                    )
                            )
                        );
                    }
                );
            }
            else {
                worksheet.addRow([
                    "No chart data"
                ]);
            }

            worksheet.addRow([]);
        }
    );

    styleBodyRows(
        worksheet,
        1
    );

    autoFitColumns(
        worksheet
    );

    return worksheet;
};


// =====================================================
// EXCEL EXPORT
// =====================================================

const exportExcel = async (
    report,
    context
) => {
    const workbook =
        new ExcelJS.Workbook();

    workbook.creator =
        COMPANY_NAME;

    workbook.lastModifiedBy =
        COMPANY_NAME;

    workbook.created =
        new Date();

    workbook.modified =
        new Date();

    workbook.properties = {
        title:
            report.title ||
            "NGO Report",

        subject:
            "NGO Management Report",

        company:
            context.organization?.name ||
            COMPANY_NAME
    };

    createSummarySheet(
        workbook,
        report,
        context
    );

    const details =
        Array.isArray(
            report.details
        )
            ? report.details
            : [];

    if (
        isBeneficiaryReport(
            report
        )
    ) {
        addTableSheet(
            workbook,
            "Beneficiaries",
            normalizeBeneficiaryRows(
                details
            )
        );

        addTableSheet(
            workbook,
            "Enterprises",
            normalizeEnterpriseRows(
                details
            )
        );

        addTableSheet(
            workbook,
            "Program Participation",
            normalizeEnrollmentRows(
                details
            )
        );

        addTableSheet(
            workbook,
            "Services",
            normalizeServiceRows(
                details
            )
        );
    }
    else if (
        details.length
    ) {
        addTableSheet(
            workbook,
            "Details",
            normalizeGenericRows(
                details
            )
        );
    }

    createChartsSheet(
        workbook,
        report
    );

    workbook.worksheets.forEach(
        worksheet => {
            worksheet.eachRow(
                row => {
                    row.eachCell(
                        cell => {
                            if (
                                cell.value instanceof Date
                            ) {
                                cell.numFmt =
                                    "dd-mmm-yyyy";
                            }
                        }
                    );
                }
            );
        }
    );

    return await workbook.xlsx.writeBuffer();
};


// =====================================================
// CSV EXPORT
// =====================================================

const exportCSV = (
    report
) => {
    const details =
        Array.isArray(
            report.details
        )
            ? report.details
            : [];

    let rows;

    if (
        isBeneficiaryReport(
            report
        )
    ) {
        rows =
            normalizeBeneficiaryRows(
                details
            );
    }
    else {
        rows =
            normalizeGenericRows(
                details
            );
    }

    if (
        !rows.length
    ) {
        return "";
    }

    const parser =
        new Parser({
            fields:
                Object.keys(
                    rows[0]
                )
        });

    return parser.parse(
        rows
    );
};


// =====================================================
// PDF HELPERS
// =====================================================

const pdfSafeText = (
    value
) => {
    return normalizeTextValue(
        value
    );
};


const pdfEnsureSpace = (
    doc,
    height = 60
) => {
    const bottom =
        doc.page.height -
        DEFAULT_PAGE_MARGIN -
        25;

    if (
        doc.y + height >
        bottom
    ) {
        doc.addPage();
    }
};


const pdfSectionTitle = (
    doc,
    title
) => {
    pdfEnsureSpace(
        doc,
        45
    );

    doc
        .font(
            "Helvetica-Bold"
        )
        .fontSize(
            12
        )
        .fillColor(
            PDF_COLORS.heading
        )
        .text(
            title
        );

    doc.moveDown(
        0.25
    );

    doc
        .moveTo(
            DEFAULT_PAGE_MARGIN,
            doc.y
        )
        .lineTo(
            doc.page.width -
                DEFAULT_PAGE_MARGIN,
            doc.y
        )
        .strokeColor(
            PDF_COLORS.border
        )
        .lineWidth(
            0.7
        )
        .stroke();

    doc.moveDown(
        0.45
    );
};


const pdfLabelValue = (
    doc,
    label,
    value
) => {
    const labelWidth = 145;

    pdfEnsureSpace(
        doc,
        22
    );

    const y =
        doc.y;

    doc
        .font(
            "Helvetica-Bold"
        )
        .fontSize(
            8.5
        )
        .fillColor(
            PDF_COLORS.heading
        )
        .text(
            `${label}:`,
            DEFAULT_PAGE_MARGIN,
            y,
            {
                width:
                    labelWidth
            }
        );

    doc
        .font(
            "Helvetica"
        )
        .fontSize(
            8.5
        )
        .fillColor(
            PDF_COLORS.text
        )
        .text(
            pdfSafeText(
                value
            ),
            DEFAULT_PAGE_MARGIN +
                labelWidth,
            y,
            {
                width:
                    doc.page.width -
                    DEFAULT_PAGE_MARGIN -
                    (
                        DEFAULT_PAGE_MARGIN +
                        labelWidth
                    )
            }
        );

    doc.moveDown(
        0.15
    );
};


const pdfKeyValueGrid = (
    doc,
    values
) => {
    Object.entries(
        values
    ).forEach(
        ([key, value]) => {
            pdfLabelValue(
                doc,
                key,
                value
            );
        }
    );
};


const pdfStatus = (
    doc,
    value
) => {
    const text =
        pdfSafeText(
            value
        );

    doc
        .font(
            "Helvetica-Bold"
        )
        .fontSize(
            8.5
        )
        .fillColor(
            PDF_COLORS.heading
        )
        .text(
            text
        );
};


// =====================================================
// PDF TABLE
// =====================================================

const calculatePdfColumnWidths = (
    doc,
    columns
) => {
    const width =
        doc.page.width -
        (
            DEFAULT_PAGE_MARGIN *
            2
        );

    if (
        columns.length === 1
    ) {
        return [
            width
        ];
    }

    const preferred = {
        "Program": 1.5,
        "Program Code": 0.9,
        "Category": 1.3,
        "Start Date": 0.9,
        "End Date": 0.9,
        "Status": 0.8,
        "Date": 0.9,
        "Enrollment": 0.9,
        "Completion": 0.9,
        "Exit Reason": 1.0,
        "Enterprise": 1.4,
        "Enterprise Code": 0.9,
        "Membership Role": 0.9,
        "Role": 0.8,
        "Joined Date": 0.9,
        "Left Date": 0.9,
        "Delivery No.": 0.9,
        "Delivery Date": 0.9,
        "Service Category": 1.1,
        "Service Type": 1.2,
        "Item / Remarks": 1.4,
        "Quantity": 0.7,
        "Unit": 0.7,
        "Unit Cost": 1.0,
        "Total Cost": 1.0
    };

    const raw =
        columns.map(
            column =>
                preferred[column] ||
                1
        );

    const total =
        raw.reduce(
            (
                sum,
                value
            ) =>
                sum + value,
            0
        );

    return raw.map(
        value =>
            (
                value /
                total
            ) *
            width
    );
};


const drawPdfTable = (
    doc,
    columns,
    rows,
    options = {}
) => {
    if (
        !Array.isArray(columns) ||
        !columns.length
    ) {
        return;
    }

    if (
        !Array.isArray(rows) ||
        !rows.length
    ) {
        doc
            .font(
                "Helvetica-Oblique"
            )
            .fontSize(
                8.5
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                "No records available."
            );

        doc.moveDown(
            0.4
        );

        return;
    }

    const maxRows =
        options.maxRows ||
        MAX_PDF_TABLE_ROWS;

    const visibleRows =
        rows.slice(
            0,
            maxRows
        );

    const tableWidth =
        doc.page.width -
        (
            DEFAULT_PAGE_MARGIN *
            2
        );

    const widths =
        calculatePdfColumnWidths(
            doc,
            columns
        );

    const padding = 3;

    const drawHeader = () => {
        pdfEnsureSpace(
            doc,
            28
        );

        const y =
            doc.y;

        let x =
            DEFAULT_PAGE_MARGIN;

        columns.forEach(
            (
                column,
                index
            ) => {
                const width =
                    widths[index];

                doc
                    .rect(
                        x,
                        y,
                        width,
                        22
                    )
                    .fillColor(
                        PDF_COLORS.light
                    )
                    .fill()
                    .strokeColor(
                        PDF_COLORS.border
                    )
                    .stroke();

                doc
                    .font(
                        "Helvetica-Bold"
                    )
                    .fontSize(
                        6.5
                    )
                    .fillColor(
                        PDF_COLORS.heading
                    )
                    .text(
                        column,
                        x + padding,
                        y + 6,
                        {
                            width:
                                width -
                                (
                                    padding *
                                    2
                                ),
                            height: 14,
                            ellipsis: true
                        }
                    );

                x += width;
            }
        );

        doc.y =
            y + 22;
    };

    const getCellText = (
        row,
        column
    ) => {
        return pdfSafeText(
            row[column]
        );
    };

    drawHeader();

    visibleRows.forEach(
        row => {
            const values =
                columns.map(
                    column =>
                        getCellText(
                            row,
                            column
                        )
                );

            const rowHeight = Math.max(
                24,
                ...values.map(
                    (
                        value,
                        index
                    ) => {
                        const width =
                            widths[index] -
                            (
                                padding *
                                2
                            );

                        const height =
                            doc.heightOfString(
                                value,
                                {
                                    width,
                                    font:
                                        "Helvetica",
                                    fontSize: 6.5,
                                    lineGap: 1
                                }
                            );

                        return (
                            height +
                            10
                        );
                    }
                )
            );

            if (
                doc.y +
                rowHeight >
                doc.page.height -
                DEFAULT_PAGE_MARGIN
            ) {
                doc.addPage();

                drawHeader();
            }

            const y =
                doc.y;

            let x =
                DEFAULT_PAGE_MARGIN;

            values.forEach(
                (
                    value,
                    index
                ) => {
                    const width =
                        widths[index];

                    doc
                        .rect(
                            x,
                            y,
                            width,
                            rowHeight
                        )
                        .fillColor(
                            PDF_COLORS.white
                        )
                        .fill()
                        .strokeColor(
                            PDF_COLORS.border
                        )
                        .stroke();

                    doc
                        .font(
                            "Helvetica"
                        )
                        .fontSize(
                            6.5
                        )
                        .fillColor(
                            PDF_COLORS.text
                        )
                        .text(
                            value,
                            x + padding,
                            y + 5,
                            {
                                width:
                                    width -
                                    (
                                        padding *
                                        2
                                    ),
                                height:
                                    rowHeight -
                                    8
                            }
                        );

                    x += width;
                }
            );

            doc.y =
                y +
                rowHeight;
        }
    );

    if (
        rows.length >
        maxRows
    ) {
        doc.moveDown(
            0.3
        );

        doc
            .font(
                "Helvetica-Oblique"
            )
            .fontSize(
                7
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                `Showing first ${maxRows} of ${rows.length} records.`
            );
    }

    doc.moveDown(
        0.5
    );
};


// =====================================================
// PDF SUMMARY STATISTICS
// =====================================================

const renderPdfStatisticGroup = (
    doc,
    title,
    data
) => {
    if (
        !Array.isArray(data) ||
        !data.length
    ) {
        return;
    }

    pdfSectionTitle(
        doc,
        title
    );

    const rows =
        data.map(
            item => {
                const label =
                    item.label ||
                    item.name ||
                    item.key ||
                    item.beneficiary ||
                    item.beneficiaryName ||
                    item.program ||
                    "—";

                const value =
                    item.value ??
                    item.count ??
                    item.total ??
                    0;

                return {
                    "Item":
                        label,

                    "Value":
                        formatNumber(
                            value
                        )
                };
            }
        );

    drawPdfTable(
        doc,
        [
            "Item",
            "Value"
        ],
        rows
    );
};


const getChartDataArray = (
    charts,
    possibleKeys
) => {
    if (
        !charts ||
        typeof charts !== "object"
    ) {
        return [];
    }

    for (
        const key of possibleKeys
    ) {
        if (
            Array.isArray(
                charts[key]
            ) &&
            charts[key].length
        ) {
            return charts[key];
        }
    }

    return [];
};


const renderReportChartsPdf = (
    doc,
    report
) => {
    const charts =
        report?.charts;

    if (
        !charts ||
        typeof charts !== "object"
    ) {
        return;
    }

    pdfSectionTitle(
        doc,
        "Charts"
    );

    Object.entries(
        charts
    ).forEach(
        ([name, data]) => {
            if (
                !Array.isArray(data) ||
                !data.length
            ) {
                return;
            }

            const rows =
                data.map(
                    item => {
                        const keys =
                            Object.keys(
                                item || {}
                            );

                        const labelKey =
                            keys.find(
                                key =>
                                    [
                                        "label",
                                        "name",
                                        "key",
                                        "beneficiary",
                                        "beneficiaryName",
                                        "program",
                                        "status",
                                        "gender"
                                    ].includes(
                                        key
                                    )
                            );

                        const valueKey =
                            keys.find(
                                key =>
                                    [
                                        "value",
                                        "count",
                                        "total",
                                        "services",
                                        "supportValue"
                                    ].includes(
                                        key
                                    )
                            );

                        return {
                            "Item":
                                labelKey
                                    ? normalizeTextValue(
                                        item[labelKey]
                                    )
                                    : "—",

                            "Value":
                                valueKey
                                    ? normalizeTextValue(
                                        item[valueKey]
                                    )
                                    : "—"
                        };
                    }
                );

            pdfSectionTitle(
                doc,
                formatLabel(
                    name
                )
            );

            drawPdfTable(
                doc,
                [
                    "Item",
                    "Value"
                ],
                rows
            );
        }
    );
};


// =====================================================
// BENEFICIARY PROGRAM PDF
// =====================================================

const renderBeneficiaryProgramsPdf = (
    doc,
    beneficiary
) => {
    pdfSectionTitle(
        doc,
        "4. Program Participation"
    );

    const programs =
        getBeneficiaryPrograms(
            beneficiary
        );

    if (
        !programs.length
    ) {
        doc
            .font(
                "Helvetica"
            )
            .fontSize(
                8.5
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                "No program participation found."
            );

        doc.moveDown(
            0.4
        );

        return;
    }

    const rows =
        programs.map(
            program => ({
                "Program":
                    getProgramName(
                        program
                    ),

                "Program Code":
                    getProgramCode(
                        program
                    ),

                "Category":
                    normalizeTextValue(
                        program.category
                    ),

                "Start Date":
                    formatDate(
                        program.startDate
                    ),

                "End Date":
                    formatDate(
                        program.endDate
                    ),

                "Status":
                    normalizeTextValue(
                        program.status
                    )
            })
        );

    drawPdfTable(
        doc,
        [
            "Program",
            "Program Code",
            "Category",
            "Start Date",
            "End Date",
            "Status"
        ],
        rows
    );
};


// =====================================================
// BENEFICIARY ENTERPRISE PDF
// =====================================================

const renderBeneficiaryEnterprisePdf = (
    doc,
    beneficiary
) => {
    pdfSectionTitle(
        doc,
        "3. Enterprise Membership"
    );

    const memberships =
        Array.isArray(
            beneficiary.enterprises
        )
            ? beneficiary.enterprises
            : [];

    if (
        !memberships.length
    ) {
        doc
            .font(
                "Helvetica"
            )
            .fontSize(
                8.5
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                "No enterprise membership found."
            );

        doc.moveDown(
            0.4
        );

        return;
    }

    const rows =
        memberships.map(
            membership => {
                const enterprise =
                    resolveMembershipEnterprise(
                        membership
                    );

                return {
                    "Enterprise":
                        getEnterpriseName(
                            enterprise,
                            membership
                        ),

                    "Enterprise Code":
                        getEnterpriseCode(
                            enterprise,
                            membership
                        ),

                    "Membership Role":
                        normalizeTextValue(
                            membership.memberRole
                        ),

                    "Joined Date":
                        formatDate(
                            membership.joinedDate
                        ),

                    "Left Date":
                        formatDate(
                            membership.leftDate
                        ),

                    "Status":
                        normalizeTextValue(
                            membership.status
                        )
                };
            }
        );

    drawPdfTable(
        doc,
        [
            "Enterprise",
            "Enterprise Code",
            "Membership Role",
            "Joined Date",
            "Left Date",
            "Status"
        ],
        rows
    );
};


// =====================================================
// BENEFICIARY ENROLLMENT PDF
// =====================================================

const renderBeneficiaryEnrollmentsPdf = (
    doc,
    beneficiary
) => {
    pdfSectionTitle(
        doc,
        "5. Enrollment History"
    );

    const enrollments =
        Array.isArray(
            beneficiary.enrollments
        )
            ? beneficiary.enrollments
            : [];

    if (
        !enrollments.length
    ) {
        doc
            .font(
                "Helvetica"
            )
            .fontSize(
                8.5
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                "No enrollment history available."
            );

        doc.moveDown(
            0.4
        );

        return;
    }

    const rows =
        enrollments.map(
            enrollment => {
                const program =
                    resolveEnrollmentProgram(
                        enrollment
                    );

                const programName =
                    getProgramName(
                        program,
                        enrollment
                    );

                const programCode =
                    getProgramCode(
                        program,
                        enrollment
                    );

                return {
                    "Date":
                        formatDate(
                            enrollment.enrollmentDate
                        ),

                    "Program":
                        programCode !== "—"
                            ? `${programName} (${programCode})`
                            : programName,

                    "Status":
                        normalizeTextValue(
                            enrollment.status
                        ),

                    "Completion":
                        formatDate(
                            enrollment.completionDate
                        ),

                    "Exit Reason":
                        normalizeTextValue(
                            enrollment.exitReason
                        )
                };
            }
        );

    drawPdfTable(
        doc,
        [
            "Date",
            "Program",
            "Status",
            "Completion",
            "Exit Reason"
        ],
        rows
    );
};


// =====================================================
// BENEFICIARY SERVICE PDF
// =====================================================

const renderBeneficiaryServicePdf = (
    doc,
    beneficiary
) => {
    pdfSectionTitle(
        doc,
        "6. Services Received"
    );

    const services =
        getBeneficiaryServices(
            beneficiary
        );

    if (
        !services.length
    ) {
        doc
            .font(
                "Helvetica"
            )
            .fontSize(
                8.5
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                "No services received."
            );

        doc.moveDown(
            0.4
        );

        return;
    }

    services.forEach(
        (
            serviceEntry,
            serviceIndex
        ) => {
            const service =
                resolveServiceEntry(
                    serviceEntry
                );

            if (!service) {
                return;
            }

            const program =
                resolveServiceProgram(
                    service,
                    beneficiary
                );

            const project =
                resolveServiceProject(
                    service
                );

            const activity =
                resolveServiceActivity(
                    service
                );

            const activityRun =
                resolveServiceActivityRun(
                    service
                );

            const deliveryNumber =
                getBusinessCode(
                    service,
                    [
                        "deliveryNumber"
                    ]
                ) ||
                getBusinessCode(
                    serviceEntry,
                    [
                        "deliveryNumber"
                    ]
                ) ||
                `Service ${serviceIndex + 1}`;

            const deliveryDate =
                service.deliveryDate ||
                serviceEntry?.deliveryDate;

            const programName =
                getProgramName(
                    program,
                    service
                );

            const programCode =
                getProgramCode(
                    program,
                    service
                );

            const projectName =
                getDisplayName(
                    project,
                    "—"
                );

            const projectCode =
                getBusinessCode(
                    project,
                    [
                        "projectCode",
                        "code"
                    ]
                );

            const activityName =
                getDisplayName(
                    activity,
                    "—"
                );

            const activityCode =
                getBusinessCode(
                    activity,
                    [
                        "activityCode",
                        "code"
                    ]
                );

            const activityRunName =
                getDisplayName(
                    activityRun,
                    "—"
                );

            const activityRunCode =
                getBusinessCode(
                    activityRun,
                    [
                        "runCode",
                        "code"
                    ]
                );

            const location =
                formatDeliveryLocation(service) ||
                formatDeliveryLocation(serviceEntry);

            const status =
                service.status ||
                serviceEntry?.status;

            const serviceTypes =
                getServiceTypes(
                    service
                );

            pdfEnsureSpace(
                doc,
                180
            );

            doc
                .font(
                    "Helvetica-Bold"
                )
                .fontSize(
                    10
                )
                .fillColor(
                    PDF_COLORS.heading
                )
                .text(
                    `${deliveryNumber} — ${formatDate(deliveryDate)}`
                );

            doc.moveDown(
                0.2
            );

            doc
                .font(
                    "Helvetica-Bold"
                )
                .fontSize(
                    8.5
                )
                .fillColor(
                    PDF_COLORS.text
                )
                .text(
                    programCode !== "—"
                        ? `${programName} (${programCode})`
                        : programName
                );

            doc.moveDown(
                0.25
            );

            pdfKeyValueGrid(
                doc,
                {
                    "Delivery No.":
                        deliveryNumber,

                    "Delivery Date":
                        formatDate(
                            deliveryDate
                        ),

                    "Program":
                        programCode !== "—"
                            ? `${programName} (${programCode})`
                            : programName,

                    "Project":
                        projectCode
                            ? `${projectName} (${projectCode})`
                            : projectName,

                    "Activity":
                        activityCode
                            ? `${activityName} (${activityCode})`
                            : activityName,

                    "Activity Run":
                        activityRunCode
                            ? `${activityRunName} (${activityRunCode})`
                            : activityRunName,

                    "Location":
                        location,

                    "Status":
                        status,

                    "Service Types":
                        serviceTypes.join(
                            ", "
                        ) || "—"
                }
            );

            const items =
                getServiceItems(
                    service
                );

            pdfSectionTitle(
                doc,
                "Service Items"
            );

            if (
                items.length
            ) {
                const itemRows =
                    items.map(
                        item => {
                            const quantity =
                                Number(
                                    item.quantity
                                ) || 0;

                            const unitCost =
                                Number(
                                    item.unitCost
                                ) || 0;

                            const totalCost =
                                Number(
                                    item.totalCost
                                ) ||
                                (
                                    quantity *
                                    unitCost
                                );

                            return {
                                "Service Category":
                                    normalizeTextValue(
                                        item.serviceCategory
                                    ),

                                "Service Type":
                                    normalizeTextValue(
                                        item.serviceType
                                    ),

                                "Item / Remarks":
                                    normalizeTextValue(
                                        item.remarks ||
                                        item.description ||
                                        item.item ||
                                        item.itemName
                                    ),

                                "Quantity":
                                    formatNumber(
                                        quantity
                                    ),

                                "Unit":
                                    normalizeTextValue(
                                        item.unit
                                    ),

                                "Unit Cost":
                                    formatCurrency(
                                        unitCost
                                    ),

                                "Total Cost":
                                    formatCurrency(
                                        totalCost
                                    )
                            };
                        }
                    );

                drawPdfTable(
                    doc,
                    [
                        "Service Category",
                        "Service Type",
                        "Item / Remarks",
                        "Quantity",
                        "Unit",
                        "Unit Cost",
                        "Total Cost"
                    ],
                    itemRows
                );
            }
            else {
                doc
                    .font(
                        "Helvetica-Oblique"
                    )
                    .fontSize(
                        8
                    )
                    .fillColor(
                        PDF_COLORS.muted
                    )
                    .text(
                        "No service items recorded."
                    );

                doc.moveDown(
                    0.3
                );
            }

            pdfLabelValue(
                doc,
                "Beneficiary Support Value",
                formatCurrency(
                    getServiceTotal(
                        service
                    )
                )
            );

            doc.moveDown(
                0.4
            );

            doc
                .moveTo(
                    DEFAULT_PAGE_MARGIN,
                    doc.y
                )
                .lineTo(
                    doc.page.width -
                        DEFAULT_PAGE_MARGIN,
                    doc.y
                )
                .strokeColor(
                    PDF_COLORS.border
                )
                .stroke();

            doc.moveDown(
                0.5
            );
        }
    );
};


// =====================================================
// BENEFICIARY SUMMARY
// =====================================================

const calculateBeneficiarySummary = (
    beneficiary
) => {
    const enrollments =
        Array.isArray(
            beneficiary.enrollments
        )
            ? beneficiary.enrollments
            : [];

    const services =
        getBeneficiaryServices(
            beneficiary
        );

    const programs =
        getBeneficiaryPrograms(
            beneficiary
        );

    const totalSupportValue =
        services.reduce(
            (
                total,
                serviceEntry
            ) => {
                const service =
                    resolveServiceEntry(
                        serviceEntry
                    );

                return (
                    total +
                    getServiceTotal(
                        service
                    )
                );
            },
            0
        );

    return {
        enrollmentCount:
            enrollments.length,

        totalServices:
            services.length,

        totalSupportValue,

        programs:
            programs.length
    };
};


const renderBeneficiarySummary = (
    doc,
    beneficiary
) => {
    const summary =
        calculateBeneficiarySummary(
            beneficiary
        );

    pdfSectionTitle(
        doc,
        "Beneficiary Summary"
    );

    pdfKeyValueGrid(
        doc,
        {
            "Enrollment Count":
                summary.enrollmentCount,

            "Total Services":
                summary.totalServices,

            "Total Support Value":
                formatCurrency(
                    summary.totalSupportValue
                ),

            "Programs":
                summary.programs
        }
    );
};


// =====================================================
// BENEFICIARY DETAIL PDF
// =====================================================

const renderBeneficiaryDetailPdf = (
    doc,
    beneficiary,
    index
) => {
    const beneficiaryNumber =
        getBeneficiaryNumber(
            beneficiary
        );

    const beneficiaryName =
        getBeneficiaryName(
            beneficiary
        );

    pdfEnsureSpace(
        doc,
        100
    );

    doc
        .font(
            "Helvetica-Bold"
        )
        .fontSize(
            14
        )
        .fillColor(
            PDF_COLORS.heading
        )
        .text(
            `${beneficiaryNumber} — ${beneficiaryName}`
        );

    doc.moveDown(
        0.25
    );

    pdfSectionTitle(
        doc,
        "Beneficiary Details"
    );

    pdfSectionTitle(
        doc,
        "1. Personal & Demographic Information"
    );

    pdfKeyValueGrid(
        doc,
        {
            "Beneficiary Number":
                beneficiaryNumber,

            "Full Name":
                beneficiaryName,

            "Gender":
                beneficiary.gender,

            "Date of Birth":
                formatDate(
                    beneficiary.dateOfBirth
                ),

            "Age":
                beneficiary.age,

            "Phone":
                beneficiary.phone,

            "Alternative Phone":
                beneficiary.alternativePhone,

            "Email":
                beneficiary.email,

            "Education":
                beneficiary.educationLevel,

            "Occupation":
                beneficiary.occupation,

            "Marital Status":
                beneficiary.maritalStatus,

            "Disability":
                beneficiary.disabilityType,

            "Vulnerable Groups":
                formatArrayForCell(
                    beneficiary.vulnerableGroups
                ),

            "Status":
                beneficiary.status
        }
    );

    pdfSectionTitle(
        doc,
        "2. Location"
    );

    pdfKeyValueGrid(
        doc,
        {
            "Country":
                beneficiary.country ||
                beneficiary.location?.country,

            "Region":
                beneficiary.region ||
                beneficiary.location?.region,

            "Zone":
                beneficiary.zone ||
                beneficiary.location?.zone,

            "Woreda":
                beneficiary.woreda ||
                beneficiary.location?.woreda,

            "Kebele":
                beneficiary.kebele ||
                beneficiary.location?.kebele,

            "Address":
                beneficiary.address ||
                beneficiary.location?.address
        }
    );

    renderBeneficiaryEnterprisePdf(
        doc,
        beneficiary
    );

    renderBeneficiaryProgramsPdf(
        doc,
        beneficiary
    );

    renderBeneficiaryEnrollmentsPdf(
        doc,
        beneficiary
    );

    renderBeneficiaryServicePdf(
        doc,
        beneficiary
    );

    renderBeneficiarySummary(
        doc,
        beneficiary
    );

    if (
        index <
        MAX_PDF_DETAIL_ROWS - 1
    ) {
        doc.addPage();
    }
};


// =====================================================
// BENEFICIARY PDF
// =====================================================

const renderBeneficiaryPdf = (
    doc,
    report
) => {
    const details =
        Array.isArray(
            report.details
        )
            ? report.details
            : [];

    if (
        !details.length
    ) {
        doc
            .font(
                "Helvetica-Oblique"
            )
            .fontSize(
                9
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                "No beneficiary records available."
            );

        return;
    }

    details
        .slice(
            0,
            MAX_PDF_DETAIL_ROWS
        )
        .forEach(
            (
                beneficiary,
                index
            ) => {
                renderBeneficiaryDetailPdf(
                    doc,
                    beneficiary,
                    index
                );
            }
        );
};

// =====================================================
// SERVICE DELIVERY REPORT DETECTION
// =====================================================

const isServiceDeliveryReport = (
    report
) => {

    const identity = [
        report?.reportName,
        report?.name,
        report?.code,
        report?.title,
        report?.reportType,
        report?.type
    ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();

    if (
        identity.includes(
            "servicedelivery"
        ) ||
        identity.includes(
            "service delivery"
        )
    ) {
        return true;
    }

    /*
     * Fallback detection.
     *
     * Service Delivery rows have one or more
     * of these fields:
     *
     * - deliveryNumber
     * - deliveryDate
     * - items[]
     * - beneficiaries[]
     */
    if (
        Array.isArray(
            report?.data
        )
    ) {
        return report.data.some(
            row =>
                row &&
                (
                    row.deliveryNumber ||
                    row.deliveryDate ||
                    Array.isArray(
                        row.items
                    ) ||
                    Array.isArray(
                        row.beneficiaries
                    )
                )
        );
    }

    return false;
};


// =====================================================
// SERVICE DELIVERY PDF HELPERS
// =====================================================

const getServiceDeliveryRows = (
    report
) => {

    if (
        Array.isArray(
            report?.data
        )
    ) {
        return report.data;
    }

    if (
        Array.isArray(
            report?.rows
        )
    ) {
        return report.rows;
    }

    if (
        Array.isArray(
            report?.details
        )
    ) {
        return report.details;
    }

    return [];
};


const getServiceDeliveryBeneficiaryName = (
    beneficiaryRecord
) => {

    const beneficiary =
        beneficiaryRecord?.beneficiary ||
        beneficiaryRecord;

    if (
        !beneficiary
    ) {
        return "—";
    }

    return (
        getDisplayName(
            beneficiary,
            ""
        ) ||
        beneficiaryRecord?.name ||
        beneficiaryRecord?.beneficiaryName ||
        getBeneficiaryNumber(
            beneficiary
        ) ||
        "—"
    );
};


const getServiceDeliveryBeneficiaryNumber = (
    beneficiaryRecord
) => {

    const beneficiary =
        beneficiaryRecord?.beneficiary ||
        beneficiaryRecord;

    return (
        getBeneficiaryNumber(
            beneficiary
        ) ||
        beneficiaryRecord?.beneficiaryNumber ||
        "—"
    );
};


const getServiceDeliveryUnitName = (
    unit
) => {

    if (
        isNil(unit)
    ) {
        return "—";
    }

    if (
        typeof unit === "string" ||
        typeof unit === "number"
    ) {
        return String(unit);
    }

    return (
        unit.name ||
        unit.value ||
        unit.label ||
        unit.code ||
        "—"
    );
};


const getServiceDeliveryItemName = (
    item
) => {

    return (
        getDisplayName(
            item?.detail,
            ""
        ) ||
        getDisplayName(
            item,
            ""
        ) ||
        item?.itemName ||
        item?.description ||
        item?.remarks ||
        "Service Item"
    );
};


const getServiceDeliveryItemTotal = (
    item
) => {

    const quantity =
        Number(
            item?.quantity
        ) || 0;

    const unitCost =
        Number(
            item?.unitCost
        ) || 0;

    const explicitTotal =
        Number(
            item?.totalCost
        );

    if (
        Number.isFinite(
            explicitTotal
        )
    ) {
        return explicitTotal;
    }

    return (
        quantity *
        unitCost
    );
};


const getServiceDeliveryAllocatedValue = (
    item
) => {

    const allocation =
        item?.allocation || {};

    return (
        Number(
            allocation.allocatedValue
        ) || 0
    );
};


const getServiceDeliveryUnallocatedValue = (
    item
) => {

    const allocation =
        item?.allocation || {};

    if (
        allocation.unallocatedValue !==
        undefined
    ) {
        return (
            Number(
                allocation.unallocatedValue
            ) || 0
        );
    }

    const total =
        getServiceDeliveryItemTotal(
            item
        );

    const allocated =
        getServiceDeliveryAllocatedValue(
            item
        );

    return Math.max(
        0,
        total - allocated
    );
};


const getServiceDeliveryOverAllocatedValue = (
    item
) => {

    const allocation =
        item?.allocation || {};

    return (
        Number(
            allocation.overAllocatedValue
        ) || 0
    );
};


const getServiceDeliveryBeneficiaryAllocationsForItem = (
    item
) => {

    const beneficiaries =
        item?.allocation?.beneficiaries;

    if (
        !Array.isArray(
            beneficiaries
        )
    ) {
        return [];
    }

    return beneficiaries;
};


const getServiceDeliveryDetailItems = (
    item
) => {

    if (
        !Array.isArray(
            item?.detailItems
        )
    ) {
        return [];
    }

    return item.detailItems;
};


// =====================================================
// SERVICE DELIVERY PDF
// =====================================================

const renderServiceDeliveryPdf = (
    doc,
    report
) => {

    const deliveries =
        getServiceDeliveryRows(
            report
        );

    if (
        !deliveries.length
    ) {
        doc
            .font(
                "Helvetica-Oblique"
            )
            .fontSize(
                9
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                "No service delivery records available."
            );

        return;
    }


    deliveries
        .slice(
            0,
            MAX_PDF_DETAIL_ROWS
        )
        .forEach(
            (
                delivery,
                deliveryIndex
            ) => {

                /*
                 * -------------------------------------------------
                 * DELIVERY INFORMATION
                 * -------------------------------------------------
                 */

                const deliveryNumber =
                    delivery?.deliveryNumber ||
                    delivery?.deliveryNo ||
                    delivery?.id ||
                    `Delivery ${deliveryIndex + 1}`;

                const deliveryDate =
                    delivery?.deliveryDate ||
                    delivery?.date;

                const program =
                    delivery?.program;

                const project =
                    delivery?.project;

                const activity =
                    delivery?.activity;

                const activityRun =
                    delivery?.activityRun;

                const programName =
                    getProgramName(
                        program,
                        delivery
                    );

                const programCode =
                    getProgramCode(
                        program,
                        delivery
                    );

                const projectName =
                    getDisplayName(
                        project,
                        "—"
                    );

                const projectCode =
                    getBusinessCode(
                        project,
                        [
                            "projectCode",
                            "code",
                            "projectNumber"
                        ]
                    );

                const activityName =
                    getDisplayName(
                        activity,
                        "—"
                    );

                const activityCode =
                    getBusinessCode(
                        activity,
                        [
                            "activityCode",
                            "code",
                            "activityNumber"
                        ]
                    );

                const activityRunName =
                    getDisplayName(
                        activityRun,
                        "—"
                    );

                const activityRunCode =
                    getBusinessCode(
                        activityRun,
                        [
                            "runCode",
                            "activityRunCode",
                            "code",
                            "number"
                        ]
                    );

                const location =
                    formatDeliveryLocation(delivery) ||
                    "—";

                const recipientType =
                    delivery?.recipientType ||
                    "—";

                const status =
                    delivery?.status ||
                    "Delivered";

                const fundingSource =
                    delivery?.fundingSource;

                const fundingSourceName =
                    getDisplayName(
                        fundingSource,
                        "—"
                    );


                /*
                 * -------------------------------------------------
                 * DELIVERY PAGE HEADER
                 * -------------------------------------------------
                 */

                pdfEnsureSpace(
                    doc,
                    180
                );

                doc
                    .font(
                        "Helvetica-Bold"
                    )
                    .fontSize(
                        12
                    )
                    .fillColor(
                        PDF_COLORS.heading
                    )
                    .text(
                        deliveryNumber
                    );

                doc.moveDown(
                    0.15
                );

                doc
                    .font(
                        "Helvetica"
                    )
                    .fontSize(
                        8
                    )
                    .fillColor(
                        PDF_COLORS.muted
                    )
                    .text(
                        formatDate(
                            deliveryDate
                        )
                    );

                doc.moveDown(
                    0.25
                );


                /*
                 * -------------------------------------------------
                 * DELIVERY DETAILS
                 * -------------------------------------------------
                 */

                pdfKeyValueGrid(
                    doc,
                    {
                        "Delivery No.":
                            deliveryNumber,

                        "Delivery Date":
                            formatDate(
                                deliveryDate
                            ),

                        "Program":
                            programCode !== "—"
                                ? `${programName} (${programCode})`
                                : programName,

                        "Project":
                            projectCode
                                ? `${projectName} (${projectCode})`
                                : projectName,

                        "Activity":
                            activityCode
                                ? `${activityName} (${activityCode})`
                                : activityName,

                        "Activity Run":
                            activityRunCode
                                ? `${activityRunName} (${activityRunCode})`
                                : activityRunName,

                        "Recipient Type":
                            recipientType,

                        "Location":
                            location,

                        "Funding Source":
                            fundingSourceName,

                        "Status":
                            status
                    }
                );


                /*
                 * -------------------------------------------------
                 * SERVICE ITEMS
                 * -------------------------------------------------
                 */

                pdfSectionTitle(
                    doc,
                    "Service Items"
                );

                const items =
                    Array.isArray(
                        delivery?.items
                    )
                        ? delivery.items
                        : [];


                if (
                    !items.length
                ) {

                    doc
                        .font(
                            "Helvetica-Oblique"
                        )
                        .fontSize(
                            8
                        )
                        .fillColor(
                            PDF_COLORS.muted
                        )
                        .text(
                            "No service items recorded."
                        );

                    doc.moveDown(
                        0.3
                    );

                }
                else {

                    const itemRows =
                        items.map(
                            item => {

                                const quantity =
                                    Number(
                                        item?.quantity
                                    ) || 0;

                                const unit =
                                    getServiceDeliveryUnitName(
                                        item?.unit
                                    );

                                const unitCost =
                                    Number(
                                        item?.unitCost
                                    ) || 0;

                                const totalCost =
                                    getServiceDeliveryItemTotal(
                                        item
                                    );

                                const allocatedValue =
                                    getServiceDeliveryAllocatedValue(
                                        item
                                    );

                                const unallocatedValue =
                                    getServiceDeliveryUnallocatedValue(
                                        item
                                    );

                                const overAllocatedValue =
                                    getServiceDeliveryOverAllocatedValue(
                                        item
                                    );

                                const allocation =
                                    item?.allocation ||
                                    {};

                                return {

                                    "Service Category":
                                        normalizeTextValue(
                                            item?.serviceCategory
                                        ),

                                    "Service Type":
                                        normalizeTextValue(
                                            item?.serviceType
                                        ),

                                    "Item / Remarks":
                                        getServiceDeliveryItemName(
                                            item
                                        ),

                                    "Quantity":
                                        formatNumber(
                                            quantity
                                        ),

                                    "Unit":
                                        unit,

                                    "Unit Cost":
                                        formatCurrency(
                                            unitCost
                                        ),

                                    "Total Cost":
                                        formatCurrency(
                                            totalCost
                                        ),

                                    "Allocated":
                                        formatCurrency(
                                            allocatedValue
                                        ),

                                    "Unallocated":
                                        formatCurrency(
                                            unallocatedValue
                                        ),

                                    "Over Allocated":
                                        formatCurrency(
                                            overAllocatedValue
                                        ),

                                    "Allocation Status":
                                        allocation
                                            .allocationStatus ||
                                        "—"
                                };
                            }
                        );


                    drawPdfTable(
                        doc,
                        [
                            "Service Category",
                            "Service Type",
                            "Item / Remarks",
                            "Quantity",
                            "Unit",
                            "Unit Cost",
                            "Total Cost",
                            "Allocated",
                            "Unallocated",
                            "Over Allocated",
                            "Allocation Status"
                        ],
                        itemRows
                    );
                }


                /*
                 * -------------------------------------------------
                 * SUPPORTING DETAIL ITEMS
                 *
                 * IMPORTANT:
                 *
                 * These are audit/supporting records.
                 * They are NOT added again to delivery totals.
                 * -------------------------------------------------
                 */

                const detailRows = [];

                items.forEach(
                    item => {

                        const detailItems =
                            getServiceDeliveryDetailItems(
                                item
                            );

                        detailItems.forEach(
                            detail => {

                                const quantity =
                                    Number(
                                        detail?.quantity
                                    ) || 0;

                                const unit =
                                    getServiceDeliveryUnitName(
                                        detail?.unit
                                    );

                                const unitCost =
                                    Number(
                                        detail?.unitCost
                                    ) || 0;

                                const totalCost =
                                    Number(
                                        detail?.totalCost
                                    );

                                detailRows.push({

                                    "Parent Service":
                                        getServiceDeliveryItemName(
                                            item
                                        ),

                                    "Detail Item":
                                        getDisplayName(
                                            detail?.item ||
                                            detail,
                                            ""
                                        ) ||
                                        detail?.itemName ||
                                        detail?.description ||
                                        detail?.remarks ||
                                        "—",

                                    "Quantity":
                                        formatNumber(
                                            quantity
                                        ),

                                    "Unit":
                                        unit,

                                    "Unit Cost":
                                        formatCurrency(
                                            unitCost
                                        ),

                                    "Detail Value":
                                        formatCurrency(
                                            Number.isFinite(
                                                totalCost
                                            )
                                                ? totalCost
                                                : quantity *
                                                  unitCost
                                        )
                                });
                            }
                        );
                    }
                );


                if (
                    detailRows.length
                ) {

                    pdfSectionTitle(
                        doc,
                        "Supporting Detail Items"
                    );

                    drawPdfTable(
                        doc,
                        [
                            "Parent Service",
                            "Detail Item",
                            "Quantity",
                            "Unit",
                            "Unit Cost",
                            "Detail Value"
                        ],
                        detailRows
                    );

                    doc
                        .font(
                            "Helvetica-Oblique"
                        )
                        .fontSize(
                            7
                        )
                        .fillColor(
                            PDF_COLORS.muted
                        )
                        .text(
                            "Supporting detail values are shown for audit purposes and are not added again to the parent service item totals."
                        );

                    doc.moveDown(
                        0.4
                    );
                }


                /*
                 * -------------------------------------------------
                 * ITEM-LEVEL BENEFICIARY ALLOCATIONS
                 * -------------------------------------------------
                 */

                const itemBeneficiaryRows = [];

                items.forEach(
                    item => {

                        const allocations =
                            getServiceDeliveryBeneficiaryAllocationsForItem(
                                item
                            );

                        allocations.forEach(
                            allocation => {

                                const beneficiary =
                                    allocation?.beneficiary ||
                                    allocation?.beneficiaryData ||
                                    null;

                                const quantity =
                                    Number(
                                        allocation?.quantity
                                    ) || 0;

                                const allocatedValue =
                                    Number(
                                        allocation?.allocatedValue
                                    ) || 0;

                                itemBeneficiaryRows.push({

                                    "Service Item":
                                        getServiceDeliveryItemName(
                                            item
                                        ),

                                    "Beneficiary No.":
                                        getServiceDeliveryBeneficiaryNumber(
                                            allocation
                                        ),

                                    "Beneficiary":
                                        getServiceDeliveryBeneficiaryName(
                                            allocation
                                        ),

                                    "Quantity":
                                        quantity
                                            ? formatNumber(
                                                quantity
                                            )
                                            : "—",

                                    "Unit":
                                        getServiceDeliveryUnitName(
                                            item?.unit
                                        ),

                                    "Allocated Value":
                                        formatCurrency(
                                            allocatedValue
                                        ),

                                    "Remarks":
                                        normalizeTextValue(
                                            allocation?.remarks
                                        )
                                });
                            }
                        );
                    }
                );


                if (
                    itemBeneficiaryRows.length
                ) {

                    pdfSectionTitle(
                        doc,
                        "Beneficiary Allocation by Service Item"
                    );

                    drawPdfTable(
                        doc,
                        [
                            "Service Item",
                            "Beneficiary No.",
                            "Beneficiary",
                            "Quantity",
                            "Unit",
                            "Allocated Value",
                            "Remarks"
                        ],
                        itemBeneficiaryRows
                    );
                }


                /*
                 * -------------------------------------------------
                 * DELIVERY TOTALS
                 *
                 * Parent service items are authoritative.
                 * Detail items are never added here.
                 * -------------------------------------------------
                 */

                const totalSupportValue =
                    items.reduce(
                        (
                            total,
                            item
                        ) =>
                            total +
                            getServiceDeliveryItemTotal(
                                item
                            ),
                        0
                    );

                const totalAllocatedValue =
                    items.reduce(
                        (
                            total,
                            item
                        ) =>
                            total +
                            getServiceDeliveryAllocatedValue(
                                item
                            ),
                        0
                    );

                const totalUnallocatedValue =
                    items.reduce(
                        (
                            total,
                            item
                        ) =>
                            total +
                            getServiceDeliveryUnallocatedValue(
                                item
                            ),
                        0
                    );

                const totalOverAllocatedValue =
                    items.reduce(
                        (
                            total,
                            item
                        ) =>
                            total +
                            getServiceDeliveryOverAllocatedValue(
                                item
                            ),
                        0
                    );


                pdfSectionTitle(
                    doc,
                    "Delivery Allocation Summary"
                );

                pdfKeyValueGrid(
                    doc,
                    {
                        "Actual Support Value":
                            formatCurrency(
                                totalSupportValue
                            ),

                        "Allocated Value":
                            formatCurrency(
                                totalAllocatedValue
                            ),

                        "Unallocated Value":
                            formatCurrency(
                                totalUnallocatedValue
                            ),

                        "Over Allocated Value":
                            formatCurrency(
                                totalOverAllocatedValue
                            ),

                        "Allocation Rate":
                            totalSupportValue > 0
                                ? `${(
                                    (
                                        totalAllocatedValue /
                                        totalSupportValue
                                    ) *
                                    100
                                ).toFixed(2)}%`
                                : "0%"
                    }
                );


                /*
                 * -------------------------------------------------
                 * WHO RECEIVED THIS SERVICE
                 * -------------------------------------------------
                 */

                const beneficiaries =
                    Array.isArray(
                        delivery?.beneficiaries
                    )
                        ? delivery.beneficiaries
                        : [];


                pdfSectionTitle(
                    doc,
                    "Who Received This Service"
                );


                if (
                    !beneficiaries.length
                ) {

                    doc
                        .font(
                            "Helvetica-Oblique"
                        )
                        .fontSize(
                            8
                        )
                        .fillColor(
                            PDF_COLORS.muted
                        )
                        .text(
                            "No beneficiary allocation records found."
                        );

                    doc.moveDown(
                        0.3
                    );

                }
                else {

                    const beneficiaryRows =
                        beneficiaries.map(
                            record => {

                                const allocations =
                                    Array.isArray(
                                        record?.allocations
                                    )
                                        ? record.allocations
                                        : [];

                                const totalQuantity =
                                    Number(
                                        record?.totalAllocatedQuantity
                                    ) ||
                                    allocations.reduce(
                                        (
                                            total,
                                            allocation
                                        ) =>
                                            total +
                                            (
                                                Number(
                                                    allocation?.quantity
                                                ) || 0
                                            ),
                                        0
                                    );

                                const totalValue =
                                    Number(
                                        record?.totalAllocatedValue
                                    ) ||
                                    allocations.reduce(
                                        (
                                            total,
                                            allocation
                                        ) =>
                                            total +
                                            (
                                                Number(
                                                    allocation?.allocatedValue
                                                ) || 0
                                            ),
                                        0
                                    );

                                const allocationText =
                                    allocations
                                        .map(
                                            allocation => {

                                                const serviceItem =
                                                    allocation?.serviceItem;

                                                const serviceItemId =
                                                    objectIdToString(
                                                        serviceItem
                                                    );

                                                const matchingItem =
                                                    items.find(
                                                        item =>
                                                            String(
                                                                item?.id ||
                                                                item?._id
                                                            ) ===
                                                            String(
                                                                serviceItemId
                                                            )
                                                    );

                                                const itemName =
                                                    matchingItem
                                                        ? getServiceDeliveryItemName(
                                                            matchingItem
                                                        )
                                                        : "Service";

                                                const quantity =
                                                    Number(
                                                        allocation?.quantity
                                                    ) || 0;

                                                const value =
                                                    Number(
                                                        allocation?.allocatedValue
                                                    ) || 0;

                                                return (
                                                    `${itemName}: ` +
                                                    `${quantity ? formatNumber(quantity) : "—"} ` +
                                                    `(${formatCurrency(value)})`
                                                );
                                            }
                                        )
                                        .join(
                                            "\n"
                                        );

                                return {

                                    "Beneficiary No.":
                                        getServiceDeliveryBeneficiaryNumber(
                                            record
                                        ),

                                    "Beneficiary":
                                        getServiceDeliveryBeneficiaryName(
                                            record
                                        ),

                                    "Status":
                                        normalizeTextValue(
                                            record?.status
                                        ),

                                    "Allocated Quantity":
                                        totalQuantity
                                            ? formatNumber(
                                                totalQuantity
                                            )
                                            : "—",

                                    "Allocated Value":
                                        formatCurrency(
                                            totalValue
                                        ),

                                    "Services Received":
                                        allocationText ||
                                        "—",

                                    "Remarks":
                                        normalizeTextValue(
                                            record?.remarks
                                        )
                                };
                            }
                        );


                    drawPdfTable(
                        doc,
                        [
                            "Beneficiary No.",
                            "Beneficiary",
                            "Status",
                            "Allocated Quantity",
                            "Allocated Value",
                            "Services Received",
                            "Remarks"
                        ],
                        beneficiaryRows
                    );
                }


                /*
                 * -------------------------------------------------
                 * PAGE SEPARATOR
                 * -------------------------------------------------
                 */

                if (
                    deliveryIndex <
                    deliveries.length - 1
                ) {

                    doc
                        .moveTo(
                            DEFAULT_PAGE_MARGIN,
                            doc.y
                        )
                        .lineTo(
                            doc.page.width -
                                DEFAULT_PAGE_MARGIN,
                            doc.y
                        )
                        .strokeColor(
                            PDF_COLORS.border
                        )
                        .stroke();

                    doc.moveDown(
                        0.6
                    );
                }
            }
        );


    /*
     * -------------------------------------------------
     * TRUNCATION NOTICE
     * -------------------------------------------------
     */

    if (
        deliveries.length >
        MAX_PDF_DETAIL_ROWS
    ) {

        doc.moveDown(
            0.4
        );

        doc
            .font(
                "Helvetica-Oblique"
            )
            .fontSize(
                7
            )
            .fillColor(
                PDF_COLORS.muted
            )
            .text(
                `Showing first ${MAX_PDF_DETAIL_ROWS} of ${deliveries.length} service delivery records.`
            );
    }
};


// =====================================================
// GENERIC PDF
// =====================================================

const renderGenericPdf = (
    doc,
    report
) => {

    const details =
        Array.isArray(
            report?.details
        )
            ? report.details
            : [];


    if (
        !details.length
    ) {
        return;
    }


    pdfSectionTitle(
        doc,
        "Details"
    );


    const firstRow =
        details[0];


    if (
        !firstRow ||
        typeof firstRow !== "object"
    ) {
        return;
    }


    const normalizedFirst =
        normalizeObjectForExcel(
            firstRow
        );


    const columns =
        Object.keys(
            normalizedFirst
        ).slice(
            0,
            8
        );


    if (
        !columns.length
    ) {
        return;
    }


    const rows =
        details
            .slice(
                0,
                MAX_PDF_DETAIL_ROWS
            )
            .map(
                row => {

                    const normalized =
                        normalizeObjectForExcel(
                            row
                        );

                    return Object.fromEntries(
                        columns.map(
                            column => [
                                column,
                                normalized[
                                    column
                                ]
                            ]
                        )
                    );
                }
            );


    drawPdfTable(
        doc,
        columns,
        rows
    );
};


// =====================================================
// PDF HEADER
// =====================================================

const renderPdfHeader = (
    doc,
    report,
    context
) => {

    const organizationName =
        context.organization?.name ||
        "—";


    doc
        .font(
            "Helvetica-Bold"
        )
        .fontSize(
            19
        )
        .fillColor(
            PDF_COLORS.heading
        )
        .text(
            COMPANY_NAME
        );


    doc
        .font(
            "Helvetica"
        )
        .fontSize(
            10
        )
        .fillColor(
            PDF_COLORS.muted
        )
        .text(
            PLATFORM_NAME
        );


    doc.moveDown(
        0.1
    );


    doc
        .font(
            "Helvetica-Bold"
        )
        .fontSize(
            11
        )
        .fillColor(
            PDF_COLORS.text
        )
        .text(
            SYSTEM_NAME
        );


    doc.moveDown(
        0.4
    );


    doc
        .font(
            "Helvetica-Bold"
        )
        .fontSize(
            15
        )
        .fillColor(
            PDF_COLORS.heading
        )
        .text(
            report.title ||
            "NGO Report"
        );


    doc.moveDown(
        0.25
    );


    pdfKeyValueGrid(
        doc,
        {
            "Organization":
                organizationName,

            "Generated":
                formatDateTime(
                    new Date()
                ),

            "Reporting Period":
                buildReportPeriodText(
                    report
                )
        }
    );


    doc.moveDown(
        0.4
    );


    doc
        .moveTo(
            DEFAULT_PAGE_MARGIN,
            doc.y
        )
        .lineTo(
            doc.page.width -
                DEFAULT_PAGE_MARGIN,
            doc.y
        )
        .strokeColor(
            PDF_COLORS.border
        )
        .lineWidth(
            1
        )
        .stroke();


    doc.moveDown(
        0.7
    );
};


// =====================================================
// PDF SUMMARY
// =====================================================

const renderPdfSummary = (
    doc,
    report
) => {

    if (
        !report?.summary ||
        typeof report.summary !== "object"
    ) {
        return;
    }


    const entries =
        Object.entries(
            report.summary
        );


    if (
        !entries.length
    ) {
        return;
    }


    pdfSectionTitle(
        doc,
        "Summary"
    );


    entries.forEach(
        (
            [key, value]
        ) => {

            let displayValue =
                value;


            if (
                typeof value === "number"
            ) {
                displayValue =
                    formatNumber(
                        value
                    );
            }
            else if (
                Array.isArray(
                    value
                )
            ) {
                displayValue =
                    value
                        .map(
                            item =>
                                normalizeTextValue(
                                    item
                                )
                        )
                        .join(
                            ", "
                        );
            }
            else if (
                value &&
                typeof value === "object"
            ) {
                displayValue =
                    Object.entries(
                        value
                    )
                        .map(
                            (
                                [
                                    childKey,
                                    childValue
                                ]
                            ) =>
                                `${formatLabel(childKey)}: ${normalizeTextValue(childValue)}`
                        )
                        .join(
                            " | "
                        );
            }


            pdfLabelValue(
                doc,
                formatLabel(
                    key
                ),
                displayValue
            );
        }
    );
};


// =====================================================
// PDF CHARTS
// =====================================================

const renderPdfCharts = (
    doc,
    report
) => {

    if (
        !report?.charts ||
        typeof report.charts !== "object"
    ) {
        return;
    }


    const chartEntries =
        Object.entries(
            report.charts
        )
            .filter(
                (
                    [
                        ,
                        data
                    ]
                ) =>
                    Array.isArray(
                        data
                    ) &&
                    data.length
            );


    if (
        !chartEntries.length
    ) {
        return;
    }


    pdfSectionTitle(
        doc,
        "Charts"
    );


    chartEntries.forEach(
        (
            [
                name,
                data
            ]
        ) => {

            const rows =
                data.map(
                    item => {

                        const keys =
                            Object.keys(
                                item || {}
                            );


                        const labelKey =
                            keys.find(
                                key =>
                                    [
                                        "label",
                                        "name",
                                        "key",
                                        "beneficiary",
                                        "beneficiaryName",
                                        "program",
                                        "status",
                                        "gender"
                                    ].includes(
                                        key
                                    )
                            );


                        const valueKey =
                            keys.find(
                                key =>
                                    [
                                        "value",
                                        "count",
                                        "total",
                                        "services",
                                        "supportValue"
                                    ].includes(
                                        key
                                    )
                            );


                        return {

                            "Label":
                                labelKey
                                    ? normalizeTextValue(
                                        item[
                                            labelKey
                                        ]
                                    )
                                    : "—",

                            "Value":
                                valueKey
                                    ? normalizeTextValue(
                                        item[
                                            valueKey
                                        ]
                                    )
                                    : "—"
                        };
                    }
                );


            pdfSectionTitle(
                doc,
                formatLabel(
                    name
                )
            );


            drawPdfTable(
                doc,
                [
                    "Label",
                    "Value"
                ],
                rows
            );
        }
    );
};


// =====================================================
// PDF EXPORT
// =====================================================

const exportPDF = (
    report,
    context
) => {

    return new Promise(
        resolve => {

            const doc =
                new PDFDocument({
                    margin:
                        DEFAULT_PAGE_MARGIN,

                    size:
                        "A4",

                    info: {
                        Title:
                            report.title ||
                            "NGO Report",

                        Author:
                            COMPANY_NAME,

                        Subject:
                            "NGO Management Report"
                    }
                });


            const buffers = [];


            doc.on(
                "data",
                chunk => {
                    buffers.push(
                        chunk
                    );
                }
            );


            doc.on(
                "end",
                () => {

                    resolve(
                        Buffer.concat(
                            buffers
                        )
                    );
                }
            );


            // =================================================
            // HEADER
            // =================================================

            renderPdfHeader(
                doc,
                report,
                context
            );


            // =================================================
            // SUMMARY
            //
            // IMPORTANT:
            // Summary is rendered ONLY HERE.
            // Generic PDF must NOT render it again.
            // =================================================

            renderPdfSummary(
                doc,
                report
            );


            // =================================================
            // CHARTS
            //
            // Charts are rendered ONLY HERE.
            // Generic PDF must NOT render them again.
            // =================================================

            renderPdfCharts(
                doc,
                report
            );


            // =================================================
            // REPORT DETAILS
            // =================================================

            if (
                isServiceDeliveryReport(
                    report
                )
            ) {

                renderServiceDeliveryPdf(
                    doc,
                    report
                );

            }
            else if (
                isBeneficiaryReport(
                    report
                )
            ) {

                renderBeneficiaryPdf(
                    doc,
                    report
                );

            }
            else {

                renderGenericPdf(
                    doc,
                    report
                );
            }


            // =================================================
            // FOOTER
            // =================================================

            const range =
                doc.bufferedPageRange();


            for (
                let pageIndex =
                    range.start;

                pageIndex <
                range.start +
                    range.count;

                pageIndex++
            ) {

                doc.switchToPage(
                    pageIndex
                );


                doc
                    .font(
                        "Helvetica"
                    )
                    .fontSize(
                        7
                    )
                    .fillColor(
                        PDF_COLORS.muted
                    )
                    .text(
                        `${context.organization?.name || COMPANY_NAME} | ${SYSTEM_NAME} | Page ${pageIndex + 1}`,
                        DEFAULT_PAGE_MARGIN,
                        doc.page.height - 25,
                        {
                            align:
                                "center",

                            width:
                                doc.page.width -
                                (
                                    DEFAULT_PAGE_MARGIN *
                                    2
                                )
                        }
                    );
            }


            doc.end();
        }
    );
};
// =====================================================
// EXPORT
// =====================================================

module.exports = {
    exportExcel,
    exportCSV,
    exportPDF
};