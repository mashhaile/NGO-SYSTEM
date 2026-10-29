import {
    useEffect,
    useMemo,
    useState
} from "react";


import {
    Alert,
    Box,
    Divider,
    Typography
} from "@mui/material";


import {
    Delete,
    Add
} from "@mui/icons-material";


import {
    AppSelect,
    AppTextField,
    AppButton
} from "../../../components/ui";


import {
    useServiceTypes,
    useLookupsByModuleAndCategory
} from "../../lookups/hooks/useLookups";


import {
    getDonorsLookupService
} from "../../donors/services/DonorService";


import {
    useQuery
} from "@tanstack/react-query";

import {
    useParams
} from "react-router-dom";

import {
    getExpenseOptionsApi
} from "../api/serviceDeliveryApi";

import {
    getDonationsService,
    getDonationByIdService
} from "../../donations/services/DonationService";

import {
    CURRENCIES
} from "../../budgets/utils/budgetUtils";
import { formatDate } from "../../../utils/date";
import { useModuleOn } from "../../../utils/modules";


// A service item may be priced in another currency (USD,
// EUR) with its exchange rate to ETB; the server keeps the
// original and uses ETB for totals and reports.
const BASE_CURRENCY = "ETB";

const CURRENCY_OPTIONS =
    [...new Set([BASE_CURRENCY, ...CURRENCIES])]
        .map(code => ({ value: code, label: code }));

const itemCurrency = item =>
    String(item?.currency || BASE_CURRENCY).toUpperCase();

// The currency a cash unit is given in (USD cash), if its code is one
const cashCurrencyOf = (unit, unitOptions) => {
    if (getUnitSemantics(unit, unitOptions) !== "monetary") return null;
    const option = findUnitOption(unit, unitOptions);
    const code = String(option?.code ?? option?.unitCode ?? option?.lookupCode ?? option?.label ?? "").trim().toUpperCase();
    return /^[A-Z]{3}$/.test(code) ? code : null;
};


// =====================================================
// MONETARY UNIT CODES
// =====================================================

const MONETARY_UNIT_CODES = [

    "AMOUNT",

    "ETB",

    "BIRR",

    "MONEY",

    "CASH"

];


// =====================================================
// OBJECT ID
// =====================================================

const OBJECT_ID_REGEX =
    /^[a-fA-F0-9]{24}$/;


const isObjectIdLike = (
    value
) => {

    return (
        typeof value === "string" &&
        OBJECT_ID_REGEX.test(
            value
        )
    );

};


// =====================================================
// GENERATE CLIENT-SIDE OBJECT ID
// =====================================================

const generateObjectId = () => {

    const timestamp =
        Math.floor(
            Date.now() / 1000
        )
            .toString(16)
            .padStart(
                8,
                "0"
            );


    let randomPart =
        "";


    for (
        let i = 0;
        i < 16;
        i += 1
    ) {

        randomPart +=
            Math.floor(
                Math.random() * 16
            )
                .toString(16);

    }


    return (
        timestamp +
        randomPart
    )
        .slice(
            0,
            24
        );

};


// =====================================================
// NORMALIZE ID
// =====================================================

const normalizeLookupValue = (
    value,
    depth = 0
) => {

    if (
        depth > 10
    ) {

        return "";

    }


    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "string" ||
        typeof value === "number"
    ) {

        return String(
            value
        );

    }


    if (
        typeof value !== "object"
    ) {

        return String(
            value
        );

    }


    const directId =
        value?._id ??
        value?.id;


    if (
        directId !== undefined &&
        directId !== null &&
        directId !== ""
    ) {

        return normalizeLookupValue(
            directId,
            depth + 1
        );

    }


    const lookupId =
        value?.lookupId;


    if (
        lookupId !== undefined &&
        lookupId !== null &&
        lookupId !== ""
    ) {

        return normalizeLookupValue(
            lookupId,
            depth + 1
        );

    }


    const nestedValue =
        value?.value;


    if (
        nestedValue !== undefined &&
        nestedValue !== null &&
        nestedValue !== ""
    ) {

        return normalizeLookupValue(
            nestedValue,
            depth + 1
        );

    }


    const lookup =
        value?.lookup;


    if (
        lookup !== undefined &&
        lookup !== null &&
        lookup !== ""
    ) {

        return normalizeLookupValue(
            lookup,
            depth + 1
        );

    }


    return "";

};


// =====================================================
// NORMALIZE LOOKUP LABEL
// =====================================================

const normalizeLookupLabel = (
    option,
    depth = 0
) => {

    if (
        depth > 10
    ) {

        return "";

    }


    if (
        option === null ||
        option === undefined ||
        option === ""
    ) {

        return "";

    }


    if (
        typeof option === "string" ||
        typeof option === "number"
    ) {

        return String(
            option
        )
            .trim();

    }


    if (
        typeof option !== "object"
    ) {

        return String(
            option
        )
            .trim();

    }


    const directLabel =
        option?.label ??
        option?.name ??
        option?.text;


    if (
        directLabel !== undefined &&
        directLabel !== null &&
        directLabel !== "" &&
        typeof directLabel !== "object"
    ) {

        return String(
            directLabel
        )
            .trim();

    }


    if (
        option?.value !== undefined &&
        option?.value !== null &&
        option?.value !== ""
    ) {

        const nestedLabel =
            normalizeLookupLabel(
                option.value,
                depth + 1
            );


        if (
            nestedLabel
        ) {

            return nestedLabel;

        }

    }


    if (
        option?.code !== undefined &&
        option?.code !== null &&
        option?.code !== ""
    ) {

        return String(
            option.code
        )
            .trim();

    }


    return "";

};


// =====================================================
// NORMALIZE LOOKUP CODE
// =====================================================

const normalizeLookupCode = (
    option,
    depth = 0
) => {

    if (
        depth > 10 ||
        option === null ||
        option === undefined ||
        option === ""
    ) {

        return "";

    }


    if (
        typeof option === "string" ||
        typeof option === "number"
    ) {

        return String(
            option
        )
            .trim()
            .toUpperCase();

    }


    if (
        typeof option !== "object"
    ) {

        return "";

    }


    const directCode =
        option?.code ??
        option?.unitCode ??
        option?.lookupCode;


    if (
        directCode !== undefined &&
        directCode !== null &&
        directCode !== ""
    ) {

        return String(
            directCode
        )
            .trim()
            .toUpperCase();

    }


    if (
        option?.value !== undefined &&
        option?.value !== null &&
        option?.value !== ""
    ) {

        const nestedCode =
            normalizeLookupCode(
                option.value,
                depth + 1
            );


        if (
            nestedCode
        ) {

            return nestedCode;

        }

    }


    return "";

};


// =====================================================
// NORMALIZE SEMANTIC TYPE
// =====================================================

const normalizeSemanticType = (
    option,
    depth = 0
) => {

    if (
        depth > 10 ||
        option === null ||
        option === undefined ||
        option === ""
    ) {

        return null;

    }


    if (
        typeof option !== "object"
    ) {

        return null;

    }


    const semanticType =
        option?.semanticType ??
        option?.metadata?.semanticType;


    if (
        semanticType === "monetary" ||
        semanticType === "physical"
    ) {

        return semanticType;

    }


    if (
        option?.value !== undefined &&
        option?.value !== null &&
        typeof option.value === "object"
    ) {

        return normalizeSemanticType(
            option.value,
            depth + 1
        );

    }


    return null;

};


// =====================================================
// NORMALIZE ALLOCATION BEHAVIOR
// =====================================================

const normalizeAllocationBehavior = (
    option,
    depth = 0
) => {

    if (
        depth > 10 ||
        option === null ||
        option === undefined ||
        option === ""
    ) {

        return null;

    }


    if (
        typeof option === "string"
    ) {

        const normalized =
            option
                .trim()
                .toUpperCase();


        if (
            normalized ===
            "CONSUMPTION"
        ) {

            return "CONSUMPTION";

        }


        if (
            normalized ===
            "PARTICIPATION"
        ) {

            return "PARTICIPATION";

        }


        return null;

    }


    if (
        typeof option !== "object"
    ) {

        return null;

    }


    const allocationBehavior =
        option?.allocationBehavior ??
        option?.metadata?.allocationBehavior;


    if (
        allocationBehavior !== undefined &&
        allocationBehavior !== null &&
        allocationBehavior !== ""
    ) {

        const normalized =
            String(
                allocationBehavior
            )
                .trim()
                .toUpperCase();


        if (
            normalized ===
            "CONSUMPTION"
        ) {

            return "CONSUMPTION";

        }


        if (
            normalized ===
            "PARTICIPATION"
        ) {

            return "PARTICIPATION";

        }

    }


    if (
        option?.value !== undefined &&
        option?.value !== null &&
        typeof option.value === "object"
    ) {

        return normalizeAllocationBehavior(
            option.value,
            depth + 1
        );

    }


    return null;

};


// =====================================================
// NORMALIZE LOOKUP OPTION
// =====================================================

const normalizeLookupOption = (
    option
) => {

    if (
        option === null ||
        option === undefined ||
        option === ""
    ) {

        return null;

    }


    const value =
        normalizeLookupValue(
            option
        );


    if (
        !value ||
        value === "[object Object]"
    ) {

        return null;

    }


    const label =
        normalizeLookupLabel(
            option
        ) ||
        value;


    const code =
        normalizeLookupCode(
            option
        );


    const semanticType =
        normalizeSemanticType(
            option
        );


    const allocationBehavior =
        normalizeAllocationBehavior(
            option
        );


    const originalUnitCode =
        typeof option === "object"
            ? (
                option?.unitCode ??
                null
            )
            : null;


    const originalLookupCode =
        typeof option === "object"
            ? (
                option?.lookupCode ??
                null
            )
            : null;


    const normalizedOption = {

        value:
            String(
                value
            ),

        label:
            String(
                label
            ),

        _id:
            String(
                value
            ),

        id:
            String(
                value
            ),

        code:
            code ||
            null,

        unitCode:
            originalUnitCode ||
            code ||
            null,

        lookupCode:
            originalLookupCode ||
            code ||
            null,

        semanticType,

        allocationBehavior

    };


    if (
        typeof option === "object"
    ) {

        Object.keys(
            option
        ).forEach(
            (
                key
            ) => {

                if (
                    key === "value" ||
                    key === "label" ||
                    key === "_id" ||
                    key === "id" ||
                    key === "code" ||
                    key === "unitCode" ||
                    key === "lookupCode" ||
                    key === "semanticType" ||
                    key === "allocationBehavior"
                ) {

                    return;

                }


                normalizedOption[
                    key
                ] =
                    option[
                        key
                    ];

            }
        );

    }


    return normalizedOption;

};


// =====================================================
// NORMALIZE RESPONSE ARRAY
// =====================================================

const normalizeResponseArray = (
    response
) => {

    if (
        Array.isArray(
            response
        )
    ) {

        return response;

    }


    if (
        !response ||
        typeof response !== "object"
    ) {

        return [];

    }


    const possibleArrays = [

        response?.data?.data,

        response?.data?.rows,

        response?.data?.items,

        response?.data?.options,

        response?.data?.results,

        response?.data,

        response?.rows,

        response?.items,

        response?.options,

        response?.results

    ];


    for (
        const candidate
        of possibleArrays
    ) {

        if (
            Array.isArray(
                candidate
            )
        ) {

            return candidate;

        }

    }


    return [];

};


// =====================================================
// NORMALIZE UNIT CODE
// =====================================================

const normalizeUnitCode = (
    value
) => {

    if (
        value === null ||
        value === undefined ||
        value === ""
    ) {

        return "";

    }


    if (
        typeof value === "object"
    ) {

        const nested =
            normalizeLookupCode(
                value
            );


        if (
            nested
        ) {

            return nested;

        }


        const label =
            normalizeLookupLabel(
                value
            );


        return String(
            label
        )
            .trim()
            .toUpperCase();

    }


    return String(
        value
    )
        .trim()
        .toUpperCase();

};


// =====================================================
// FIND UNIT OPTION
// =====================================================

const findUnitOption = (
    unit,
    unitOptions
) => {

    if (
        unit === null ||
        unit === undefined ||
        unit === ""
    ) {

        return null;

    }


    const options =
        Array.isArray(
            unitOptions
        )
            ? unitOptions
            : [];


    if (
        options.length === 0
    ) {

        return null;

    }


    const unitId =
        normalizeLookupValue(
            unit
        );


    if (
        unitId &&
        isObjectIdLike(
            unitId
        )
    ) {

        const byId =
            options.find(
                (
                    option
                ) => {

                    const optionId =
                        normalizeLookupValue(
                            option
                        );


                    return (
                        String(
                            optionId
                        ) ===
                        String(
                            unitId
                        )
                    );

                }
            );


        if (
            byId
        ) {

            return byId;

        }

    }


    const normalizedUnit =
        normalizeUnitCode(
            unit
        );


    if (
        !normalizedUnit
    ) {

        return null;

    }


    const byCodeOrLabel =
        options.find(
            (
                option
            ) => {

                const candidates = [

                    option?.code,

                    option?.unitCode,

                    option?.lookupCode,

                    option?.name,

                    option?.label,

                    option?.text

                ];


                return candidates.some(
                    (
                        candidate
                    ) =>
                        normalizeUnitCode(
                            candidate
                        ) ===
                        normalizedUnit
                );

            }
        );


    return byCodeOrLabel || null;

};


// =====================================================
// GET UNIT SEMANTICS
// =====================================================

const getUnitSemantics = (
    unit,
    unitOptions
) => {

    const resolvedUnit =
        findUnitOption(
            unit,
            unitOptions
        );


    if (
        resolvedUnit?.semanticType ===
        "monetary"
    ) {

        return "monetary";

    }


    if (
        resolvedUnit?.semanticType ===
        "physical"
    ) {

        return "physical";

    }


    if (
        resolvedUnit
    ) {

        const code =
            normalizeUnitCode(
                resolvedUnit?.code ??
                resolvedUnit?.unitCode ??
                resolvedUnit?.lookupCode ??
                ""
            );


        if (
            MONETARY_UNIT_CODES.includes(
                code
            )
        ) {

            return "monetary";

        }


        const label =
            normalizeUnitCode(
                resolvedUnit?.label ??
                resolvedUnit?.name ??
                resolvedUnit?.text ??
                ""
            );


        if (
            MONETARY_UNIT_CODES.includes(
                label
            )
        ) {

            return "monetary";

        }

    }


    const rawCode =
        normalizeUnitCode(
            unit
        );


    if (
        MONETARY_UNIT_CODES.includes(
            rawCode
        )
    ) {

        return "monetary";

    }


    return "unknown";

};


// =====================================================
// MONEY UNIT DETECTION
// =====================================================

const isAmountUnit = (
    unit,
    unitOptions
) => {

    return (
        getUnitSemantics(
            unit,
            unitOptions
        ) ===
        "monetary"
    );

};


// =====================================================
// WHOLE OR DECIMAL QUANTITY
// =====================================================
// Weights, volumes and lengths take parts (12.5 Kg);
// everything else is counted in whole numbers (same rule
// as the server).

const DECIMAL_UNIT_CODES = [
    "KG",
    "KILOGRAM",
    "LITER",
    "LITRE",
    "METER"
];

const allowsDecimalQuantity = (
    unit,
    unitOptions
) => {

    const option =
        findUnitOption(
            unit,
            unitOptions
        );

    return [
        option?.code,
        option?.label,
        option?.name
    ]
        .filter(Boolean)
        .some(
            candidate =>
                DECIMAL_UNIT_CODES.includes(
                    normalizeUnitCode(
                        candidate
                    )
                )
        );

};

const quantityStep = (
    unit,
    unitOptions
) =>
    allowsDecimalQuantity(
        unit,
        unitOptions
    )
        ? "any"
        : 1;


// =====================================================
// GET ALLOWED UNIT IDS
// =====================================================

const getAllowedUnitIds = (
    serviceType
) => {

    if (
        !serviceType ||
        typeof serviceType !== "object"
    ) {

        return [];

    }


    const allowedUnits =
        Array.isArray(
            serviceType?.allowedUnits
        )
            ? serviceType.allowedUnits
            : [];


    const ids = [];


    allowedUnits.forEach(
        (
            unit
        ) => {

            const unitId =
                normalizeLookupValue(
                    unit
                );


            if (
                !unitId
            ) {

                return;

            }


            const normalizedId =
                String(
                    unitId
                )
                    .trim();


            if (
                ids.includes(
                    normalizedId
                )
            ) {

                return;

            }


            ids.push(
                normalizedId
            );

        }
    );


    return ids;

};


// =====================================================
// CALCULATE TOTAL COST
// =====================================================

const calculateTotalCost = (
    quantity,
    unitCost
) => {

    const safeQuantity =
        Number(
            quantity
        );


    const safeUnitCost =
        Number(
            unitCost
        );


    const normalizedQuantity =
        Number.isFinite(
            safeQuantity
        )
            ? safeQuantity
            : 0;


    const normalizedUnitCost =
        Number.isFinite(
            safeUnitCost
        )
            ? safeUnitCost
            : 0;


    return (
        normalizedQuantity *
        normalizedUnitCost
    );

};


// =====================================================
// NORMALIZE DONOR OPTIONS
// =====================================================

const normalizeDonorOptions = (
    response
) => {

    return normalizeResponseArray(
        response
    )
        .filter(
            donor =>
                donor?.active !== false &&
                donor?.deleted !== true
        )
        .map(
            donor => {

                const value =
                    normalizeLookupValue(
                        donor
                    );


                if (
                    !value
                ) {

                    return null;

                }


                const name =
                    donor?.name ||
                    donor?.label ||
                    donor?.value ||
                    value;


                return {

                    value:
                        String(
                            value
                        ),

                    label:
                        String(
                            name
                        )
                            .trim(),

                    _id:
                        String(
                            value
                        ),

                    id:
                        String(
                            value
                        ),

                    original:
                        donor

                };

            }
        )
        .filter(
            Boolean
        );

};


// =====================================================
// NORMALIZE DONATION OPTIONS
// =====================================================

const normalizeDonationOptions = (
    response
) => {

    return normalizeResponseArray(
        response
    )
        .filter(
            donation =>
                donation?.active !== false &&
                donation?.deleted !== true
        )
        .map(
            donation => {

                const value =
                    normalizeLookupValue(
                        donation
                    );


                if (
                    !value
                ) {

                    return null;

                }


                const donationCode =
                    donation?.donationCode ||
                    donation?.code ||
                    "";


                const title =
                    donation?.title ||
                    donation?.name ||
                    donation?.label ||
                    "";


                let label;


                if (
                    donationCode &&
                    title
                ) {

                    label =
                        `${donationCode} - ${title}`;

                }
                else if (
                    donationCode
                ) {

                    label =
                        String(
                            donationCode
                        );

                }
                else if (
                    title
                ) {

                    label =
                        String(
                            title
                        );

                }
                else {

                    label =
                        String(
                            value
                        );

                }


                return {

                    value:
                        String(
                            value
                        ),

                    label:
                        label.trim(),

                    _id:
                        String(
                            value
                        ),

                    id:
                        String(
                            value
                        ),

                    donor:
                        normalizeLookupValue(
                            donation?.donor
                        ),

                    original:
                        donation

                };

            }
        )
        .filter(
            Boolean
        );

};


// =====================================================
// SERVICE DELIVERY ITEM ROW
// =====================================================

// May this donation pay for this work? (the same rule as the server,
// services/donationFunding.js): not cancelled; unrestricted pays for
// anything; restricted only for its own program / project (a main
// project: its phases too) / activity / activity run.
const idOfValue = (value) => String(value?._id || value || "");

const donationMayPay = (option, work = {}) => {
    // the options carry the donation itself in "original"
    const donation = option?.original || option;
    if (donation?.status === "Cancelled") return false;
    if (String(donation?.fundingRestriction || "Unrestricted") !== "Restricted") return true;
    const key = ["activityRun", "activity", "project", "program"].find(name => idOfValue(donation?.[name]));
    if (!key) return true;
    const scope = idOfValue(donation[key]);
    if (key === "project" && idOfValue(work.parentProject) === scope) return true;
    return idOfValue(work[key]) === scope;
};

const ServiceDeliveryItemRow = ({
    item,
    index,
    setItems,
    project,
    work = {},
    deliveryId,
    serviceCategories,
    unitOptions,
    unitsLoading,
    donorOptions,
    donationOptions,
    donorsLoading,
    donationsLoading
}) => {

    const serviceCategoryValue =
        normalizeLookupValue(
            item?.serviceCategory
        );


    const serviceTypeValue =
        normalizeLookupValue(
            item?.serviceType
        );


    const unitValue =
        normalizeLookupValue(
            item?.unit
        );


    const donorValue =
        normalizeLookupValue(
            item?.donor
        );


    const donationValue =
        normalizeLookupValue(
            item?.donation
        );

    // What the chosen donation has used and has left
    // (service deliveries + submitted / approved expenses)
    const {
        data: selectedDonationFunding
    } = useQuery({
        queryKey: ["donation-funding", donationValue],
        queryFn: async () => (await getDonationByIdService(donationValue))?.data?.funding || null,
        enabled: Boolean(donationValue),
        staleTime: 30000
    });

    // donor / donation fields belong to the funding module
    const fundingOn = useModuleOn("funding");

    // The chosen donation's own record (status, amount)
    const selectedDonationRecord =
        donationValue
            ? donationOptions.find(
                option =>
                    String(option?.value) ===
                    String(donationValue)
            )?.original ||
            null
            : null;


    const {
        data: serviceTypesResponse,
        isLoading: serviceTypesLoading
    } = useServiceTypes(
        serviceCategoryValue
    );


    const serviceTypes =
        normalizeResponseArray(
            serviceTypesResponse
        );


    const serviceTypeOptions =
        useMemo(
            () => {

                const normalizedOptions =
                    serviceTypes
                        .filter(
                            type =>
                                type?.active !== false
                        )
                        .map(
                            normalizeLookupOption
                        )
                        .filter(
                            Boolean
                        );


                const uniqueOptions =
                    [];


                const seen =
                    new Set();


                normalizedOptions.forEach(
                    option => {

                        const key =
                            String(
                                option.value
                            );


                        if (
                            seen.has(
                                key
                            )
                        ) {

                            return;

                        }


                        seen.add(
                            key
                        );


                        uniqueOptions.push(
                            option
                        );

                    }
                );


                return uniqueOptions;

            },
            [
                serviceTypes
            ]
        );


    const selectedServiceType =
        useMemo(
            () => {

                if (
                    !serviceTypeValue
                ) {

                    return null;

                }


                return (
                    serviceTypeOptions.find(
                        option =>
                            String(
                                option?.value
                            ) ===
                            String(
                                serviceTypeValue
                            )
                    ) ||
                    null
                );

            },
            [
                serviceTypeOptions,
                serviceTypeValue
            ]
        );


    const allowedUnitIds =
        useMemo(
            () => {

                return getAllowedUnitIds(
                    selectedServiceType
                );

            },
            [
                selectedServiceType
            ]
        );


    const filteredUnitOptions =
        useMemo(
            () => {

                if (
                    !serviceTypeValue
                ) {

                    return [];

                }


                if (
                    allowedUnitIds.length === 0
                ) {

                    return [];

                }


                return unitOptions.filter(
                    unit => {

                        const unitId =
                            normalizeLookupValue(
                                unit
                            );


                        if (
                            !unitId
                        ) {

                            return false;

                        }


                        return allowedUnitIds.includes(
                            String(
                                unitId
                            )
                        );

                    }
                );

            },
            [
                unitOptions,
                serviceTypeValue,
                allowedUnitIds
            ]
        );


    // donors with at least one donation allowed for this work
    // (the one already chosen stays)
    const filteredDonorOptions =
        useMemo(
            () => {
                const payers = new Set(
                    donationOptions
                        .filter(donation => donationMayPay(donation, work))
                        .map(donation => String(normalizeLookupValue(donation?.donor) || ""))
                );
                return donorOptions.filter(donor =>
                    payers.has(String(normalizeLookupValue(donor?.value ?? donor?._id ?? donor))) ||
                    String(normalizeLookupValue(donor?.value ?? donor?._id ?? donor)) === String(donorValue || "")
                );
            },
            [donorOptions, donationOptions, work, donorValue]
        );


    const filteredDonationOptions =
        useMemo(
            () => {

                // only donations allowed to pay for this work (the one
                // already chosen stays, so an older record still shows it)
                const allowed =
                    donationOptions.filter(
                        donation =>
                            donationMayPay(donation, work) ||
                            String(normalizeLookupValue(donation?._id)) === String(normalizeLookupValue(item?.donation))
                    );

                if (
                    !donorValue
                ) {

                    return allowed;

                }


                return allowed.filter(
                    donation => {

                        const donationDonor =
                            normalizeLookupValue(
                                donation?.donor
                            );


                        return (
                            !donationDonor ||
                            String(
                                donationDonor
                            ) ===
                            String(
                                donorValue
                            )
                        );

                    }
                );

            },
            [
                donorValue,
                donationOptions,
                work,
                item?.donation
            ]
        );


    // =================================================
    // SYNC SERVICE TYPE LABEL + ALLOCATION BEHAVIOR
    // =================================================

    useEffect(
        () => {

            if (
                !serviceTypeValue ||
                serviceTypesLoading ||
                !selectedServiceType
            ) {

                return;

            }


            const serviceTypeLabel =
                String(
                    selectedServiceType?.label ||
                    ""
                )
                    .trim();


            /*
             * Allocation behavior belongs to the
             * Service Type configuration.
             *
             * If an old Service Type has no behavior,
             * use CONSUMPTION for backward compatibility.
             */

            const allocationBehavior =
                normalizeAllocationBehavior(
                    selectedServiceType?.allocationBehavior
                ) ||
                "CONSUMPTION";


            const currentLabel =
                String(
                    item?.serviceTypeLabel ||
                    ""
                )
                    .trim();


            const currentAllocationBehavior =
                normalizeAllocationBehavior(
                    item?.allocationBehavior
                );


            if (
                currentLabel ===
                    serviceTypeLabel &&
                currentAllocationBehavior ===
                    allocationBehavior
            ) {

                return;

            }


            setItems(
                previousItems => {

                    if (
                        !Array.isArray(
                            previousItems
                        )
                    ) {

                        return previousItems;

                    }


                    const currentItem =
                        previousItems[
                            index
                        ];


                    if (
                        !currentItem
                    ) {

                        return previousItems;

                    }


                    const currentType =
                        normalizeLookupValue(
                            currentItem?.serviceType
                        );


                    if (
                        String(
                            currentType
                        ) !==
                        String(
                            serviceTypeValue
                        )
                    ) {

                        return previousItems;

                    }


                    const updatedItems =
                        [
                            ...previousItems
                        ];


                    updatedItems[
                        index
                    ] = {

                        ...currentItem,

                        serviceTypeLabel:
                            serviceTypeLabel,

                        allocationBehavior:
                            allocationBehavior

                    };


                    return updatedItems;

                }
            );

        },
        [
            serviceTypeValue,
            selectedServiceType,
            serviceTypesLoading,
            item?.serviceTypeLabel,
            item?.allocationBehavior,
            index,
            setItems
        ]
    );


    // =================================================
    // CLEAR UNIT WHEN NOT ALLOWED
    // =================================================

    useEffect(
        () => {

            if (
                !serviceTypeValue ||
                serviceTypesLoading ||
                unitsLoading ||
                !unitValue
            ) {

                return;

            }


            if (
                allowedUnitIds.length === 0
            ) {

                setItems(
                    previousItems => {

                        if (
                            !Array.isArray(
                                previousItems
                            )
                        ) {

                            return previousItems;

                        }


                        const currentItem =
                            previousItems[
                                index
                            ];


                        if (
                            !currentItem
                        ) {

                            return previousItems;

                        }


                        const currentUnit =
                            normalizeLookupValue(
                                currentItem?.unit
                            );


                        if (
                            currentUnit !==
                            unitValue
                        ) {

                            return previousItems;

                        }


                        const updatedItems =
                            [
                                ...previousItems
                            ];


                        updatedItems[
                            index
                        ] = {

                            ...currentItem,

                            unit:
                                "",

                            unitCost:
                                0,

                            totalCost:
                                0

                        };


                        return updatedItems;

                    }
                );


                return;

            }


            const currentUnitId =
                normalizeLookupValue(
                    item?.unit
                );


            const isAllowed =
                allowedUnitIds.includes(
                    String(
                        currentUnitId
                    )
                );


            if (
                isAllowed
            ) {

                return;

            }


            setItems(
                previousItems => {

                    if (
                        !Array.isArray(
                            previousItems
                        )
                    ) {

                        return previousItems;

                    }


                    const currentItem =
                        previousItems[
                            index
                        ];


                    if (
                        !currentItem
                    ) {

                        return previousItems;

                    }


                    const currentItemUnit =
                        normalizeLookupValue(
                            currentItem?.unit
                        );


                    if (
                        currentItemUnit !==
                        currentUnitId
                    ) {

                        return previousItems;

                    }


                    const updatedItems =
                        [
                            ...previousItems
                        ];


                    updatedItems[
                        index
                    ] = {

                        ...currentItem,

                        unit:
                            "",

                        unitCost:
                            0,

                        totalCost:
                            0

                    };


                    return updatedItems;

                }
            );

        },
        [
            serviceTypeValue,
            unitValue,
            allowedUnitIds,
            serviceTypesLoading,
            unitsLoading,
            item?.unit,
            index,
            setItems
        ]
    );


    // =================================================
    // CLEAR INVALID DONATION WHEN DONOR CHANGES
    // =================================================

    useEffect(
        () => {

            if (
                !donationValue ||
                !donorValue
            ) {

                return;

            }


            const selectedDonation =
                donationOptions.find(
                    donation =>
                        String(
                            donation?.value
                        ) ===
                        String(
                            donationValue
                        )
                );


            if (
                !selectedDonation
            ) {

                return;

            }


            const donationDonor =
                normalizeLookupValue(
                    selectedDonation?.donor
                );


            if (
                !donationDonor ||
                String(
                    donationDonor
                ) ===
                String(
                    donorValue
                )
            ) {

                return;

            }


            setItems(
                previousItems => {

                    if (
                        !Array.isArray(
                            previousItems
                        )
                    ) {

                        return previousItems;

                    }


                    const currentItem =
                        previousItems[
                            index
                        ];


                    if (
                        !currentItem
                    ) {

                        return previousItems;

                    }


                    const currentDonation =
                        normalizeLookupValue(
                            currentItem?.donation
                        );


                    if (
                        String(
                            currentDonation
                        ) !==
                        String(
                            donationValue
                        )
                    ) {

                        return previousItems;

                    }


                    const updatedItems =
                        [
                            ...previousItems
                        ];


                    updatedItems[
                        index
                    ] = {

                        ...currentItem,

                        donation:
                            ""

                    };


                    return updatedItems;

                }
            );

        },
        [
            donorValue,
            donationValue,
            donationOptions,
            index,
            setItems
        ]
    );


    // =================================================
    // UPDATE ITEM
    // =================================================

    const updateItem = (
        field,
        value
    ) => {

        setItems(
            previousItems => {

                if (
                    !Array.isArray(
                        previousItems
                    )
                ) {

                    return previousItems;

                }


                if (
                    index < 0 ||
                    index >= previousItems.length
                ) {

                    return previousItems;

                }


                const existingItem =
                    previousItems[
                        index
                    ];


                if (
                    !existingItem ||
                    typeof existingItem !== "object"
                ) {

                    return previousItems;

                }


                const existingItemId =
                    normalizeLookupValue(
                        existingItem?._id ??
                        existingItem?.id
                    );


                const updatedItem = {

                    ...existingItem,

                    _id:
                        existingItemId ||
                        generateObjectId()

                };


                if (
                    field ===
                    "serviceCategory"
                ) {

                    updatedItem.serviceCategory =
                        normalizeLookupValue(
                            value
                        );


                    updatedItem.serviceType =
                        "";


                    updatedItem.serviceTypeLabel =
                        "";


                    updatedItem.allocationBehavior =
                        null;


                    updatedItem.unit =
                        "";


                    updatedItem.unitCost =
                        0;

                }


                else if (
                    field ===
                    "serviceType"
                ) {

                    const selectedValue =
                        normalizeLookupValue(
                            value
                        );


                    updatedItem.serviceType =
                        selectedValue;


                    const selectedOption =
                        serviceTypeOptions.find(
                            option =>
                                String(
                                    option?.value
                                ) ===
                                String(
                                    selectedValue
                                )
                        );


                    updatedItem.serviceTypeLabel =
                        selectedOption?.label
                            ? String(
                                selectedOption.label
                            )
                            : "";


                    /*
                     * The allocation behavior is inherited
                     * directly from the selected Service Type.
                     *
                     * Never infer it from the Service Type
                     * name or code.
                     */

                    updatedItem.allocationBehavior =
                        normalizeAllocationBehavior(
                            selectedOption?.allocationBehavior
                        ) ||
                        "CONSUMPTION";


                    /*
                     * Changing Service Type invalidates
                     * the current Unit and Unit Cost.
                     */

                    updatedItem.unit =
                        "";


                    updatedItem.unitCost =
                        0;

                }


                else if (
                    field ===
                    "unit"
                ) {

                    const selectedUnit =
                        normalizeLookupValue(
                            value
                        );


                    const isAllowed =
                        allowedUnitIds.includes(
                            String(
                                selectedUnit
                            )
                        );


                    if (
                        !isAllowed
                    ) {

                        return previousItems;

                    }


                    updatedItem.unit =
                        selectedUnit;

                    const cashCurrency =
                        cashCurrencyOf(selectedUnit, unitOptions);

                    if (cashCurrency) {
                        updatedItem.currency = cashCurrency;
                        if (cashCurrency === BASE_CURRENCY) updatedItem.exchangeRate = null;
                    }
                }


                else if (
                    field ===
                    "donor"
                ) {

                    updatedItem.donor =
                        normalizeLookupValue(
                            value
                        ) ||
                        null;


                    updatedItem.donation =
                        null;

                }


                else if (
                    field ===
                    "donation"
                ) {

                    updatedItem.donation =
                        normalizeLookupValue(
                            value
                        ) ||
                        null;

                    // another donation: its own received rate applies
                    if (String(updatedItem.donation || "") !== String(existingItem.donation || "")) {
                        updatedItem.donationRate = null;
                    }

                }


                else if (
                    field ===
                    "quantity"
                ) {

                    const numericValue =
                        Number(
                            value
                        );


                    updatedItem.quantity =
                        value === ""
                            ? ""
                            : Number.isFinite(
                                numericValue
                            ) &&
                            numericValue >= 0
                                ? numericValue
                                : existingItem?.quantity ?? 1;

                }


                else if (
                    field ===
                    "currency"
                ) {

                    updatedItem.currency =
                        String(value || BASE_CURRENCY).toUpperCase();

                    if (updatedItem.currency === BASE_CURRENCY) {
                        updatedItem.exchangeRate = null;
                    }

                }


                else if (
                    field ===
                    "exchangeRate"
                ) {

                    const rate = Number(value);

                    updatedItem.exchangeRate =
                        value === "" || !Number.isFinite(rate) || rate <= 0
                            ? null
                            : rate;

                }


                else if (
                    field ===
                    "unitCost"
                ) {
                    const numericValue =
                        Number(
                            value
                        );
                    updatedItem.unitCost =
                        Number.isFinite(
                            numericValue
                        ) &&
                        numericValue >= 0
                            ? numericValue
                            : 0;

                }


                else {

                    updatedItem[
                        field
                    ] =
                        value;

                }


                updatedItem.totalCost =
                    calculateTotalCost(
                        updatedItem.quantity,
                        updatedItem.unitCost
                    );


                const updatedItems =
                    [
                        ...previousItems
                    ];


                updatedItems[
                    index
                ] =
                    updatedItem;


                return updatedItems;

            }
        );

    };


    // =================================================
    // DETAIL ITEM UPDATE
    // =================================================

    const updateDetailItem = (
        detailIndex,
        field,
        value
    ) => {

        setItems(
            previousItems => {

                if (
                    !Array.isArray(
                        previousItems
                    )
                ) {

                    return previousItems;

                }


                const currentItem =
                    previousItems[
                        index
                    ];


                if (
                    !currentItem
                ) {

                    return previousItems;

                }


                const detailItems =
                    Array.isArray(
                        currentItem?.detailItems
                    )
                        ? currentItem.detailItems
                        : [];


                if (
                    detailIndex < 0 ||
                    detailIndex >= detailItems.length
                ) {

                    return previousItems;

                }


                const existingDetail =
                    detailItems[
                        detailIndex
                    ];


                const detailId =
                    normalizeLookupValue(
                        existingDetail?._id ??
                        existingDetail?.id
                    );


                const updatedDetail = {

                    ...existingDetail,

                    _id:
                        detailId ||
                        generateObjectId()

                };


                if (
                    field ===
                    "quantity"
                ) {

                    const numericValue =
                        Number(
                            value
                        );


                    updatedDetail.quantity =
                        value === ""
                            ? ""
                            : Number.isFinite(
                                numericValue
                            ) &&
                            numericValue >= 0
                                ? numericValue
                                : existingDetail?.quantity ?? 1;

                }


                else if (
                    field ===
                    "unitCost"
                ) {

                    const numericValue =
                        Number(
                            value
                        );


                    updatedDetail.unitCost =
                        Number.isFinite(
                            numericValue
                        ) &&
                        numericValue >= 0
                            ? numericValue
                            : 0;

                }


                else if (
                    field ===
                    "unit"
                ) {

                    updatedDetail.unit =
                        normalizeLookupValue(
                            value
                        ) ||
                        null;

                }

                // Given out in another unit (1 Sack = 50 Kg)
                else if (
                    field ===
                    "allocationUnit"
                ) {

                    updatedDetail.allocationUnit =
                        normalizeLookupValue(
                            value
                        ) ||
                        null;

                    if (
                        !updatedDetail.allocationUnit
                    ) {
                        updatedDetail.allocationConversionFactor =
                            1;
                    }

                }

                else if (
                    field ===
                    "allocationConversionFactor"
                ) {

                    const numericValue =
                        Number(
                            value
                        );

                    updatedDetail.allocationConversionFactor =
                        value === ""
                            ? ""
                            : Number.isFinite(
                                numericValue
                            ) &&
                            numericValue >= 0
                                ? numericValue
                                : existingDetail?.allocationConversionFactor ?? 1;

                }


                else {

                    updatedDetail[
                        field
                    ] =
                        value;

                }


                updatedDetail.totalCost =
                    calculateTotalCost(
                        updatedDetail.quantity,
                        updatedDetail.unitCost
                    );


                const updatedDetailItems =
                    [
                        ...detailItems
                    ];


                updatedDetailItems[
                    detailIndex
                ] =
                    updatedDetail;


                const updatedItems =
                    [
                        ...previousItems
                    ];


                updatedItems[
                    index
                ] = {

                    ...currentItem,

                    detailItems:
                        updatedDetailItems

                };


                return updatedItems;

            }
        );

    };


    // =================================================
    // ADD DETAIL ITEM
    // =================================================

    const addDetailItem = () => {

        setItems(
            previousItems => {

                if (
                    !Array.isArray(
                        previousItems
                    )
                ) {

                    return previousItems;

                }


                const currentItem =
                    previousItems[
                        index
                    ];


                if (
                    !currentItem
                ) {

                    return previousItems;

                }


                const currentDetailItems =
                    Array.isArray(
                        currentItem?.detailItems
                    )
                        ? currentItem.detailItems
                        : [];


                const newDetailItem = {

                    _id:
                        generateObjectId(),

                    name:
                        "",

                    quantity:
                        1,

                    unit:
                        null,

                    allocationUnit:
                        null,

                    allocationConversionFactor:
                        1,

                    unitCost:
                        0,

                    totalCost:
                        0

                };


                const updatedItems =
                    [
                        ...previousItems
                    ];


                updatedItems[
                    index
                ] = {

                    ...currentItem,

                    detailItems: [

                        ...currentDetailItems,

                        newDetailItem

                    ]

                };


                return updatedItems;

            }
        );

    };


    // =================================================
    // REMOVE DETAIL ITEM
    // =================================================

    const removeDetailItem = (
        detailIndex
    ) => {

        setItems(
            previousItems => {

                if (
                    !Array.isArray(
                        previousItems
                    )
                ) {

                    return previousItems;

                }


                const currentItem =
                    previousItems[
                        index
                    ];


                if (
                    !currentItem
                ) {

                    return previousItems;

                }


                const currentDetailItems =
                    Array.isArray(
                        currentItem?.detailItems
                    )
                        ? currentItem.detailItems
                        : [];


                const updatedDetailItems =
                    currentDetailItems.filter(
                        (
                            _,
                            currentIndex
                        ) =>
                            currentIndex !==
                            detailIndex
                    );


                const updatedItems =
                    [
                        ...previousItems
                    ];


                updatedItems[
                    index
                ] = {

                    ...currentItem,

                    detailItems:
                        updatedDetailItems

                };


                return updatedItems;

            }
        );

    };


    // =================================================
    // REMOVE INVALID SERVICE TYPE
    // =================================================

    useEffect(
        () => {

            if (
                !serviceCategoryValue ||
                !serviceTypeValue ||
                serviceTypesLoading
            ) {

                return;

            }


            const exists =
                serviceTypeOptions.some(
                    option =>
                        String(
                            option?.value
                        ) ===
                        String(
                            serviceTypeValue
                        )
                );


            if (
                exists
            ) {

                return;

            }


            setItems(
                previousItems => {

                    if (
                        !Array.isArray(
                            previousItems
                        )
                    ) {

                        return previousItems;

                    }


                    const currentItem =
                        previousItems[
                            index
                        ];


                    if (
                        !currentItem
                    ) {

                        return previousItems;

                    }


                    const currentType =
                        normalizeLookupValue(
                            currentItem?.serviceType
                        );


                    if (
                        currentType !==
                        serviceTypeValue
                    ) {

                        return previousItems;

                    }


                    const updatedItems =
                        [
                            ...previousItems
                        ];


                    updatedItems[
                        index
                    ] = {

                        ...currentItem,

                        serviceType:
                            "",

                        serviceTypeLabel:
                            "",

                        allocationBehavior:
                            null,

                        unit:
                            "",

                        unitCost:
                            0,

                        totalCost:
                            0

                    };


                    return updatedItems;

                }
            );

        },
        [
            serviceCategoryValue,
            serviceTypeValue,
            serviceTypeOptions,
            serviceTypesLoading,
            index,
            setItems
        ]
    );


    // =================================================
    // REMOVE ITEM
    // =================================================

    const removeItem = () => {

        setItems(
            previousItems => {

                if (
                    !Array.isArray(
                        previousItems
                    )
                ) {

                    return previousItems;

                }


                return previousItems.filter(
                    (
                        _,
                        itemIndex
                    ) =>
                        itemIndex !==
                        index
                );

            }
        );

    };


    // =================================================
    // MONEY UNIT
    // =================================================

    const amountUnit =
        isAmountUnit(
            item?.unit,
            unitOptions
        );


    // =================================================
    // DETAIL ITEMS
    // =================================================

    const detailItems =
        Array.isArray(
            item?.detailItems
        )
            ? item.detailItems
            : [];


    // Money is broken down into money, goods into goods
    const parentUnitChosen =
        Boolean(
            normalizeLookupValue(
                item?.unit
            )
        );

    const detailUnitOptions =
        parentUnitChosen
            ? unitOptions.filter(
                option =>
                    isAmountUnit(
                        option?.value,
                        unitOptions
                    ) ===
                    amountUnit
            )
            : unitOptions;

    // Units goods can be given out in (Sack -> Kg); not
    // money, and not time (days, hours, sessions)
    const goodsUnitOptions =
        unitOptions.filter(
            option =>
                !isAmountUnit(
                    option?.value,
                    unitOptions
                ) &&
                ![
                    "DAY",
                    "HOUR",
                    "SESSION",
                    "WEEK",
                    "MONTH"
                ].includes(
                    normalizeUnitCode(
                        option?.code ||
                        option?.label
                    )
                )
        );

    const unitName = (
        unit
    ) =>
        findUnitOption(
            unit,
            unitOptions
        )?.label ||
        "unit";


    // The breakdown must add up to the item's cost
    const itemTotalCost =
        calculateTotalCost(
            item?.quantity,
            item?.unitCost
        );

    // An ETB item (cash, fees) paid from a donation in another
    // currency: at this rate (1 USD = ? ETB), by default the rate
    // the donation was received at
    const donationCurrencyCode =
        String(selectedDonationRecord?.currency || BASE_CURRENCY).toUpperCase();

    const paidFromForeignDonation =
        Boolean(selectedDonationRecord) &&
        donationCurrencyCode !== BASE_CURRENCY &&
        itemCurrency(item) === BASE_CURRENCY;

    const donationRateValue =
        Number(item?.donationRate) > 0
            ? Number(item.donationRate)
            : Number(selectedDonationRecord?.receivedRate) > 0
                ? Number(selectedDonationRecord.receivedRate)
                : 0;

    // What the item costs in its donation's currency (null: cannot compare)
    const itemCostInDonationCurrency = (() => {
        if (!selectedDonationRecord) return null;
        const donationCurrency = donationCurrencyCode;
        if (donationCurrency === itemCurrency(item)) return itemTotalCost;
        if (donationCurrency === BASE_CURRENCY && Number(item?.exchangeRate) > 0) return itemTotalCost * Number(item.exchangeRate);
        if (paidFromForeignDonation && donationRateValue > 0) return Math.round((itemTotalCost / donationRateValue) * 100) / 100;
        return null;
    })();

    // The expenses these items may have been bought with
    // (same donation and project), the close ones first
    const {
        data: expenseOptions = []
    } = useQuery({
        queryKey: ["expense-options", donationValue, project, deliveryId, Math.round(Number(itemCostInDonationCurrency || 0))],
        queryFn: () => getExpenseOptionsApi({
            donation: donationValue,
            project: project || undefined,
            amount: itemCostInDonationCurrency || 0,
            excludeDelivery: deliveryId || undefined
        }),
        enabled: Boolean(donationValue),
        staleTime: 30000
    });

    const paidByExpenseValue =
        normalizeLookupValue(
            item?.paidByExpense
        ) || "";

    const separateExpenses =
        (Array.isArray(item?.separateFromExpenses) ? item.separateFromExpenses : [])
            .map(value => String(normalizeLookupValue(value)));

    const suggestedExpense =
        !paidByExpenseValue
            ? expenseOptions.find(option => option.close && !separateExpenses.includes(String(option._id))) || null
            : null;

    const expenseSelectOptions = [
        { value: "", label: "Not bought with an expense (charged to the donation)" },
        ...expenseOptions.map(option => ({
            value: String(option._id),
            label: `${option.expenseCode}${option.description ? ` · ${option.description}` : ""} · ${option.currency || "ETB"} ${Number(option.remaining).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })} not yet linked (${option.status})`
        })),
        ...(paidByExpenseValue && !expenseOptions.some(option => String(option._id) === String(paidByExpenseValue))
            ? [{ value: String(paidByExpenseValue), label: item?.paidByExpense?.expenseCode || "The linked expense" }]
            : [])
    ];

    const detailItemsTotal =
        detailItems.reduce(
            (
                sum,
                detail
            ) =>
                sum +
                calculateTotalCost(
                    detail?.quantity,
                    detail?.unitCost
                ),
            0
        );

    const detailTotalMismatch =
        detailItems.length > 0 &&
        Math.abs(
            detailItemsTotal -
            itemTotalCost
        ) >
        0.01;

    const formatAmount = (
        value
    ) =>
        Number(
            value || 0
        ).toLocaleString(
            "en-US",
            {
                minimumFractionDigits: 2,
                maximumFractionDigits: 2
            }
        );


    // =================================================
    // RENDER SINGLE SERVICE ITEM
    // =================================================

    return (
        <Box
            sx={{
                width: "100%",
                mb: 3,
                p: 2,
                border: "1px solid",
                borderColor: "divider",
                borderRadius: 1
            }}
        >

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mb: 2
                }}
            >

                <Typography
                    variant="subtitle1"
                    sx={{
                        fontWeight: 600
                    }}
                >
                    Service Item {index + 1}
                </Typography>


                <AppButton
                    type="button"
                    variant="outlined"
                    onClick={removeItem}
                    startIcon={
                        <Delete />
                    }
                >
                    Remove
                </AppButton>

            </Box>

            <Box
                sx={{
                    display: "grid",
                    gridTemplateColumns: {
                        xs: "1fr",
                        md: "1fr 1fr"
                    },
                    gap: 2
                }}
            >

                <AppSelect
                    label="Service Category"
                    required
                    value={
                        serviceCategoryValue
                    }
                    options={
                        serviceCategories
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "serviceCategory",
                                event?.target?.value ??
                                event
                            )
                    }
                    fullWidth
                />


                <AppSelect
                    label="Service Type"
                    required
                    value={
                        serviceTypeValue
                    }
                    options={
                        serviceTypeOptions
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "serviceType",
                                event?.target?.value ??
                                event
                            )
                    }
                    disabled={
                        !serviceCategoryValue ||
                        serviceTypesLoading
                    }
                    fullWidth
                />


                <AppTextField
                    label="Quantity"
                    required
                    type="number"
                    value={
                        item?.quantity ?? 1
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "quantity",
                                event?.target?.value
                            )
                    }
                    inputProps={{
                        min: 0,
                        step:
                            quantityStep(
                                item?.unit,
                                unitOptions
                            )
                    }}
                    fullWidth
                />


                <AppSelect
                    label="Unit"
                    required
                    value={
                        unitValue
                    }
                    options={
                        filteredUnitOptions
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "unit",
                                event?.target?.value ??
                                event
                            )
                    }
                    disabled={
                        !serviceTypeValue ||
                        unitsLoading ||
                        filteredUnitOptions.length === 0
                    }
                    fullWidth
                />


                <AppSelect
                    label="Currency"
                    value={
                        itemCurrency(item)
                    }
                    options={
                        CURRENCY_OPTIONS
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "currency",
                                event?.target?.value ??
                                event
                            )
                    }
                    disabled={
                        Boolean(cashCurrencyOf(item?.unit, unitOptions))
                    }
                    helperText={
                        cashCurrencyOf(item?.unit, unitOptions)
                            ? "Cash is recorded in its own currency"
                            : undefined
                    }
                    fullWidth
                />


                {itemCurrency(item) !== BASE_CURRENCY && (

                    <AppTextField
                        label={`Exchange rate (1 ${itemCurrency(item)} = ? ETB)`}
                        required
                        type="number"
                        value={
                            item?.exchangeRate ?? ""
                        }
                        onChange={
                            (event) =>
                                updateItem(
                                    "exchangeRate",
                                    event?.target?.value
                                )
                        }
                        error={
                            !(Number(item?.exchangeRate) > 0)
                        }
                        helperText={
                            Number(item?.exchangeRate) > 0
                                ? `Total = ETB ${formatAmount(itemTotalCost * Number(item.exchangeRate))}`
                                : "Needed to count this item in ETB"
                        }
                        inputProps={{
                            min: 0,
                            step: "0.0001"
                        }}
                        fullWidth
                    />

                )}


                <AppTextField
                    label={`Unit Cost (${itemCurrency(item)})`}
                    required
                    type="number"
                    value={
                        item?.unitCost ?? 0
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "unitCost",
                                event?.target?.value
                            )
                    }
                    inputProps={{
                        min: 0,
                        step: "0.01"
                    }}
                    fullWidth
                />


                <AppTextField
                    label={`Total Cost (${itemCurrency(item)})`}
                    value={
                        calculateTotalCost(
                            item?.quantity,
                            item?.unitCost
                        )
                    }
                    InputProps={{
                        readOnly: true
                    }}
                    fullWidth
                />


                {/* donor and donation: only with the funding module */}
                {fundingOn && (
                <AppSelect
                    label="Donor"
                    value={
                        donorValue
                    }
                    options={
                        filteredDonorOptions
                    }
                    helperText={
                        !donorsLoading && filteredDonorOptions.length === 0
                            ? "No donation can pay for this work: only unrestricted donations and those restricted to this program / project are offered."
                            : undefined
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "donor",
                                event?.target?.value ??
                                event
                            )
                    }
                    disabled={
                        donorsLoading ||
                        filteredDonorOptions.length === 0
                    }
                    fullWidth
                />
                )}


                {fundingOn && (
                <AppSelect
                    label="Donation"
                    value={
                        donationValue
                    }
                    options={
                        filteredDonationOptions
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "donation",
                                event?.target?.value ??
                                event
                            )
                    }
                    disabled={
                        !donorValue ||
                        donationsLoading ||
                        donationsLoadingOrEmpty(
                            filteredDonationOptions
                        )
                    }
                    fullWidth
                />
                )}

            </Box>

            {/* ETB item paid from a foreign donation: its rate */}

            {paidFromForeignDonation && (

                <Box sx={{ mt: 1.5, maxWidth: 420 }}>
                    <AppTextField
                        label={`Exchange rate for this donation (1 ${donationCurrencyCode} = ? ETB)`}
                        type="number"
                        value={item?.donationRate ?? (Number(selectedDonationRecord?.receivedRate) > 0 ? selectedDonationRecord.receivedRate : "")}
                        onChange={(event) => updateItem("donationRate", event?.target?.value ?? event)}
                        inputProps={{ min: 0, step: "any" }}
                        helperText={
                            donationRateValue > 0
                                ? `This item costs ETB ${formatAmount(itemTotalCost)}: ${donationCurrencyCode} ${formatAmount(itemCostInDonationCurrency)} is charged to the donation.${Number(item?.donationRate) > 0 ? "" : " Filled in with the rate the donation was received at."}`
                                : `The donation is in ${donationCurrencyCode}: give the rate to charge it.`
                        }
                        fullWidth
                    />
                </Box>

            )}

            {/* Donation trace: unlinked costs reach no donor. */}

            {fundingOn && !donationValue && (

                <Alert
                    severity="warning"
                    variant="outlined"
                    sx={{
                        mt: 1.5
                    }}
                >
                    Not linked to a donation. This cost will not appear in any donor&apos;s &quot;Where did it go?&quot; trace. Choose the donor and the donation that paid for it.
                </Alert>

            )}

            {/* The chosen donation: what it has left */}

            {selectedDonationFunding && selectedDonationRecord?.status !== "Cancelled" && (

                <Typography
                    variant="body2"
                    color={
                        itemCostInDonationCurrency !== null &&
                        itemCostInDonationCurrency > selectedDonationFunding.left + 0.01
                            ? "warning.main"
                            : "text.secondary"
                    }
                    sx={{
                        mt: 1
                    }}
                >
                    {`This donation has ${selectedDonationFunding.currency} ${formatAmount(selectedDonationFunding.left)} left of ${formatAmount(selectedDonationFunding.amount)} (used: ${formatAmount(selectedDonationFunding.byDeliveries)} in service deliveries, ${formatAmount(selectedDonationFunding.byExpenses)} in expenses). What this delivery already saved is counted as used; it is checked again when you save.`}
                    {itemCostInDonationCurrency === null && ` This item is in ${itemCurrency(item)}: give it in ${selectedDonationFunding.currency}${selectedDonationFunding.currency === BASE_CURRENCY ? " with its exchange rate" : ""} to charge this donation.`}
                </Typography>

            )}

            {/* Bought with an expense: the donation is charged once */}

            {donationValue && (expenseOptions.length > 0 || paidByExpenseValue) && (

                <Box
                    sx={{
                        mt: 1.5,
                        maxWidth: 640
                    }}
                >

                    <AppSelect
                        label="Bought with expense"
                        value={paidByExpenseValue}
                        options={expenseSelectOptions}
                        onChange={
                            (event) =>
                                updateItem(
                                    "paidByExpense",
                                    (event?.target?.value ?? event) || null
                                )
                        }
                        helperText={
                            paidByExpenseValue
                                ? "These items were bought with that expense: the donation is charged once, by the expense."
                                : "If these items were bought with an expense on this donation, choose it so the money is not counted twice."
                        }
                        fullWidth
                    />

                </Box>

            )}

            {suggestedExpense && (

                <Alert
                    severity="warning"
                    variant="outlined"
                    sx={{
                        mt: 1.5
                    }}
                    action={
                        <Box sx={{ display: "flex", gap: 1, flexWrap: "wrap" }}>
                            <AppButton
                                size="small"
                                variant="contained"
                                onClick={() => updateItem("paidByExpense", String(suggestedExpense._id))}
                            >
                                Yes, link it
                            </AppButton>
                            <AppButton
                                size="small"
                                variant="outlined"
                                onClick={() => updateItem("separateFromExpenses", [...separateExpenses, String(suggestedExpense._id)])}
                            >
                                No, separate
                            </AppButton>
                        </Box>
                    }
                >
                    {`Expense ${suggestedExpense.expenseCode}${suggestedExpense.description ? ` "${suggestedExpense.description}"` : ""} (${suggestedExpense.currency || "ETB"} ${Number(suggestedExpense.amount).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}, ${suggestedExpense.expenseDate ? formatDate(suggestedExpense.expenseDate) : ""}) is on the same donation, with about the same amount. Were these items bought with it? If so, the donation is charged once.`}
                </Alert>

            )}

            {/* The chosen donation: pledged only, cancelled, or too small */}

            {selectedDonationRecord && (

                selectedDonationRecord.status === "Cancelled"
                    ? (
                        <Alert
                            severity="error"
                            variant="outlined"
                            sx={{
                                mt: 1.5
                            }}
                        >
                            This donation is cancelled and cannot pay for this item. Choose another donation.
                        </Alert>
                    )
                    : itemCostInDonationCurrency !== null &&
                        itemCostInDonationCurrency > Number(selectedDonationRecord.amount || 0) + 0.01
                        ? (
                            <Alert
                                severity="warning"
                                variant="outlined"
                                sx={{
                                    mt: 1.5
                                }}
                            >
                                This item costs {formatAmount(itemCostInDonationCurrency)} {selectedDonationRecord.currency || "ETB"}, more than the whole donation ({formatAmount(selectedDonationRecord.amount)} {selectedDonationRecord.currency || "ETB"}). It cannot be saved this way: lower the cost or split it across donations.
                            </Alert>
                        )
                        : selectedDonationRecord.status === "Pledged"
                            ? (
                                <Alert
                                    severity="info"
                                    variant="outlined"
                                    sx={{
                                        mt: 1.5
                                    }}
                                >
                                    This donation is still pledged, not received. The cost is charged to it, but the donor&apos;s funding counts only received money.
                                </Alert>
                            )
                            : null

            )}

            <Box
                sx={{
                    mt: 2
                }}
            >

                <AppTextField
                    label="Remarks"
                    value={
                        item?.remarks ?? ""
                    }
                    onChange={
                        (event) =>
                            updateItem(
                                "remarks",
                                event?.target?.value
                            )
                    }
                    multiline
                    minRows={2}
                    fullWidth
                />

            </Box>

            <Divider
                sx={{
                    my: 3
                }}
            />

            <Box
                sx={{
                    display: "flex",
                    justifyContent: "space-between",
                    alignItems: "center",
                    mb: 2
                }}
            >

                <Typography
                    variant="subtitle2"
                    sx={{
                        fontWeight: 600
                    }}
                >
                    Detail Items
                </Typography>


                <AppButton
                    type="button"
                    variant="outlined"
                    size="small"
                    startIcon={
                        <Add />
                    }
                    onClick={
                        addDetailItem
                    }
                >
                    Add Detail Item
                </AppButton>

            </Box>

            {
                detailItems.length === 0
                    ? (
                        <Typography
                            variant="body2"
                            sx={{
                                color: "text.secondary"
                            }}
                        >
                            No detail items added.
                        </Typography>
                    )
                    : (
                        <Box
                            sx={{
                                display: "flex",
                                flexDirection: "column",
                                gap: 2
                            }}
                        >

                            {
                                detailItems.map(
                                    (
                                        detailItem,
                                        detailIndex
                                    ) => {

                                        const detailUnitValue =
                                            normalizeLookupValue(
                                                detailItem?.unit
                                            );


                                        const detailAllocationUnitValue =
                                            normalizeLookupValue(
                                                detailItem?.allocationUnit
                                            ) ||
                                            "";


                                        const detailTotal =
                                            calculateTotalCost(
                                                detailItem?.quantity,
                                                detailItem?.unitCost
                                            );


                                        return (

                                            <Box
                                                key={
                                                    normalizeLookupValue(
                                                        detailItem?._id ??
                                                        detailItem?.id
                                                    ) ||
                                                    `detail-item-${index}-${detailIndex}`
                                                }
                                                sx={{
                                                    display: "grid",
                                                    gridTemplateColumns: {
                                                        xs: "1fr",
                                                        md: "2fr 1fr 1fr 1fr auto"
                                                    },
                                                    gap: 2,
                                                    alignItems: "center"
                                                }}
                                            >

                                                <AppTextField
                                                    label="Name"
                                                    required
                                                    value={
                                                        detailItem?.name ??
                                                        ""
                                                    }
                                                    onChange={
                                                        (event) =>
                                                            updateDetailItem(
                                                                detailIndex,
                                                                "name",
                                                                event?.target?.value
                                                            )
                                                    }
                                                    fullWidth
                                                />


                                                <AppTextField
                                                    label="Quantity"
                                                    required
                                                    type="number"
                                                    value={
                                                        detailItem?.quantity ??
                                                        1
                                                    }
                                                    onChange={
                                                        (event) =>
                                                            updateDetailItem(
                                                                detailIndex,
                                                                "quantity",
                                                                event?.target?.value
                                                            )
                                                    }
                                                    inputProps={{
                                                        min: 0,
                                                        step:
                                                            quantityStep(
                                                                detailItem?.unit,
                                                                unitOptions
                                                            )
                                                    }}
                                                    fullWidth
                                                />


                                                <AppSelect
                                                    label="Unit"
                                                    required
                                                    value={
                                                        detailUnitValue
                                                    }
                                                    options={
                                                        detailUnitOptions
                                                    }
                                                    onChange={
                                                        (event) =>
                                                            updateDetailItem(
                                                                detailIndex,
                                                                "unit",
                                                                event?.target?.value ??
                                                                event
                                                            )
                                                    }
                                                    fullWidth
                                                />


                                                <AppTextField
                                                    label="Unit Cost"
                                                    required
                                                    type="number"
                                                    value={
                                                        detailItem?.unitCost ??
                                                        0
                                                    }
                                                    onChange={
                                                        (event) =>
                                                            updateDetailItem(
                                                                detailIndex,
                                                                "unitCost",
                                                                event?.target?.value
                                                            )
                                                    }
                                                    inputProps={{
                                                        min: 0,
                                                        step: "0.01"
                                                    }}
                                                    fullWidth
                                                />


                                                <Box
                                                    sx={{
                                                        display: "flex",
                                                        alignItems: "center",
                                                        gap: 1
                                                    }}
                                                >

                                                    <AppTextField
                                                        label="Total"
                                                        value={
                                                            detailTotal
                                                        }
                                                        InputProps={{
                                                            readOnly: true
                                                        }}
                                                    />


                                                    <AppButton
                                                        type="button"
                                                        variant="outlined"
                                                        onClick={
                                                            () =>
                                                                removeDetailItem(
                                                                    detailIndex
                                                                )
                                                        }
                                                        startIcon={
                                                            <Delete />
                                                        }
                                                    >
                                                        Remove
                                                    </AppButton>

                                                </Box>


                                                {/* Given out in another unit: 1 Sack = 50 Kg */}

                                                {!amountUnit && (

                                                    <Box
                                                        sx={{
                                                            gridColumn: "1 / -1",
                                                            display: "grid",
                                                            gridTemplateColumns: {
                                                                xs: "1fr",
                                                                md: "2fr 1fr 2fr"
                                                            },
                                                            gap: 2,
                                                            alignItems: "center"
                                                        }}
                                                    >

                                                        <AppSelect
                                                            label="Given out in"
                                                            placeholder="Same unit"
                                                            value={
                                                                detailAllocationUnitValue
                                                            }
                                                            options={
                                                                goodsUnitOptions.filter(
                                                                    option =>
                                                                        String(option?.value) !==
                                                                        String(detailUnitValue)
                                                                )
                                                            }
                                                            onChange={
                                                                (event) =>
                                                                    updateDetailItem(
                                                                        detailIndex,
                                                                        "allocationUnit",
                                                                        event?.target?.value ??
                                                                        event
                                                                    )
                                                            }
                                                            disabled={
                                                                !detailUnitValue
                                                            }
                                                            fullWidth
                                                        />


                                                        {detailAllocationUnitValue && (

                                                            <AppTextField
                                                                label={
                                                                    `${unitName(detailUnitValue)} holds`
                                                                }
                                                                type="number"
                                                                value={
                                                                    detailItem?.allocationConversionFactor ??
                                                                    1
                                                                }
                                                                onChange={
                                                                    (event) =>
                                                                        updateDetailItem(
                                                                            detailIndex,
                                                                            "allocationConversionFactor",
                                                                            event?.target?.value
                                                                        )
                                                                }
                                                                inputProps={{
                                                                    min: 0,
                                                                    step: "any"
                                                                }}
                                                                helperText={
                                                                    unitName(detailAllocationUnitValue)
                                                                }
                                                                fullWidth
                                                            />

                                                        )}


                                                        <Typography
                                                            variant="body2"
                                                            sx={{
                                                                color: "text.secondary",
                                                                gridColumn: detailAllocationUnitValue
                                                                    ? "auto"
                                                                    : { md: "span 2" }
                                                            }}
                                                        >
                                                            {
                                                                detailAllocationUnitValue
                                                                    ? `1 ${unitName(detailUnitValue)} = ${Number(detailItem?.allocationConversionFactor || 0)} ${unitName(detailAllocationUnitValue)}. Beneficiaries share ${Number(detailItem?.quantity || 0) * Number(detailItem?.allocationConversionFactor || 0)} ${unitName(detailAllocationUnitValue)}.`
                                                                    : "Beneficiaries receive it in the same unit."
                                                            }
                                                        </Typography>

                                                    </Box>

                                                )}

                                            </Box>

                                        );

                                    }
                                )
                            }

                        </Box>
                    )
            }


            {detailTotalMismatch && (

                <Alert
                    severity="warning"
                    variant="outlined"
                    sx={{
                        mt: 2
                    }}
                >
                    The detail items add up to {formatAmount(detailItemsTotal)}, but this item costs {formatAmount(itemTotalCost)}. They must be equal before you can save.
                </Alert>

            )}

        </Box>
    );

};


// =====================================================
// DONATION OPTION EMPTY CHECK
// =====================================================

const donationsLoadingOrEmpty = (
    options
) => {

    return !Array.isArray(
        options
    ) ||
    options.length === 0;

};


// =====================================================
// SERVICE DELIVERY ITEMS
// =====================================================

const ServiceDeliveryItems = ({
    items = [],
    setItems,
    serviceCategories = [],
    units = [],
    project = null,
    work = {}
}) => {

    // editing: this delivery's own links are not "taken"
    const {
        id: deliveryId
    } = useParams();

    const [
        donorOptions,
        setDonorOptions
    ] =
        useState([]);


    const [
        donationOptions,
        setDonationOptions
    ] =
        useState([]);


    const [
        donorsLoading,
        setDonorsLoading
    ] =
        useState(false);


    const [
        donationsLoading,
        setDonationsLoading
    ] =
        useState(false);


    // =================================================
    // LOAD DONORS
    // =================================================

    useEffect(
        () => {

            let mounted = true;


            const loadDonors =
                async () => {

                    setDonorsLoading(
                        true
                    );


                    try {

                        const response =
                            await getDonorsLookupService();


                        if (
                            !mounted
                        ) {

                            return;

                        }


                        setDonorOptions(
                            normalizeDonorOptions(
                                response
                            )
                        );

                    }
                    catch (
                        error
                    ) {

                        if (
                            !mounted
                        ) {

                            return;

                        }


                        console.error(
                            "Failed to load donors:",
                            error
                        );


                        setDonorOptions(
                            []
                        );

                    }
                    finally {

                        if (
                            mounted
                        ) {

                            setDonorsLoading(
                                false
                            );

                        }

                    }

                };


            loadDonors();


            return () => {

                mounted = false;

            };

        },
        []
    );


    // =================================================
    // LOAD DONATIONS
    // =================================================

    useEffect(
        () => {

            let mounted = true;


            const loadDonations =
                async () => {

                    setDonationsLoading(
                        true
                    );


                    try {

                        const response =
                            await getDonationsService({
                                limit:
                                    1000
                            });


                        if (
                            !mounted
                        ) {

                            return;

                        }


                        setDonationOptions(
                            normalizeDonationOptions(
                                response
                            )
                        );

                    }
                    catch (
                        error
                    ) {

                        if (
                            !mounted
                        ) {

                            return;

                        }


                        console.error(
                            "Failed to load donations:",
                            error
                        );


                        setDonationOptions(
                            []
                        );

                    }
                    finally {

                        if (
                            mounted
                        ) {

                            setDonationsLoading(
                                false
                            );

                        }

                    }

                };


            loadDonations();


            return () => {

                mounted = false;

            };

        },
        []
    );


    // =================================================
    // LOAD SERVICE DELIVERY UNITS
    // =================================================

    const {
        data: unitsResponse,
        isLoading: unitsHookLoading
    } =
        useLookupsByModuleAndCategory(
            "ServiceDelivery",
            "Unit"
        );


    const parentUnits =
        Array.isArray(
            units
        )
            ? units
            : [];


    const fallbackUnits =
        normalizeResponseArray(
            unitsResponse
        );


    const rawUnits =
        parentUnits.length > 0
            ? parentUnits
            : fallbackUnits;


    const unitsLoading =
        parentUnits.length > 0
            ? false
            : unitsHookLoading;


    // =================================================
    // UNIT OPTIONS
    // =================================================

    const unitOptions =
        useMemo(
            () => {

                const normalizedOptions =
                    rawUnits
                        .filter(
                            unit =>
                                unit?.active !== false
                        )
                        .map(
                            normalizeLookupOption
                        )
                        .filter(
                            Boolean
                        );


                const uniqueOptions =
                    [];


                const seen =
                    new Set();


                normalizedOptions.forEach(
                    option => {

                        const key =
                            String(
                                option.value
                            );


                        if (
                            seen.has(
                                key
                            )
                        ) {

                            return;

                        }


                        seen.add(
                            key
                        );


                        uniqueOptions.push(
                            option
                        );

                    }
                );


                return uniqueOptions;

            },
            [
                rawUnits
            ]
        );


    // =================================================
    // CATEGORY OPTIONS
    // =================================================

    const categoryOptions =
        useMemo(
            () => {

                if (
                    !Array.isArray(
                        serviceCategories
                    )
                ) {

                    return [];

                }


                const normalizedOptions =
                    serviceCategories
                        .map(
                            normalizeLookupOption
                        )
                        .filter(
                            Boolean
                        );


                const uniqueOptions =
                    [];


                const seen =
                    new Set();


                normalizedOptions.forEach(
                    option => {

                        const key =
                            String(
                                option.value
                            );


                        if (
                            seen.has(
                                key
                            )
                        ) {

                            return;

                        }


                        seen.add(
                            key
                        );


                        uniqueOptions.push(
                            option
                        );

                    }
                );


                return uniqueOptions;

            },
            [
                serviceCategories
            ]
        );


    // =================================================
    // ADD SERVICE ITEM
    // =================================================

    const addItem = () => {

        const newItem = {

            _id:
                generateObjectId(),

            serviceCategory:
                "",

            serviceType:
                "",

            serviceTypeLabel:
                "",

            allocationBehavior:
                null,

            quantity:
                1,

            unit:
                "",

            unitCost:
                0,
            totalCost:
                0,
            currency:
                BASE_CURRENCY,
            exchangeRate:
                null,
            donor:
                null,

            donation:
                null,

            detailItems:
                [],

            remarks:
                ""

        };


        setItems(
            previousItems => {

                const existingItems =
                    Array.isArray(
                        previousItems
                    )
                        ? previousItems
                        : [];


                return [

                    ...existingItems,

                    newItem

                ];

            }
        );

    };


    // =================================================
    // RENDER
    // =================================================

    return (

        <Box
            sx={{
                width:
                    "100%"
            }}
        >

            {
                Array.isArray(
                    items
                ) &&
                items.map(
                    (
                        item,
                        index
                    ) => (

                        <ServiceDeliveryItemRow

                            key={
                                normalizeLookupValue(
                                    item?._id ??
                                    item?.id
                                ) ||
                                `service-item-${index}`
                            }

                            item={
                                item
                            }
                            index={
                                index
                            }
                            project={
                                normalizeLookupValue(project) || null
                            }
                            work={
                                work
                            }
                            deliveryId={
                                deliveryId || null
                            }

                            setItems={
                                setItems
                            }

                            serviceCategories={
                                categoryOptions
                            }

                            unitOptions={
                                unitOptions
                            }

                            unitsLoading={
                                unitsLoading
                            }

                            donorOptions={
                                donorOptions
                            }

                            donationOptions={
                                donationOptions
                            }

                            donorsLoading={
                                donorsLoading
                            }

                            donationsLoading={
                                donationsLoading
                            }

                        />

                    )
                )
            }


            {/* =================================================
                ADD SERVICE ITEM
            ================================================= */}

            <Box
                sx={{
                    width:
                        "100%",

                    mt:
                        2,

                    mb:
                        2,

                    display:
                        "flex",

                    justifyContent:
                        "flex-start",

                    alignItems:
                        "center"
                }}
            >

                <AppButton
                    type="button"
                    variant="outlined"
                    startIcon={
                        <Add />
                    }
                    onClick={
                        addItem
                    }
                >
                    Add Service Item
                </AppButton>

            </Box>

        </Box>

    );

};


export default ServiceDeliveryItems;
