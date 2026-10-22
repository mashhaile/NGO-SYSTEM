const mongoose =
    require("mongoose");

const Donation =
    require("../models/donation");

const Donor =
    require("../models/donor");

const ServiceDelivery =
    require("../models/ServiceDelivery");

const ServiceDeliveryBeneficiary =
    require("../models/ServiceDeliveryBeneficiary");

const ActivityRun =
    require("../models/ActivityRun");

const AttendanceRecord =
    require("../models/AttendanceRecord");

const TermsOfReference =
    require("../models/TermsOfReference");

const ApiError =
    require("../utils/apiError");

const {
    COUNTED_DELIVERY_FILTER
} = require("../constants/serviceDeliveryStatus");



// =====================================================
// DONATION TRACE
// =====================================================
//
// Follows a donation to where it was used:
//
// Donation ─► service delivery items funded by it
//          ─► beneficiaries who received those items
//          ─► activities, attendance and approved TORs
//
// An item is funded by a donation when item.donation
// is that donation, or (legacy) when the item has no
// donation and the delivery itself names the donation.
//
// A beneficiary is reached by the donation when they
// received at least one funded item (an allocation on
// it), or their delivery has no item-level allocations.
//
// Beneficiary NAMES are only included on request
// (includeNames); otherwise only aggregated numbers.
//
// =====================================================


const toId = (value) =>
    value && typeof value === "object"
        ? String(value._id || value)
        : value
            ? String(value)
            : "";


const toNumber = (value) => {

    const number =
        Number(value);

    return Number.isFinite(number)
        ? number
        : 0;

};


const roundMoney = (value) =>
    Math.round(toNumber(value) * 100) / 100;


// Money items (Cash Assistance in ETB) have no quantity of
// their own: 8 x 5,000 ETB is 40,000 ETB, not "8 ETB".
const {
    getUnitSemantics
} = require("../config/serviceDeliveryUnits");

const isMoneyUnit = (unit) => {
    const type = String(unit?.semanticType || "").toLowerCase();
    if (type) return type === "monetary";
    return [unit?.code, unit?.value].some(code => code && getUnitSemantics(code) === "monetary");
};

const shownQuantity = (item) =>
    isMoneyUnit(item.unit)
        ? toNumber(item.totalCost)
        : toNumber(item.quantity);


const fullName = (person) =>
    [
        person?.firstName,
        person?.middleName,
        person?.lastName
    ]
        .filter(Boolean)
        .join(" ");


const AGE_BANDS = [
    [0, 17, "Under 18"],
    [18, 29, "18–29"],
    [30, 49, "30–49"],
    [50, 200, "50 and over"]
];


const ageBand = (beneficiary) => {

    let age =
        beneficiary?.age;

    if (
        (age === null || age === undefined) &&
        beneficiary?.dateOfBirth
    ) {
        age =
            Math.floor(
                (Date.now() - new Date(beneficiary.dateOfBirth)) /
                (365.25 * 24 * 3600 * 1000)
            );
    }

    if (age === null || age === undefined || Number.isNaN(Number(age))) {
        return "Unknown";
    }

    const band =
        AGE_BANDS.find(
            ([min, max]) =>
                age >= min &&
                age <= max
        );

    return band
        ? band[2]
        : "Unknown";

};


const countBy = (items, keyFn) => {

    const counts = new Map();

    items.forEach(item => {

        const key =
            keyFn(item) || "Unknown";

        counts.set(
            key,
            (counts.get(key) || 0) + 1
        );

    });

    return Array.from(counts, ([label, count]) => ({ label, count }))
        .sort((a, b) => b.count - a.count);

};


const codeName = (item, codeKey) =>
    item && typeof item === "object"
        ? {
            id: toId(item),
            code: item[codeKey] || "",
            name: item.name || ""
        }
        : null;


const locationText = (record) =>
    [
        record?.woreda,
        record?.zone,
        record?.region
    ]
        .filter(Boolean)
        .join(", ");



// =====================================================
// CORE: trace one donation
// =====================================================

const traceDonation = async (
    donation,
    organizationId,
    options = {}
) => {

    const donationId =
        toId(donation._id);


    // ---------------- Funded deliveries -------------

    const deliveries =
        await ServiceDelivery.find({
            organization: organizationId,
            isDeleted: false,
            ...COUNTED_DELIVERY_FILTER,
            $or: [
                { "items.donation": donation._id },
                { donation: donation._id }
            ]
        })
            .populate("project", "projectCode name")
            .populate("activity", "activityCode name")
            .populate("activityRun", "runCode name")
            .populate("items.serviceType", "value")
            .populate("items.unit", "value code semanticType")
            .sort({ deliveryDate: 1 })
            .lean();


    const fundedItemIds = new Set();

    let used = 0;

    const deliveryRows = [];

    const serviceTypeTotals = new Map();

    const projectTotals = new Map();

    const activityTotals = new Map();

    const locationTotals = new Map();


    deliveries.forEach(delivery => {

        const deliveryFundedByDonation =
            toId(delivery.donation) === donationId;

        const fundedItems =
            (delivery.items || []).filter(item =>
                toId(item.donation) === donationId ||
                (!item.donation && deliveryFundedByDonation)
            );

        if (!fundedItems.length) {
            return;
        }

        let deliveryAmount = 0;

        fundedItems.forEach(item => {

            fundedItemIds.add(toId(item._id));

            const cost =
                toNumber(item.totalCost);

            deliveryAmount += cost;

            const typeName =
                item.serviceType?.value || "Service";

            const unitName =
                item.unit?.value || "";

            const key =
                `${typeName}|${unitName}`;

            const current =
                serviceTypeTotals.get(key) || {
                    service: typeName,
                    unit: unitName,
                    quantity: 0,
                    amount: 0,
                    deliveries: 0
                };

            current.quantity += shownQuantity(item);
            current.amount += cost;
            current.deliveries += 1;

            serviceTypeTotals.set(key, current);

        });

        used += deliveryAmount;

        const addTo = (map, key, label) => {

            if (!key) {
                return;
            }

            const current =
                map.get(key) || {
                    ...label,
                    amount: 0,
                    deliveries: 0
                };

            current.amount += deliveryAmount;
            current.deliveries += 1;

            map.set(key, current);

        };

        addTo(
            projectTotals,
            toId(delivery.project),
            { project: codeName(delivery.project, "projectCode") }
        );

        addTo(
            activityTotals,
            toId(delivery.activity),
            { activity: codeName(delivery.activity, "activityCode") }
        );

        const place =
            locationText(delivery) || delivery.deliveryLocation || "";

        addTo(
            locationTotals,
            place || "Unspecified",
            {
                location: place || "Unspecified",
                region: delivery.region || "",
                zone: delivery.zone || "",
                woreda: delivery.woreda || ""
            }
        );

        deliveryRows.push({
            id: toId(delivery._id),
            deliveryNumber: delivery.deliveryNumber,
            date: delivery.deliveryDate,
            project: codeName(delivery.project, "projectCode"),
            activity: codeName(delivery.activity, "activityCode"),
            recipientType: delivery.recipientType,
            recipientName: delivery.recipientName || "",
            allocationMethod: delivery.allocationMethod,
            location: place,
            amount: roundMoney(deliveryAmount),
            services:
                fundedItems.map(item => ({
                    service: item.serviceType?.value || "Service",
                    quantity: shownQuantity(item),
                    unit: item.unit?.value || "",
                    amount: roundMoney(item.totalCost)
                })),
            beneficiaries: 0
        });

    });


    // ---------------- Beneficiaries reached ---------

    const deliveryIds =
        deliveryRows.map(row => row.id);

    const links =
        deliveryIds.length
            ? await ServiceDeliveryBeneficiary.find({
                organization: organizationId,
                serviceDelivery: {
                    $in: deliveryIds
                }
            })
                .populate({
                    path: "beneficiary",
                    select:
                        "beneficiaryNumber firstName middleName lastName gender age dateOfBirth region zone woreda kebele",
                    populate: {
                        path: "gender",
                        select: "value"
                    }
                })
                .lean()
            : [];


    const reached = new Map();

    const deliveryRowById =
        new Map(
            deliveryRows.map(row => [row.id, row])
        );

    // Per delivery: what this donation paid that no one's
    // own allocation covers, and how many people on it have
    // no allocation of their own. They share it equally
    // (only people: households, groups and institutions
    // are not split among their members).
    const leftByDelivery = new Map();

    links.forEach(link => {
        const id = toId(link.serviceDelivery);
        const row = deliveryRowById.get(id);
        if (!row || (row.recipientType || "Individual") !== "Individual") return;
        const current = leftByDelivery.get(id) || { left: row.amount, without: 0 };
        const allocations = link.allocations || [];
        if (allocations.length === 0) {
            current.without += 1;
        }
        else {
            current.left -= allocations
                .filter(allocation => fundedItemIds.has(toId(allocation.serviceItem)))
                .reduce((sum, allocation) => sum + toNumber(allocation.allocatedValue), 0);
        }
        leftByDelivery.set(id, current);
    });


    links.forEach(link => {

        if (!link.beneficiary) {
            return;
        }

        const allocations =
            link.allocations || [];

        const fundedAllocations =
            allocations.filter(allocation =>
                fundedItemIds.has(toId(allocation.serviceItem))
            );

        const received =
            allocations.length === 0 ||
            fundedAllocations.length > 0;

        if (!received) {
            return;
        }

        const beneficiaryId =
            toId(link.beneficiary);

        const share =
            leftByDelivery.get(toId(link.serviceDelivery));

        const value =
            allocations.length === 0
                ? (share && share.without > 0 ? Math.max(share.left, 0) / share.without : 0)
                : fundedAllocations.reduce(
                    (sum, allocation) =>
                        sum + toNumber(allocation.allocatedValue),
                    0
                );

        const row =
            deliveryRowById.get(toId(link.serviceDelivery));

        if (row) {
            row.beneficiaries += 1;
        }

        const current =
            reached.get(beneficiaryId) || {
                beneficiary: link.beneficiary,
                deliveries: 0,
                value: 0
            };

        current.deliveries += 1;
        current.value += value;

        reached.set(beneficiaryId, current);

    });


    const reachedList =
        Array.from(reached.values());


    // ---------------- Groups / institutions ---------

    const groupRecipients =
        deliveryRows
            .filter(row =>
                row.beneficiaries === 0 &&
                row.recipientType !== "Individual"
            )
            .map(row => ({
                recipientType: row.recipientType,
                recipientName: row.recipientName || row.recipientType,
                deliveryNumber: row.deliveryNumber,
                date: row.date
            }));


    // ---------------- Activities + attendance -------

    const activityIds =
        new Set(
            [
                toId(donation.activity),
                ...deliveryRows.map(row => row.activity?.id)
            ].filter(Boolean)
        );

    const runs =
        activityIds.size
            ? await ActivityRun.find({
                organization: organizationId,
                activity: {
                    $in: Array.from(activityIds)
                },
                isDeleted: false
            })
                .select("activity runCode name startDate endDate status")
                .populate("activity", "activityCode name")
                .lean()
            : [];

    const attendance =
        runs.length
            ? await AttendanceRecord.aggregate([
                {
                    $match: {
                        organization: new mongoose.Types.ObjectId(String(organizationId)),
                        activityRun: {
                            $in: runs.map(run => run._id)
                        },
                        status: {
                            $in: ["Present", "Late"]
                        }
                    }
                },
                {
                    $group: {
                        _id: "$activityRun",
                        attended: {
                            $sum: 1
                        }
                    }
                }
            ])
            : [];

    const attendedByRun =
        new Map(
            attendance.map(item => [toId(item._id), item.attended])
        );

    const activitiesFunded =
        runs.map(run => ({
            activity: codeName(run.activity, "activityCode"),
            run: {
                id: toId(run._id),
                code: run.runCode,
                name: run.name
            },
            startDate: run.startDate,
            endDate: run.endDate,
            status: run.status,
            attended: attendedByRun.get(toId(run._id)) || 0
        }));


    // ---------------- Approved TORs (planned) -------

    const tors =
        activityIds.size
            ? await TermsOfReference.find({
                organization: organizationId,
                isDeleted: false,
                status: "Approved",
                activity: {
                    $in: Array.from(activityIds)
                }
            })
                .select("torNumber title totalBudget currency approvedAt activity")
                .lean()
            : [];


    // ---------------- Totals ------------------------

    const amount =
        toNumber(donation.amount);

    const received =
        donation.status === "Received"
            ? amount
            : 0;

    const usedAmount =
        roundMoney(used);

    const totals = {
        currency: donation.currency || "ETB",
        pledged: donation.status === "Pledged" ? amount : 0,
        received,
        used: usedAmount,
        remaining: roundMoney(Math.max(received - usedAmount, 0)),
        overspent: roundMoney(Math.max(usedAmount - received, 0)),
        percentUsed:
            received > 0
                ? Math.round((usedAmount / received) * 1000) / 10
                : 0,
        deliveries: deliveryRows.length,
        beneficiariesReached: reachedList.length,
        groupsReached: groupRecipients.length
    };


    // ---------------- Timeline ----------------------

    const timeline = [
        {
            date: donation.donationDate,
            type: donation.status === "Received" ? "Received" : donation.status,
            label: `Donation ${donation.status.toLowerCase()}`,
            amount
        },
        ...deliveryRows.map(row => ({
            date: row.date,
            type: "Delivered",
            label:
                `${row.services.map(s => s.service).join(", ")}` +
                (row.location ? ` · ${row.location}` : ""),
            amount: row.amount,
            reference: row.deliveryNumber,
            beneficiaries: row.beneficiaries
        }))
    ]
        .filter(item => item.date)
        .sort((a, b) => new Date(a.date) - new Date(b.date));


    // ---------------- Result ------------------------

    const beneficiaries =
        reachedList.map(item => item.beneficiary);

    return {

        donation: {
            id: donationId,
            code: donation.donationCode,
            title: donation.title || "",
            amount,
            currency: donation.currency || "ETB",
            date: donation.donationDate,
            status: donation.status,
            fundingRestriction: donation.fundingRestriction,
            donationType: donation.donationType,
            donor: donation.donor
                ? {
                    id: toId(donation.donor),
                    name: donation.donor.name,
                    donorType: donation.donor.donorType,
                    shareBeneficiaryNames:
                        Boolean(donation.donor.shareBeneficiaryNames)
                }
                : null,
            program: codeName(donation.program, "programCode"),
            project: codeName(donation.project, "projectCode"),
            activity: codeName(donation.activity, "activityCode")
        },

        totals,

        breakdown: {
            byProject: Array.from(projectTotals.values()),
            byActivity: Array.from(activityTotals.values()),
            byService: Array.from(serviceTypeTotals.values()),
            byLocation: Array.from(locationTotals.values())
        },

        reach: {
            total: reachedList.length,
            byGender: countBy(beneficiaries, b => b.gender?.value),
            byAge: countBy(beneficiaries, ageBand),
            byRegion: countBy(beneficiaries, b => b.region),
            byWoreda: countBy(
                beneficiaries,
                b => [b.woreda, b.zone].filter(Boolean).join(", ")
            ),
            groups: groupRecipients
        },

        deliveries: deliveryRows,

        activities: activitiesFunded,

        tors: tors.map(tor => ({
            id: toId(tor._id),
            torNumber: tor.torNumber,
            title: tor.title,
            plannedBudget: tor.totalBudget,
            currency: tor.currency,
            approvedAt: tor.approvedAt
        })),

        timeline,

        namesIncluded: Boolean(options.includeNames),

        // Only when names are allowed for this viewer

        beneficiaries:
            options.includeNames
                ? reachedList
                    .map(item => ({
                        number: item.beneficiary.beneficiaryNumber,
                        name: fullName(item.beneficiary),
                        gender: item.beneficiary.gender?.value || "",
                        ageGroup: ageBand(item.beneficiary),
                        kebele: item.beneficiary.kebele || "",
                        location: locationText(item.beneficiary),
                        deliveries: item.deliveries,
                        value: roundMoney(item.value)
                    }))
                    .sort((a, b) => a.name.localeCompare(b.name))
                : undefined,

        // Internal: lets the donor trace count unique people

        _beneficiaryIds:
            reachedList.map(item => toId(item.beneficiary))

    };

};



// =====================================================
// PUBLIC FUNCTIONS
// =====================================================

const loadDonation = async (id, organizationId) => {

    if (!mongoose.isValidObjectId(id)) {
        throw new ApiError("Donation not found.", 404);
    }

    const donation =
        await Donation.findOne({
            _id: id,
            organization: organizationId,
            isDeleted: false
        })
            .populate("donor", "name donorType shareBeneficiaryNames")
            .populate("program", "programCode name")
            .populate("project", "projectCode name")
            .populate("activity", "activityCode name")
            .lean();

    if (!donation) {
        throw new ApiError("Donation not found.", 404);
    }

    return donation;

};


const stripInternal = (trace) => {

    const {
        _beneficiaryIds,
        ...rest
    } = trace;

    return rest;

};


const getDonationTrace = async (
    id,
    organizationId,
    options = {}
) => {

    const donation =
        await loadDonation(id, organizationId);

    return stripInternal(
        await traceDonation(
            donation,
            organizationId,
            options
        )
    );

};


// All donations of a donor, with combined totals.
// Beneficiaries are counted once even if several of the
// donor's donations reached them.

const getDonorTrace = async (
    donorId,
    organizationId
) => {

    if (!mongoose.isValidObjectId(donorId)) {
        throw new ApiError("Donor not found.", 404);
    }

    const donor =
        await Donor.findOne({
            _id: donorId,
            organization: organizationId,
            isDeleted: false
        })
            .select("name donorType shareBeneficiaryNames")
            .lean();

    if (!donor) {
        throw new ApiError("Donor not found.", 404);
    }

    const donations =
        await Donation.find({
            organization: organizationId,
            donor: donor._id,
            isDeleted: false,
            status: {
                $ne: "Cancelled"
            }
        })
            .populate("donor", "name donorType shareBeneficiaryNames")
            .populate("program", "programCode name")
            .populate("project", "projectCode name")
            .populate("activity", "activityCode name")
            .sort({ donationDate: -1 })
            .lean();

    const traces =
        await Promise.all(
            donations.map(donation =>
                traceDonation(donation, organizationId)
            )
        );

    const uniqueBeneficiaries =
        new Set(
            traces.flatMap(trace => trace._beneficiaryIds)
        );

    const sum = (key) =>
        roundMoney(
            traces.reduce(
                (total, trace) => total + toNumber(trace.totals[key]),
                0
            )
        );

    const received = sum("received");

    const used = sum("used");

    return {
        donor: {
            id: toId(donor._id),
            name: donor.name,
            donorType: donor.donorType,
            shareBeneficiaryNames: Boolean(donor.shareBeneficiaryNames)
        },
        totals: {
            donations: donations.length,
            pledged: sum("pledged"),
            received,
            used,
            remaining: roundMoney(Math.max(received - used, 0)),
            percentUsed:
                received > 0
                    ? Math.round((used / received) * 1000) / 10
                    : 0,
            deliveries: traces.reduce((total, trace) => total + trace.totals.deliveries, 0),
            beneficiariesReached: uniqueBeneficiaries.size
        },
        donations:
            traces.map(trace => ({
                ...trace.donation,
                totals: trace.totals
            }))
    };

};


// Delivered service items not linked to any donation.

const getUntracedSpending = async (
    organizationId,
    query = {}
) => {

    const limit =
        Math.min(500, Math.max(1, Number(query.limit) || 200));

    const deliveries =
        await ServiceDelivery.find({
            organization: organizationId,
            isDeleted: false,
            ...COUNTED_DELIVERY_FILTER,
            donation: null,
            "items.donation": null
        })
            .select("deliveryNumber deliveryDate project items region zone woreda deliveryLocation")
            .populate("project", "projectCode name")
            .populate("items.serviceType", "value")
            .sort({ deliveryDate: -1 })
            .limit(limit)
            .lean();

    const rows = [];

    let total = 0;

    deliveries.forEach(delivery => {

        (delivery.items || [])
            .filter(item => !item.donation)
            .forEach(item => {

                const amount =
                    roundMoney(item.totalCost);

                total += amount;

                rows.push({
                    deliveryId: toId(delivery._id),
                    deliveryNumber: delivery.deliveryNumber,
                    date: delivery.deliveryDate,
                    project: codeName(delivery.project, "projectCode"),
                    service: item.serviceType?.value || "Service",
                    quantity: shownQuantity(item),
                    amount,
                    location: locationText(delivery) || delivery.deliveryLocation || ""
                });

            });

    });

    return {
        rows,
        totals: {
            items: rows.length,
            amount: roundMoney(total)
        }
    };

};


module.exports = {
    getDonationTrace,
    getDonorTrace,
    getUntracedSpending,
    loadDonation,
    traceDonation
};
