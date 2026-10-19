const crypto =
    require("crypto");

const mongoose =
    require("mongoose");

const DonorShareLink =
    require("../models/DonorShareLink");

const Donor =
    require("../models/donor");

const Donation =
    require("../models/donation");

const Organization =
    require("../models/organization");

const ApiError =
    require("../utils/apiError");

const {
    loadDonation,
    traceDonation,
    getDonorTrace
} = require("./donationTraceService");



// =====================================================
// DONOR SHARE LINKS
// =====================================================

const EXPIRY_OPTIONS_DAYS = [30, 90, 180, 365];

const DEFAULT_EXPIRY_DAYS = 90;

const MAX_RECENT_VIEWS = 50;

const ACTIVE_ORGANIZATION_STATUSES = ["trial", "active"];


const hashToken = (token) =>
    crypto
        .createHash("sha256")
        .update(String(token))
        .digest("hex");


const linkStatus = (link) => {

    if (link.revokedAt) {
        return "Revoked";
    }

    if (new Date(link.expiresAt) <= new Date()) {
        return "Expired";
    }

    return "Active";

};


const toPublicLink = (link) => ({
    id: String(link._id),
    label: link.label,
    donation: link.donation
        ? {
            id: String(link.donation._id || link.donation),
            code: link.donation.donationCode || "",
            title: link.donation.title || ""
        }
        : null,
    scope: link.donation ? "Donation" : "All donations",
    tokenHint: link.tokenHint,
    expiresAt: link.expiresAt,
    revokedAt: link.revokedAt,
    status: linkStatus(link),
    viewCount: link.viewCount,
    lastViewedAt: link.lastViewedAt,
    createdAt: link.createdAt,
    createdBy: link.createdBy?.name || link.createdBy?.email || ""
});



// =====================================================
// STAFF: CREATE / LIST / REVOKE
// =====================================================

const createShareLink = async (
    organizationId,
    userId,
    data
) => {

    if (!mongoose.isValidObjectId(data.donor)) {
        throw new ApiError("Donor not found.", 404);
    }

    const donor =
        await Donor.findOne({
            _id: data.donor,
            organization: organizationId,
            isDeleted: false
        })
            .select("_id")
            .lean();

    if (!donor) {
        throw new ApiError("Donor not found.", 404);
    }

    let donation = null;

    if (data.donation) {

        donation =
            await Donation.findOne({
                _id: data.donation,
                organization: organizationId,
                donor: donor._id,
                isDeleted: false
            })
                .select("_id")
                .lean();

        if (!donation) {
            throw new ApiError(
                "Donation not found for this donor.",
                404
            );
        }

    }

    const days =
        EXPIRY_OPTIONS_DAYS.includes(Number(data.expiresInDays))
            ? Number(data.expiresInDays)
            : DEFAULT_EXPIRY_DAYS;

    const token =
        crypto.randomBytes(32).toString("base64url");

    const link =
        await DonorShareLink.create({
            organization: organizationId,
            donor: donor._id,
            donation: donation?._id || null,
            label: data.label || "",
            tokenHash: hashToken(token),
            tokenHint: token.slice(-6),
            expiresAt: new Date(Date.now() + days * 24 * 3600 * 1000),
            createdBy: userId
        });

    // The token is returned only here; it is never stored.

    return {
        link: toPublicLink(link),
        token
    };

};


const listShareLinks = async (
    organizationId,
    donorId
) => {

    if (!mongoose.isValidObjectId(donorId)) {
        throw new ApiError("Donor not found.", 404);
    }

    const links =
        await DonorShareLink.find({
            organization: organizationId,
            donor: donorId
        })
            .populate("donation", "donationCode title")
            .populate("createdBy", "name email")
            .sort({ createdAt: -1 })
            .lean();

    return links.map(toPublicLink);

};


const revokeShareLink = async (
    organizationId,
    linkId,
    userId
) => {

    if (!mongoose.isValidObjectId(linkId)) {
        throw new ApiError("Share link not found.", 404);
    }

    const link =
        await DonorShareLink.findOneAndUpdate(
            {
                _id: linkId,
                organization: organizationId,
                revokedAt: null
            },
            {
                $set: {
                    revokedAt: new Date(),
                    revokedBy: userId
                }
            },
            {
                returnDocument: "after"
            }
        )
            .populate("donation", "donationCode title")
            .populate("createdBy", "name email")
            .lean();

    if (!link) {
        throw new ApiError(
            "Share link not found or already revoked.",
            404
        );
    }

    return toPublicLink(link);

};



// =====================================================
// PUBLIC (donor, no account)
// =====================================================
//
// Every failure returns the same message so a caller
// cannot tell an unknown token from an expired or
// revoked one.
//
// =====================================================

const UNAVAILABLE =
    "This link is not valid. It may have expired or been withdrawn. Please contact the organization for a new link.";


const resolveToken = async (token) => {

    if (
        typeof token !== "string" ||
        token.length < 32 ||
        token.length > 100
    ) {
        throw new ApiError(UNAVAILABLE, 404);
    }

    const link =
        await DonorShareLink.findOne({
            tokenHash: hashToken(token)
        }).lean();

    if (!link || linkStatus(link) !== "Active") {
        throw new ApiError(UNAVAILABLE, 404);
    }

    const organization =
        await Organization.findOne({
            _id: link.organization,
            isDeleted: false,
            status: {
                $in: ACTIVE_ORGANIZATION_STATUSES
            }
        })
            .select("name")
            .lean();

    if (!organization) {
        throw new ApiError(UNAVAILABLE, 404);
    }

    return {
        link,
        organization
    };

};


const recordView = (link, userAgent) =>
    DonorShareLink.updateOne(
        {
            _id: link._id
        },
        {
            $inc: {
                viewCount: 1
            },
            $set: {
                lastViewedAt: new Date()
            },
            $push: {
                recentViews: {
                    $each: [
                        {
                            at: new Date(),
                            userAgent: String(userAgent || "").slice(0, 200)
                        }
                    ],
                    $slice: -MAX_RECENT_VIEWS
                }
            }
        }
    );


// Remove internal ids / staff-only fields from a trace.

const toDonorFacingTrace = (trace) => {

    const {
        _beneficiaryIds,
        ...rest
    } = trace;

    return {
        ...rest,
        deliveries:
            (rest.deliveries || []).map(({ id, ...delivery }) => delivery),
        tors:
            (rest.tors || []).map(({ id, ...tor }) => tor)
    };

};


const getPublicView = async (token, userAgent) => {

    const {
        link,
        organization
    } = await resolveToken(token);

    const donor =
        await Donor.findOne({
            _id: link.donor,
            organization: link.organization,
            isDeleted: false
        })
            .select("name shareBeneficiaryNames")
            .lean();

    if (!donor) {
        throw new ApiError(UNAVAILABLE, 404);
    }

    const includeNames =
        Boolean(donor.shareBeneficiaryNames);

    const donations =
        link.donation
            ? [await loadDonation(link.donation, link.organization)]
            : await Donation.find({
                organization: link.organization,
                donor: link.donor,
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
                traceDonation(
                    donation,
                    link.organization,
                    { includeNames }
                )
            )
        );

    const summary =
        link.donation
            ? null
            : (await getDonorTrace(link.donor, link.organization)).totals;

    await recordView(link, userAgent);

    return {
        organization: {
            name: organization.name
        },
        donor: {
            name: donor.name
        },
        scope: link.donation ? "Donation" : "All donations",
        namesIncluded: includeNames,
        expiresAt: link.expiresAt,
        generatedAt: new Date(),
        summary,
        donations: traces.map(toDonorFacingTrace)
    };

};


// Donation must be within the link's scope.

const assertDonationInScope = async (token, donationId) => {

    const {
        link
    } = await resolveToken(token);

    if (!mongoose.isValidObjectId(donationId)) {
        throw new ApiError(UNAVAILABLE, 404);
    }

    if (
        link.donation &&
        String(link.donation) !== String(donationId)
    ) {
        throw new ApiError(UNAVAILABLE, 404);
    }

    const donation =
        await Donation.findOne({
            _id: donationId,
            organization: link.organization,
            donor: link.donor,
            isDeleted: false
        })
            .select("_id")
            .lean();

    if (!donation) {
        throw new ApiError(UNAVAILABLE, 404);
    }

    return link;

};


module.exports = {
    EXPIRY_OPTIONS_DAYS,
    createShareLink,
    listShareLinks,
    revokeShareLink,
    getPublicView,
    assertDonationInScope
};
