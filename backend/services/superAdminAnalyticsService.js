const Organization =
    require("../models/organization");

const User =
    require("../models/user");

const Beneficiary =
    require("../models/Beneficiary");

const Donor =
    require("../models/donor");

const Program =
    require("../models/program");

const Subscription =
    require("../models/subscription");

const auditLogService =
    require("./auditLogService");


// =====================================================
// MONTHLY GROWTH
// =====================================================

const getMonthlyGrowth = async (
    Model
) => {

    const data =
        await Model.aggregate([

            {
                $match: {
                    createdAt: {
                        $exists: true,
                        $ne: null
                    }
                }
            },

            {
                $group: {

                    _id: {

                        year: {
                            $year: "$createdAt"
                        },

                        month: {
                            $month: "$createdAt"
                        }

                    },

                    count: {
                        $sum: 1
                    }

                }
            },

            {
                $sort: {

                    "_id.year": 1,

                    "_id.month": 1

                }

            }

        ]);


    return data.map(
        item => ({

            year:
                item._id.year,

            month:
                item._id.month,

            count:
                item.count

        })
    );

};


// =====================================================
// PLATFORM ANALYTICS
// =====================================================

const getPlatformAnalytics = async () => {


    // =================================================
    // ORGANIZATION / PLATFORM COUNTS
    // =================================================

    const [

        totalOrganizations,

        activeOrganizations,

        inactiveOrganizations,

        suspendedOrganizations,

        deletedOrganizations,

        totalUsers,

        totalBeneficiaries,

        totalDonors,

        totalPrograms

    ] = await Promise.all([


        // ---------------------------------------------
        // TOTAL
        // ---------------------------------------------

        Organization.countDocuments({

            isDeleted: false

        }),


        // ---------------------------------------------
        // ACTIVE
        // ---------------------------------------------

        Organization.countDocuments({

            status: "active",

            isDeleted: false

        }),


        // ---------------------------------------------
        // INACTIVE
        // ---------------------------------------------

        Organization.countDocuments({

            status: "inactive",

            isDeleted: false

        }),


        // ---------------------------------------------
        // SUSPENDED
        // ---------------------------------------------

        Organization.countDocuments({

            status: "suspended",

            isDeleted: false

        }),


        // ---------------------------------------------
        // DELETED
        // ---------------------------------------------

        Organization.countDocuments({

            isDeleted: true

        }),


        // ---------------------------------------------
        // USERS
        // ---------------------------------------------

        User.countDocuments({}),


        // ---------------------------------------------
        // BENEFICIARIES
        // ---------------------------------------------

        Beneficiary.countDocuments({

            isDeleted: false

        }),


        // ---------------------------------------------
        // DONORS
        // ---------------------------------------------

        Donor.countDocuments({

            isDeleted: false

        }),


        // ---------------------------------------------
        // PROGRAMS
        // ---------------------------------------------

        Program.countDocuments({

            isDeleted: false

        })

    ]);


    // =================================================
    // SUBSCRIPTION STATISTICS
    // =================================================

    const subscriptionAggregation =
        await Subscription.aggregate([

            {
                $group: {

                    _id: "$status",

                    count: {
                        $sum: 1
                    }

                }

            }

        ]);


    const subscriptionStats = {

        active: 0,

        expired: 0,

        pending: 0,

        cancelled: 0

    };


    subscriptionAggregation.forEach(
        item => {

            if (
                Object.prototype.hasOwnProperty.call(
                    subscriptionStats,
                    item._id
                )
            ) {

                subscriptionStats[
                    item._id
                ] =
                    item.count;

            }

        }
    );


    // =================================================
    // MONTHLY GROWTH
    // =================================================

    const [

        organizationGrowth,

        userGrowth

    ] = await Promise.all([

        getMonthlyGrowth(
            Organization
        ),

        getMonthlyGrowth(
            User
        )

    ]);


    // =================================================
    // ORGANIZATIONS
    // =================================================

    const organizations =
        await Organization.find({

            isDeleted: false

        })
        .select(
            "_id name status"
        )
        .lean();


    // =================================================
    // ORGANIZATION STATISTICS
    // =================================================

    const topOrganizations =
        await Promise.all(

            organizations.map(
                async organization => {


                    const [

                        users,

                        beneficiaries,

                        subscription

                    ] = await Promise.all([


                        // ---------------------------------
                        // USERS
                        // ---------------------------------

                        User.countDocuments({

                            organization:
                                organization._id

                        }),


                        // ---------------------------------
                        // BENEFICIARIES
                        // ---------------------------------

                        Beneficiary.countDocuments({

                            organization:
                                organization._id,

                            isDeleted: false

                        }),


                        // ---------------------------------
                        // SUBSCRIPTION
                        // ---------------------------------

                        Subscription.findOne({

                            organization:
                                organization._id

                        })
                        .sort({

                            createdAt: -1

                        })
                        .select(
                            "status"
                        )
                        .lean()

                    ]);


                    return {

                        id:
                            organization._id,

                        name:
                            organization.name,

                        users,

                        beneficiaries,

                        organizationStatus:
                            organization.status,

                        subscriptionStatus:
                            subscription
                                ? subscription.status
                                : "none"

                    };

                }
            )

        );


    // =================================================
    // SORT TOP ORGANIZATIONS
    // =================================================

    topOrganizations.sort(

        (a, b) =>
            b.beneficiaries -
            a.beneficiaries

    );


    const topTenOrganizations =
        topOrganizations.slice(
            0,
            10
        );


    // =================================================
    // PLATFORM HEALTH
    // =================================================

    const organizationsWithoutSubscription =
        topOrganizations.filter(

            organization =>
                organization.subscriptionStatus ===
                "none"

        ).length;


    // =================================================
    // RECENT ACTIVITIES
    // =================================================

    const recentActivities =
        await auditLogService.getRecentActivities(
            10
        );


    // =================================================
    // FINAL RESPONSE
    // =================================================

    return {

        organizations: {

            total:
                totalOrganizations,

            active:
                activeOrganizations,

            inactive:
                inactiveOrganizations,

            suspended:
                suspendedOrganizations,

            deleted:
                deletedOrganizations

        },


        users:
            totalUsers,


        beneficiaries:
            totalBeneficiaries,


        donors:
            totalDonors,


        programs:
            totalPrograms,


        subscriptions:
            subscriptionStats,


        monthlyGrowth: {

            organizations:
                organizationGrowth,

            users:
                userGrowth

        },


        platformHealth: {

            activeSubscriptions:
                subscriptionStats.active,

            expiredSubscriptions:
                subscriptionStats.expired,

            organizationsWithoutSubscription

        },


        topOrganizations:
            topTenOrganizations,


        recentActivities

    };

};


// =====================================================
// EXPORT
// =====================================================

module.exports = {

    getPlatformAnalytics

};