const Donor = require("../models/Donor");



// ==========================================
// CREATE DONOR
// ==========================================

const createDonor = async (

    data,

    organizationId,

    userId

) => {

    const exists = await Donor.findOne({

        organization: organizationId,

        name: data.name,

        donorType: data.donorType,

        isDeleted: false

    });


    if (exists) {

        throw new Error(
            "Donor already exists"
        );

    }


    const donor = await Donor.create({

        ...data,

        organization: organizationId,

        createdBy: userId

    });


    return donor;

};



// ==========================================
// GET ALL DONORS
// ==========================================

const getDonors = async (

    organizationId,

    query = {}

) => {

    const {

        search = "",

        donorType,

        status,

        country,

        page = 1,

        limit = 10

    } = query;


    const filter = {

        organization: organizationId,

        isDeleted: false

    };


    if (search) {

        filter.$or = [

            {
                name: {
                    $regex: search,
                    $options: "i"
                }
            },

            {
                email: {
                    $regex: search,
                    $options: "i"
                }
            },

            {
                phone: {
                    $regex: search,
                    $options: "i"
                }
            },

            {
                country: {
                    $regex: search,
                    $options: "i"
                }
            },

            {
                contactPerson: {
                    $regex: search,
                    $options: "i"
                }
            }

        ];

    }


    if (donorType) {

        filter.donorType =
            donorType;

    }


    if (status) {

        filter.status =
            status;

    }


    if (country) {

        filter.country =
            country;

    }


    const pageNumber =
        Number(page);

    const limitNumber =
        Number(limit);


    const skip =
        (pageNumber - 1) *
        limitNumber;


    const [
        data,
        total
    ] = await Promise.all([

        Donor.find(filter)

            .sort({
                createdAt: -1
            })

            .skip(skip)

            .limit(limitNumber),

        Donor.countDocuments(filter)

    ]);


    return {

        data,

        pagination: {

            total,

            page: pageNumber,

            limit: limitNumber,

            totalPages:
                Math.ceil(
                    total /
                    limitNumber
                )

        }

    };

};



// ==========================================
// DONOR LOOKUP
// ==========================================

const getDonorLookup = async (
    organizationId
) => {

    return Donor.find({

        organization:
            organizationId,

        isDeleted:
            false

    })

        .select(
            "_id name organizationName"
        )

        .sort({
            name: 1
        });

};



// ==========================================
// GET SINGLE DONOR
// ==========================================

const getDonorById = async (

    id,

    organizationId

) => {

    return await Donor.findOne({

        _id: id,

        organization:
            organizationId,

        isDeleted:
            false

    });

};



// ==========================================
// UPDATE DONOR
// ==========================================

const updateDonor = async (

    id,

    data,

    organizationId,

    userId

) => {

    const donor =
        await Donor.findOne({

            _id: id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!donor) {

        throw new Error(
            "Donor not found"
        );

    }


    // ==========================================
    // CHECK DUPLICATE
    // ==========================================

    const newName =
        data.name !== undefined
            ? data.name
            : donor.name;


    const newDonorType =
        data.donorType !== undefined
            ? data.donorType
            : donor.donorType;


    if (

        newName !== donor.name ||

        newDonorType !==
        donor.donorType

    ) {

        const exists =
            await Donor.findOne({

                organization:
                    organizationId,

                name:
                    newName,

                donorType:
                    newDonorType,

                isDeleted:
                    false,

                _id: {
                    $ne: id
                }

            });


        if (exists) {

            throw new Error(
                "Donor already exists"
            );

        }

    }


    // ==========================================
    // PROTECTED FIELDS
    // ==========================================

    delete data.organization;

    delete data.createdBy;

    delete data.updatedBy;

    delete data.isDeleted;

    delete data.deletedAt;

    delete data.deletedBy;


    // ==========================================
    // EXPLICIT DONOR FIELDS
    // ==========================================

    if (data.name !== undefined)
        donor.name =
            data.name;


    if (data.donorType !== undefined)
        donor.donorType =
            data.donorType;


    if (data.country !== undefined)
        donor.country =
            data.country || null;


    if (data.website !== undefined)
        donor.website =
            data.website || null;


    if (
        data.registrationNumber !==
        undefined
    )
        donor.registrationNumber =
            data.registrationNumber || null;


    if (data.email !== undefined)
        donor.email =
            data.email || null;


    if (data.phone !== undefined)
        donor.phone =
            data.phone || null;


    if (data.address !== undefined)
        donor.address =
            data.address || null;


    if (
        data.contactPerson !==
        undefined
    )
        donor.contactPerson =
            data.contactPerson || null;


    if (
        data.donorSince !==
        undefined
    )
        donor.donorSince =
            data.donorSince || null;


    if (
        data.lastContactDate !==
        undefined
    )
        donor.lastContactDate =
            data.lastContactDate || null;


    if (
        data.nextFollowUpDate !==
        undefined
    )
        donor.nextFollowUpDate =
            data.nextFollowUpDate || null;


    if (data.status !== undefined)
        donor.status =
            data.status;


    if (data.notes !== undefined)
        donor.notes =
            data.notes || null;


    // ==========================================
    // AUDIT
    // ==========================================

    donor.updatedBy =
        userId;


    // ==========================================
    // SAVE
    // ==========================================

    await donor.save();


    return donor;

};



// ==========================================
// DELETE DONOR
// ==========================================

const deleteDonor = async (

    id,

    organizationId,

    userId

) => {

    const donor =
        await Donor.findOne({

            _id: id,

            organization:
                organizationId,

            isDeleted:
                false

        });


    if (!donor) {

        throw new Error(
            "Donor not found"
        );

    }


    donor.isDeleted =
        true;

    donor.deletedAt =
        new Date();

    donor.deletedBy =
        userId;


    await donor.save();


    return donor;

};



// ==========================================
// EXPORTS
// ==========================================

module.exports = {

    createDonor,

    getDonors,

    getDonorLookup,

    getDonorById,

    updateDonor,

    deleteDonor

};