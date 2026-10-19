const AdminArea =
    require("../models/AdminArea");


// =====================================================
// GET LOCATIONS
// =====================================================
//
// GET /locations?level=1
// GET /locations?level=2&parent=ET03
// GET /locations?level=3&parent=ET0301
//
// Returns active admin areas sorted by name.
//
// =====================================================

const getLocationsController =
    async (req, res, next) => {

        try {

            const level =
                Number(req.query.level || 1);

            if (![1, 2, 3].includes(level)) {

                return res.status(400).json({
                    success: false,
                    message:
                        "level must be 1, 2 or 3."
                });

            }


            const filter = {
                level,
                active: true
            };


            if (level > 1) {

                const parent =
                    String(req.query.parent || "")
                        .trim()
                        .toUpperCase();

                if (!parent) {

                    return res.status(400).json({
                        success: false,
                        message:
                            "parent is required for level 2 and 3."
                    });

                }

                filter.parentPcode =
                    parent;

            }


            const locations =
                await AdminArea

                    .find(filter)

                    .select(
                        "pcode name level parentPcode childLabel -_id"
                    )

                    .sort({
                        name: 1
                    })

                    .lean();


            res.set(
                "Cache-Control",
                "private, max-age=3600"
            );

            res.json({
                success: true,
                data: locations
            });

        } catch (error) {

            next(error);

        }

    };


module.exports = {
    getLocationsController
};
