const multer = require("multer");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const ExcelJS = require("exceljs");

const Lookup =
    require("../models/Lookup");

const {
    importBeneficiaries
} = require("../services/beneficiaryImportService");


// =====================================================
// CONSTANTS
// =====================================================

const IMPORT_DIRECTORY =
    path.resolve(
        process.cwd(),
        "uploads",
        "imports"
    );

const MAX_FILE_SIZE =
    10 * 1024 * 1024;

const LOOKUP_MODULE =
    "Beneficiary";

const LOOKUP_CATEGORIES = {

    gender:
        "Gender",

    educationLevel:
        "EducationLevel",

    occupation:
        "Occupation",

    maritalStatus:
        "MaritalStatus",

    disabilityType:
        "DisabilityType",

    vulnerableGroups:
        "VulnerableGroup"

};

const TEMPLATE_DATA_START_ROW =
    2;

const TEMPLATE_DATA_END_ROW =
    1001;


// =====================================================
// ENSURE IMPORT DIRECTORY
// =====================================================

if (
    !fs.existsSync(
        IMPORT_DIRECTORY
    )
) {

    fs.mkdirSync(
        IMPORT_DIRECTORY,
        {
            recursive: true
        }
    );

}


// =====================================================
// MULTER STORAGE
// =====================================================

const storage =
    multer.diskStorage({

        destination: (
            req,
            file,
            cb
        ) => {

            cb(
                null,
                IMPORT_DIRECTORY
            );

        },

        filename: (
            req,
            file,
            cb
        ) => {

            const extension =
                path
                    .extname(
                        file.originalname || ""
                    )
                    .toLowerCase();

            const uniqueName =
                `beneficiaries-${Date.now()}-${crypto.randomBytes(8).toString("hex")}${extension}`;

            cb(
                null,
                uniqueName
            );

        }

    });


// =====================================================
// FILE FILTER
// =====================================================

const fileFilter = (
    req,
    file,
    cb
) => {

    const extension =
        path
            .extname(
                file.originalname || ""
            )
            .toLowerCase();

    if (
        extension !== ".xlsx"
    ) {

        return cb(
            new Error(
                "Only .xlsx Excel files are allowed."
            )
        );

    }

    const allowedMimeTypes = [

        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",

        "application/octet-stream"

    ];

    if (
        file.mimetype &&
        !allowedMimeTypes.includes(
            file.mimetype
        )
    ) {

        return cb(
            new Error(
                "Invalid Excel file type."
            )
        );

    }

    cb(
        null,
        true
    );

};


// =====================================================
// UPLOAD
// =====================================================

const upload =
    multer({

        storage,

        fileFilter,

        limits: {

            fileSize:
                MAX_FILE_SIZE,

            files:
                1

        }

    }).single("file");


// =====================================================
// REMOVE UPLOADED FILE
// =====================================================

const removeUploadedFile =
    async (
        filePath
    ) => {

        if (!filePath) {

            return;

        }

        try {

            await fs.promises.unlink(
                filePath
            );

        }
        catch (error) {

            if (
                error.code !== "ENOENT"
            ) {

                console.error(
                    "Failed to remove uploaded import file:",
                    error
                );

            }

        }

    };


// =====================================================
// GET ORGANIZATION BENEFICIARY LOOKUPS
// =====================================================

const getBeneficiaryLookups =
    async (
        organizationId
    ) => {

        const lookups =
            await Lookup.find({

                organization:
                    organizationId,

                module:
                    LOOKUP_MODULE,

                category: {
                    $in:
                        Object.values(
                            LOOKUP_CATEGORIES
                        )
                },

                active:
                    true

            })
            .sort({

                category:
                    1,

                value:
                    1

            })
            .lean();

        const result = {

            gender: [],

            educationLevel: [],

            occupation: [],

            maritalStatus: [],

            disabilityType: [],

            vulnerableGroups: []

        };

        const categoryToField = {

            Gender:
                "gender",

            EducationLevel:
                "educationLevel",

            Occupation:
                "occupation",

            MaritalStatus:
                "maritalStatus",

            DisabilityType:
                "disabilityType",

            VulnerableGroup:
                "vulnerableGroups"

        };

        for (
            const lookup of lookups
        ) {

            const field =
                categoryToField[
                    lookup.category
                ];

            if (!field) {

                continue;

            }

            const value =
                String(
                    lookup.value || ""
                ).trim();

            if (
                value &&
                !result[field].includes(
                    value
                )
            ) {

                result[field].push(
                    value
                );

            }

        }

        return result;

    };


// =====================================================
// ADD LIST VALIDATION
// =====================================================

const addListValidation =
    (
        sheet,
        cell,
        formula,
        allowBlank = true
    ) => {

        sheet
            .getCell(cell)
            .dataValidation = {

                type:
                    "list",

                allowBlank,

                formulae: [
                    formula
                ],

                showErrorMessage:
                    true,

                errorStyle:
                    "stop",

                errorTitle:
                    "Invalid value",

                error:
                    "Please select a value from the dropdown list."

            };

    };


// =====================================================
// CREATE NAMED RANGE
// =====================================================

const createNamedRange = (
    workbook,
    name,
    sheetName,
    columnLetter,
    startRow,
    endRow
) => {

    const escapedSheetName =
        String(
            sheetName
        ).replace(
            /'/g,
            "''"
        );

    const formula =
        `'${escapedSheetName}'!$${columnLetter}$${startRow}:$${columnLetter}$${endRow}`;

    workbook.definedNames.add(
        formula,
        name
    );

};


// =====================================================
// IMPORT CONTROLLER
// =====================================================

const importBeneficiariesController =
    async (
        req,
        res
    ) => {

        let uploadedFilePath =
            null;

        upload(
            req,
            res,
            async (
                error
            ) => {

                try {

                    // =====================================
                    // MULTER ERROR
                    // =====================================

                    if (error) {

                        if (
                            error instanceof
                            multer.MulterError
                        ) {

                            if (
                                error.code ===
                                "LIMIT_FILE_SIZE"
                            ) {

                                return res
                                    .status(400)
                                    .json({

                                        success:
                                            false,

                                        message:
                                            "Excel file is too large. Maximum allowed size is 10 MB."

                                    });

                            }

                            if (
                                error.code ===
                                "LIMIT_UNEXPECTED_FILE"
                            ) {

                                return res
                                    .status(400)
                                    .json({

                                        success:
                                            false,

                                        message:
                                            "Only one Excel file can be uploaded using the 'file' field."

                                    });

                            }

                            if (
                                error.code ===
                                "LIMIT_FILE_COUNT"
                            ) {

                                return res
                                    .status(400)
                                    .json({

                                        success:
                                            false,

                                        message:
                                            "Only one Excel file can be uploaded."

                                    });

                            }

                        }

                        return res
                            .status(400)
                            .json({

                                success:
                                    false,

                                message:
                                    error.message ||
                                    "Invalid file upload."

                            });

                    }


                    // =====================================
                    // FILE REQUIRED
                    // =====================================

                    if (!req.file) {

                        return res
                            .status(400)
                            .json({

                                success:
                                    false,

                                message:
                                    "Excel file is required."

                            });

                    }

                    uploadedFilePath =
                        req.file.path;


                    // =====================================
                    // TENANT CONTEXT
                    // =====================================

                    if (
                        !req.organizationId
                    ) {

                        await removeUploadedFile(
                            uploadedFilePath
                        );

                        uploadedFilePath =
                            null;

                        return res
                            .status(401)
                            .json({

                                success:
                                    false,

                                message:
                                    "Authenticated organization is required."

                            });

                    }


                    // =====================================
                    // USER CONTEXT
                    // =====================================

                    if (
                        !req.user?.userId
                    ) {

                        await removeUploadedFile(
                            uploadedFilePath
                        );

                        uploadedFilePath =
                            null;

                        return res
                            .status(401)
                            .json({

                                success:
                                    false,

                                message:
                                    "Authenticated user is required."

                            });

                    }


                    // =====================================
                    // IMPORT
                    // =====================================

                    const result =
                        await importBeneficiaries(

                            uploadedFilePath,

                            req.organizationId,

                            req.user.userId

                        );


                    // =====================================
                    // FILE CLEANUP
                    // =====================================

                    uploadedFilePath =
                        null;


                    // =====================================
                    // IMPORT RESULT
                    // =====================================

                    const created =
                        Number(
                            result?.created || 0
                        );

                    const failed =
                        Number(
                            result?.failed || 0
                        );

                    const totalRows =
                        Number(
                            result?.totalRows || 0
                        );

                    const hasErrors =
                        failed > 0;

                    const allFailed =
                        totalRows > 0 &&
                        created === 0 &&
                        failed > 0;

                    const statusCode =
                        allFailed
                            ? 400
                            : 200;

                    return res
                        .status(
                            statusCode
                        )
                        .json({

                            success:
                                !hasErrors,

                            message:
                                hasErrors
                                    ? "Beneficiary import completed with errors."
                                    : "Beneficiary import completed successfully.",

                            data:
                                result

                        });

                }
                catch (error) {

                    console.error(
                        "Beneficiary import error:",
                        error
                    );

                    await removeUploadedFile(
                        uploadedFilePath
                    );

                    uploadedFilePath =
                        null;

                    return res
                        .status(
                            error.statusCode ||
                            500
                        )
                        .json({

                            success:
                                false,

                            message:
                                error.message ||
                                "Beneficiary import failed."

                        });

                }

            }
        );

    };


// =====================================================
// DOWNLOAD BENEFICIARY TEMPLATE
// =====================================================

// A Region > Zone > Woreda that exists in the official list
// (Oromia > Arsi > Amigna when present), for the sample row
const sampleLocationOf = async () => {
    try {
        const AdminArea = require("../models/AdminArea");
        const region =
            await AdminArea.findOne({ level: 1, name: "Oromia" }).lean() ||
            await AdminArea.findOne({ level: 1 }).lean();
        const zone = region
            ? await AdminArea.findOne({ level: 2, parentPcode: region.pcode }).sort({ name: 1 }).lean()
            : null;
        const woreda = zone
            ? await AdminArea.findOne({ level: 3, parentPcode: zone.pcode }).sort({ name: 1 }).lean()
            : null;
        return { region: region?.name || "", zone: zone?.name || "", woreda: woreda?.name || "" };
    }
    catch {
        return { region: "", zone: "", woreda: "" };
    }
};


const downloadBeneficiaryTemplateController =
    async (
        req,
        res,
        next
    ) => {

        try {

            // =============================================
            // TENANT CONTEXT
            // =============================================

            if (
                !req.organizationId
            ) {

                return res
                    .status(401)
                    .json({

                        success:
                            false,

                        message:
                            "Authenticated organization is required."

                    });

            }


            // =============================================
            // GET ORGANIZATION LOOKUPS
            // =============================================

            const lookupValues =
                await getBeneficiaryLookups(
                    req.organizationId
                );


            // =============================================
            // WORKBOOK
            // =============================================

            const workbook =
                new ExcelJS.Workbook();

            workbook.creator =
                "NGO Management SaaS Platform";

            workbook.lastModifiedBy =
                "NGO Management SaaS Platform";

            workbook.created =
                new Date();

            workbook.modified =
                new Date();


            // =============================================
            // BENEFICIARIES SHEET
            // =============================================

            const sheet =
                workbook.addWorksheet(
                    "Beneficiaries"
                );

            sheet.columns = [

                {
                    header:
                        "First Name",
                    key:
                        "firstName",
                    width:
                        20
                },

                {
                    header:
                        "Middle Name",
                    key:
                        "middleName",
                    width:
                        20
                },

                {
                    header:
                        "Last Name",
                    key:
                        "lastName",
                    width:
                        20
                },

                {
                    header:
                        "Gender",
                    key:
                        "gender",
                    width:
                        18
                },

                {
                    header:
                        "Date of Birth",
                    key:
                        "dateOfBirth",
                    width:
                        16
                },

                {
                    header:
                        "Age",
                    key:
                        "age",
                    width:
                        10
                },

                {
                    header:
                        "Phone",
                    key:
                        "phone",
                    width:
                        18
                },

                {
                    header:
                        "Alternative Phone",
                    key:
                        "alternativePhone",
                    width:
                        20
                },

                {
                    header:
                        "Email",
                    key:
                        "email",
                    width:
                        28
                },

                {
                    header:
                        "Country",
                    key:
                        "country",
                    width:
                        18
                },

                {
                    header:
                        "Region",
                    key:
                        "region",
                    width:
                        18
                },

                {
                    header:
                        "Zone",
                    key:
                        "zone",
                    width:
                        18
                },

                {
                    header:
                        "Woreda",
                    key:
                        "woreda",
                    width:
                        18
                },

                {
                    header:
                        "Kebele",
                    key:
                        "kebele",
                    width:
                        18
                },

                {
                    header:
                        "Address",
                    key:
                        "address",
                    width:
                        30
                },

                {
                    header:
                        "Education Level",
                    key:
                        "educationLevel",
                    width:
                        22
                },

                {
                    header:
                        "Occupation",
                    key:
                        "occupation",
                    width:
                        22
                },

                {
                    header:
                        "Marital Status",
                    key:
                        "maritalStatus",
                    width:
                        20
                },

                {
                    header:
                        "Is PWD",
                    key:
                        "isPWD",
                    width:
                        12
                },

                {
                    header:
                        "Disability Type",
                    key:
                        "disabilityType",
                    width:
                        22
                },

                {
                    header:
                        "Vulnerable Groups",
                    key:
                        "vulnerableGroups",
                    width:
                        35
                },

                {
                    header:
                        "Status",
                    key:
                        "status",
                    width:
                        15
                }

            ];


            // =============================================
            // HEADER STYLE
            // =============================================

            const headerRow =
                sheet.getRow(1);

            headerRow.font = {

                bold:
                    true

            };

            headerRow.alignment = {

                vertical:
                    "middle",

                horizontal:
                    "center"

            };

            headerRow.height =
                25;


            // =============================================
            // SAMPLE DATA
            // =============================================
            //
            // A real Region > Zone > Woreda from the official
            // list, so the sample row itself imports.

            const sampleLocation =
                await sampleLocationOf();

            const sampleRow =
                sheet.addRow({

                    firstName:
                        "Abebe",

                    middleName:
                        "Kebede",

                    lastName:
                        "Tesfaye",

                    gender:
                        lookupValues.gender[0] ||
                        "",

                    dateOfBirth:
                        new Date(
                            1998,
                            0,
                            2
                        ),

                    phone:
                        "0911000000",

                    alternativePhone:
                        "",

                    email:
                        "example@example.com",

                    country:
                        "Ethiopia",

                    region:
                        sampleLocation.region,

                    zone:
                        sampleLocation.zone,

                    woreda:
                        sampleLocation.woreda,

                    kebele:
                        "01",

                    address:
                        "Sample address",

                    educationLevel:
                        lookupValues.educationLevel[0] ||
                        "",

                    occupation:
                        lookupValues.occupation[0] ||
                        "",

                    maritalStatus:
                        lookupValues.maritalStatus[0] ||
                        "",

                    isPWD:
                        "No",

                    disabilityType:
                        "",

                    vulnerableGroups:
                        "",

                    status:
                        "Active"

                });


            // =============================================
            // AGE FORMULA
            // =============================================

            sampleRow.getCell(
                6
            ).value = {

                formula:
                    `IF(E${sampleRow.number}="","",IFERROR(DATEDIF(E${sampleRow.number},TODAY(),"Y"),""))`

            };


            // =============================================
            // LOOKUP VALUES SHEET
            // =============================================

            const lookupSheet =
                workbook.addWorksheet(
                    "Lookup Values"
                );

            lookupSheet.state =
                "hidden";

            const lookupHeaders = [

                "Gender",

                "EducationLevel",

                "Occupation",

                "MaritalStatus",

                "DisabilityType",

                "VulnerableGroup",

                "PWD",

                "Status"

            ];

            lookupHeaders.forEach(
                (
                    header,
                    index
                ) => {

                    lookupSheet.getCell(
                        1,
                        index + 1
                    ).value =
                        header;

                }
            );


            const writeLookupValues =
                (
                    column,
                    values
                ) => {

                    values.forEach(
                        (
                            value,
                            index
                        ) => {

                            lookupSheet.getCell(
                                index + 2,
                                column
                            ).value =
                                value;

                        }
                    );

                };


            const pwdValues = [
                "Yes",
                "No"
            ];

            const statusValues = [
                "Active",
                "Inactive"
            ];


            writeLookupValues(
                1,
                lookupValues.gender
            );

            writeLookupValues(
                2,
                lookupValues.educationLevel
            );

            writeLookupValues(
                3,
                lookupValues.occupation
            );

            writeLookupValues(
                4,
                lookupValues.maritalStatus
            );

            writeLookupValues(
                5,
                lookupValues.disabilityType
            );

            writeLookupValues(
                6,
                lookupValues.vulnerableGroups
            );

            writeLookupValues(
                7,
                pwdValues
            );

            writeLookupValues(
                8,
                statusValues
            );


            // =============================================
            // NAMED RANGES
            // =============================================

            const namedRanges = [

                {
                    name:
                        "BeneficiaryGender",

                    column:
                        "A",

                    values:
                        lookupValues.gender

                },

                {
                    name:
                        "BeneficiaryEducationLevel",

                    column:
                        "B",

                    values:
                        lookupValues.educationLevel

                },

                {
                    name:
                        "BeneficiaryOccupation",

                    column:
                        "C",

                    values:
                        lookupValues.occupation

                },

                {
                    name:
                        "BeneficiaryMaritalStatus",

                    column:
                        "D",

                    values:
                        lookupValues.maritalStatus

                },

                {
                    name:
                        "BeneficiaryDisabilityType",

                    column:
                        "E",

                    values:
                        lookupValues.disabilityType

                },

                {
                    name:
                        "BeneficiaryVulnerableGroup",

                    column:
                        "F",

                    values:
                        lookupValues.vulnerableGroups

                },

                {
                    name:
                        "BeneficiaryPWD",

                    column:
                        "G",

                    values:
                        pwdValues

                },

                {
                    name:
                        "BeneficiaryStatus",

                    column:
                        "H",

                    values:
                        statusValues

                }

            ];


            namedRanges.forEach(
                (
                    range
                ) => {

                    createNamedRange(

                        workbook,

                        range.name,

                        "Lookup Values",

                        range.column,

                        2,

                        Math.max(
                            2,
                            range.values.length + 1
                        )

                    );

                }
            );


            // =============================================
            // DROPDOWNS
            // =============================================

            for (
                let row =
                    TEMPLATE_DATA_START_ROW;

                row <=
                    TEMPLATE_DATA_END_ROW;

                row++
            ) {

                addListValidation(
                    sheet,
                    `D${row}`,
                    "=BeneficiaryGender"
                );

                addListValidation(
                    sheet,
                    `P${row}`,
                    "=BeneficiaryEducationLevel"
                );

                addListValidation(
                    sheet,
                    `Q${row}`,
                    "=BeneficiaryOccupation"
                );

                addListValidation(
                    sheet,
                    `R${row}`,
                    "=BeneficiaryMaritalStatus"
                );

                addListValidation(
                    sheet,
                    `S${row}`,
                    "=BeneficiaryPWD"
                );

                addListValidation(
                    sheet,
                    `T${row}`,
                    "=BeneficiaryDisabilityType"
                );
                  addListValidation(
                sheet,
               `U${row}`,
              "=BeneficiaryVulnerableGroup"
               );

                addListValidation(
                    sheet,
                    `V${row}`,
                    "=BeneficiaryStatus"
                );

            }


            // =============================================
            // AGE FORMULAS
            // =============================================

            for (
                let row =
                    TEMPLATE_DATA_START_ROW;

                row <=
                    TEMPLATE_DATA_END_ROW;

                row++
            ) {

                sheet.getCell(
                    `F${row}`
                ).value = {

                    formula:
                        `IF(E${row}="","",IFERROR(DATEDIF(E${row},TODAY(),"Y"),""))`

                };

            }


            // =============================================
            // FORMATTING
            // =============================================

            for (
                let row =
                    TEMPLATE_DATA_START_ROW;

                row <=
                    TEMPLATE_DATA_END_ROW;

                row++
            ) {

                sheet.getCell(
                    `E${row}`
                ).numFmt =
                    "yyyy-mm-dd";

                sheet.getCell(
                    `G${row}`
                ).numFmt =
                    "@";

                sheet.getCell(
                    `H${row}`
                ).numFmt =
                    "@";

                sheet.getCell(
                    `M${row}`
                ).numFmt =
                    "@";

                sheet.getCell(
                    `N${row}`
                ).numFmt =
                    "@";

            }


            // =============================================
            // FREEZE / FILTER
            // =============================================

            sheet.freezePanes =
                "A2";

            sheet.autoFilter = {

                from:
                    "A1",

                to:
                    "V1"

            };


            // =============================================
            // UNLOCK INPUT CELLS
            // =============================================

            for (
                let row =
                    TEMPLATE_DATA_START_ROW;

                row <=
                    TEMPLATE_DATA_END_ROW;

                row++
            ) {

                for (
                    let column = 1;

                    column <= 22;

                    column++
                ) {

                    // Age is calculated automatically
                    // and must remain locked.

                    if (
                        column === 6
                    ) {

                        continue;

                    }

                    sheet.getCell(
                        row,
                        column
                    ).protection = {

                        locked:
                            false

                    };

                }

            }


            // =============================================
            // PROTECT BENEFICIARY SHEET
            // =============================================

            await sheet.protect(
                "NGO_BENEFICIARY_TEMPLATE",
                {

                    selectLockedCells:
                        true,

                    selectUnlockedCells:
                        true,

                    formatCells:
                        false,

                    formatColumns:
                        false,

                    formatRows:
                        false,

                    insertColumns:
                        false,

                    insertRows:
                        true,

                    deleteColumns:
                        false,

                    deleteRows:
                        true,

                    sort:
                        true,

                    autoFilter:
                        true

                }
            );


            // =============================================
            // INSTRUCTIONS SHEET
            // =============================================

            const instructions =
                workbook.addWorksheet(
                    "Instructions"
                );

            instructions.getColumn(
                1
            ).width =
                100;

            instructions.getCell(
                "A1"
            ).value =
                "Beneficiary Bulk Import Instructions";

            instructions.getCell(
                "A1"
            ).font = {

                bold:
                    true,

                size:
                    16

            };


            const instructionRows = [

                "1. Enter one beneficiary per row on the Beneficiaries sheet.",

                "2. First Name, Last Name, Gender, and Date of Birth are required.",

                "3. Age is calculated automatically from Date of Birth. Do not enter or modify Age.",

                "4. Gender, Education Level, Occupation, Marital Status, Disability Type, PWD, and Status use dropdown lists.",

                "5. Vulnerable Groups may contain multiple values separated by commas or semicolons.",

                "6. Leave Disability Type empty when Is PWD is No.",

                "7. If Is PWD is Yes, select a valid Disability Type.",

                "8. Do not modify the Lookup Values sheet.",

                "9. Do not rename the Beneficiaries worksheet.",

                "10. Save the completed file as .xlsx before uploading.",

                "11. The system validates every row against your organization's configured Beneficiary lookups.",

                "12. Lookup values are organization-specific and must match the available dropdown values.",

                "13. The organization is determined automatically from your authenticated account.",

                "14. Beneficiary Number is generated automatically by the system.",

                "15. The system calculates and stores Age from Date of Birth; Excel Age is never trusted as source data."

            ];


            instructionRows.forEach(
                (
                    text,
                    index
                ) => {

                    instructions.getCell(
                        index + 3,
                        1
                    ).value =
                        text;

                }
            );


            // =============================================
            // PROTECT LOOKUP SHEET
            // =============================================

            await lookupSheet.protect(
                "NGO_BENEFICIARY_LOOKUPS",
                {

                    selectLockedCells:
                        true,

                    selectUnlockedCells:
                        false,

                    formatCells:
                        false,

                    formatColumns:
                        false,

                    formatRows:
                        false,

                    insertColumns:
                        false,

                    insertRows:
                        false,

                    deleteColumns:
                        false,

                    deleteRows:
                        false

                }
            );


            // =============================================
            // DOWNLOAD
            // =============================================

            res.setHeader(
                "Content-Type",
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
            );

            res.setHeader(
                "Content-Disposition",
                'attachment; filename="beneficiary-import-template.xlsx"'
            );

            await workbook.xlsx.write(
                res
            );

            res.end();

        }
        catch (error) {

            console.error(
                "Beneficiary template generation error:",
                error
            );

            if (
                typeof next ===
                "function"
            ) {

                return next(
                    error
                );

            }

            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        error.message ||
                        "Failed generating beneficiary import template."

                });

        }

    };


// =====================================================
// EXPORTS
// =====================================================

module.exports = {

    importBeneficiariesController,

    downloadBeneficiaryTemplate:
        downloadBeneficiaryTemplateController

};