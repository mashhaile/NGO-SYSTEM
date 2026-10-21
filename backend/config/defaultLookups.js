// =====================================================
// DEFAULT (COMMON) LOOKUP VALUES
// =====================================================
//
// Seeded into every new organization so its dropdowns are
// usable from day one. Organizations can then edit,
// deactivate or delete these values freely.
//
// A category is only seeded while it is EMPTY for that
// organization, so an organization's own changes are never
// overwritten or brought back (see defaultLookupService).
//
// Units (ServiceDelivery / Unit) are not here: they are
// created by serviceDeliveryUnitService, and Service Types
// below refer to them by value.
//
// =====================================================

const DEFAULT_LOOKUPS = {

    Beneficiary: {

        Gender: [
            "Male",
            "Female"
        ],

        EducationLevel: [
            "No Formal Education",
            "Primary Education",
            "Secondary Education",
            "Certificate",
            "Diploma",
            "Bachelor's Degree",
            "Master's Degree or Above",
            "Other"
        ],

        Occupation: [
            "Unemployed",
            "Student",
            "Farmer",
            "Trader",
            "Government Employee",
            "Private Employee",
            "Self-Employed",
            "Daily Laborer",
            "Household Work",
            "Retired",
            "Other"
        ],

        MaritalStatus: [
            "Single",
            "Married",
            "Divorced",
            "Widowed",
            "Separated",
            "Other"
        ],

        DisabilityType: [
            "Physical",
            "Visual",
            "Hearing",
            "Speech",
            "Intellectual",
            "Mental",
            "Multiple",
            "Other"
        ],

        VulnerableGroup: [
            "Person with Disability",
            "Orphan",
            "Child at Risk",
            "Elderly",
            "Female Headed Household",
            "Single Parent",
            "Refugee",
            "Internally Displaced Person",
            "Low Income Household",
            "Other"
        ]

    },


    Enterprise: {

        EnterpriseType: [
            "Micro Enterprise",
            "Small Enterprise",
            "Medium Enterprise",
            "Large Enterprise",
            "Cooperative",
            "Social Enterprise",
            "Community-Based Enterprise",
            "Family Business",
            "Nonprofit Enterprise",
            "Other"
        ],

        OwnershipType: [
            "Sole Proprietorship",
            "Partnership",
            "Private Limited Company",
            "Public Limited Company",
            "Cooperative Ownership",
            "Community Ownership",
            "Family Ownership",
            "Joint Ownership",
            "Government Owned",
            "Nonprofit Owned",
            "Other"
        ],

        BusinessSector: [
            "Agriculture",
            "Livestock",
            "Fisheries",
            "Food Processing",
            "Manufacturing",
            "Construction",
            "Retail",
            "Wholesale",
            "Trade",
            "Hospitality and Tourism",
            "Transport",
            "Information and Communication Technology",
            "Financial Services",
            "Health Services",
            "Education Services",
            "Professional Services",
            "Handicrafts and Artisans",
            "Textiles and Garments",
            "Beauty and Personal Care",
            "Energy",
            "Water and Sanitation",
            "Waste Management",
            "Other"
        ]

    },


    ServiceDelivery: {

        ServiceCategory: [
            "Health",
            "Education",
            "Water, Sanitation and Hygiene",
            "Food and Nutrition",
            "Livelihoods",
            "Protection",
            "Shelter and Housing",
            "Emergency Assistance",
            "Economic Empowerment",
            "Social Support",
            "Legal and Documentation",
            "Disability Support",
            "Youth Development",
            "Community Development",
            "Capacity Building"
        ]

    }

};


// Service Types: parent category + the units they can be
// delivered in (unit values from config/serviceDeliveryUnits).

const MONEY = ["Amount", "ETB", "Cash"];

const DEFAULT_SERVICE_TYPES = [

    { category: "Education", value: "School Fees", units: MONEY },
    { category: "Education", value: "School Uniform", units: ["Pair", "Piece"] },
    { category: "Education", value: "School Supplies", units: ["Box", "Pack", "Piece", "Set", "Unit"] },
    { category: "Education", value: "Education Materials", units: ["Box", "Pack", "Piece", "Set", "Unit"] },
    { category: "Education", value: "Tuition Support", units: MONEY },
    { category: "Education", value: "Teacher Support", units: ["Session", "Hour", "Piece", "Set"] },

    { category: "Health", value: "Medical Treatment", units: MONEY },
    { category: "Health", value: "Medical Supplies", units: ["Piece", "Set", "Box", "Pack"] },
    { category: "Health", value: "Health Screening", units: ["Session", "Day", "Hour"] },
    { category: "Health", value: "Health Awareness Session", units: ["Session", "Hour"] },

    { category: "Food and Nutrition", value: "Food Assistance", units: ["Kg", "Box", "Pack"] },
    { category: "Food and Nutrition", value: "Nutrition Support", units: ["Kg", "Liter", "Box", "Pack"] },

    { category: "Water, Sanitation and Hygiene", value: "Hygiene Kit", units: ["Set", "Unit", "Box"] },
    { category: "Water, Sanitation and Hygiene", value: "WASH Supplies", units: ["Box", "Pack", "Piece", "Kg", "Liter"] },

    { category: "Emergency Assistance", value: "Cash Assistance", units: MONEY },
    { category: "Shelter and Housing", value: "Shelter Materials", units: ["Box", "Pack", "Piece", "Kg"] },

    { category: "Livelihoods", value: "Livelihood Training", units: ["Session", "Hour", "Set"] },
    { category: "Capacity Building", value: "Vocational Training", units: ["Session", "Hour", "Set"] },
    { category: "Capacity Building", value: "Business Skills Training", units: ["Session", "Hour"] },
    { category: "Youth Development", value: "Youth Skills Training", units: ["Session", "Hour", "Set"] },

    { category: "Legal and Documentation", value: "Legal Assistance", units: ["Session", "Hour", "Amount", "ETB"] },
    { category: "Protection", value: "Child Protection Support", units: ["Session", "Hour", "Piece", "Set"] },
    { category: "Disability Support", value: "Disability Support Equipment", units: ["Piece", "Box", "Set", "Unit"] }

];


module.exports = {
    DEFAULT_LOOKUPS,
    DEFAULT_SERVICE_TYPES
};
