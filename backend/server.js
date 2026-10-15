require("dotenv").config();

const express = require("express");
const cors = require("cors");

const connectDB = require("./config/db");


// ================= Routes =================
const superAdminRoutes =
    require("./routes/superAdminRoutes");
const adminDashboardRoutes =
require("./routes/adminDashboardRoutes");

const adminOrganizationRoutes =
    require("./routes/adminOrganizationRoutes");

    const adminUserRoutes =
    require("./routes/AdminUserRoutes");

const organizationRoutes =
    require("./routes/organizationRoutes");

const beneficiaryRoutes =
    require("./routes/beneficiaryRoutes");

const authRoutes =
    require("./routes/authroutes");

const userRoutes =
    require("./routes/userRoutes");

const programRoutes =
    require("./routes/programRoutes");

 const projectRoutes = require("./routes/projectRoutes");

const enrollmentRoutes =
    require("./routes/enrollmentRoutes");

const donorRoutes =
    require("./routes/donorRoutes");

const donationRoutes =
    require("./routes/donationRoutes");

const servicedeliveryRoutes =
    require("./routes/serviceDeliveryRoutes");

const dashboardRoutes =
    require("./routes/dashboardRoutes");

const reportRoutes =
    require("./routes/reportRoutes");
const planRoutes =
    require("./routes/planRoutes");
    const subscriptionRoutes =
    require("./routes/subscriptionRoutes");

    const AdminAuditLogRoutes =
    require("./routes/adminAuditLogRoutes");  
    
    const OrganizationAuditLogRoutes =
    require("./routes/organizationAuditLogRoutes");

    const notificationRoutes =
    require("./routes/notificationRoutes"); 

 const superAdminAnalyticsRoutes =
require("./routes/superAdminAnalyticsRoutes");

const customfieldsRoutes =
require("./routes/customFieldRoutes");


const activityRoutes =
 require("./routes/activityRoutes");

 const attendanceRoutes = require("./routes/attendanceRoutes");

 const activityRunRoutes =
require("./routes/activityRunRoutes");

const enterpriseRoutes =
    require("./routes/enterpriseRoutes");

const enterpriseMemberRoutes =
    require("./routes/enterpriseMemberRoutes");

// ================= Middleware =================

const errorHandler =
    require("./middleware/errorHandler");



const app = express();



// ================= Global Middleware =================

app.use(cors());

app.use(express.json());



// ================= Database =================

connectDB();

// ================= Background Jobs =================
require("./jobs/scheduler");

// ================= API Routes =================
app.use(
    "/api/v1/super-admin",
    superAdminRoutes
);
    app.use(
"/api/v1/admin/dashboard",
adminDashboardRoutes
);

app.use(
    "/api/v1/organizations",
    organizationRoutes
);

app.use(
    "/api/v1/admin/users",
    adminUserRoutes
);

app.use(
    "/api/v1/admin/organizations",
    adminOrganizationRoutes
);


app.use(
    "/api/v1/auth",
    authRoutes
);
app.use(
"/api/v1/beneficiaries/import",
require("./routes/beneficiaryImportRoutes")
);

app.use(
    "/api/v1/beneficiaries",
    beneficiaryRoutes
);

app.use(
    "/api/v1/enterprises",
    enterpriseRoutes
);

app.use(
    "/api/v1/enterprise-members",
    enterpriseMemberRoutes
);

app.use(
    "/api/v1/users",
    userRoutes
);

app.use(
    "/api/v1/programs",
    programRoutes
);

app.use(
    "/api/v1/projects",
    projectRoutes
);
app.use(
    "/api/v1/enrollments",
    enrollmentRoutes
);


app.use(
    "/api/v1/donors",
    donorRoutes
);


app.use(
    "/api/v1/donations",
    donationRoutes
);


app.use(
    "/api/v1/service-deliveries",
    servicedeliveryRoutes
);


app.use(
    "/api/v1/dashboard",
    dashboardRoutes
);


app.use(
    "/api/v1/reports",
    reportRoutes
);

app.use(
    "/api/v1/subscriptions",
    subscriptionRoutes
);

app.use(
    "/api/v1/plans",
    planRoutes
);

app.use(
    "/api/v1/admin/audit-logs",
    AdminAuditLogRoutes
);

app.use(
    "/api/v1/organization/audit-logs",
    OrganizationAuditLogRoutes
);

app.use(
    "/api/v1/notifications",
    notificationRoutes
);      

app.use(

"/api/v1/super-admin/analytics",

superAdminAnalyticsRoutes

);

app.use(
    "/api/v1/custom-fields",
    require("./routes/customFieldRoutes")
);


app.use(

    "/api/v1/activities",

    activityRoutes
    
);
app.use(

    "/api/v1/activity-runs",

    activityRunRoutes

);


app.use(

    "/api/v1/attendance",

    attendanceRoutes

);

app.use(

    "/api/v1/lookups",

    require("./routes/lookupRoutes")

);

// ================= Test Route =================

app.get("/", (req,res)=>{

    res.json({

        message:
        "NGO SaaS API is running 🚀"

    });

});



// ================= Error Middleware =================

app.use(errorHandler);



// ================= Start Server =================

const PORT =
    process.env.PORT || 5000;



app.listen(
    PORT,
    ()=>{

        console.log(
            `🚀 Server running on port ${PORT}`
        );

    }
);