require("dotenv").config();

const fs = require("fs");
const path = require("path");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");

const connectDB = require("./config/db");


// ================= Environment checks =================

const isProduction = process.env.NODE_ENV === "production";

if (!process.env.JWT_SECRET || !process.env.MONGO_URI) {

    console.error(
        "Missing required environment variables: " +
        "JWT_SECRET and MONGO_URI must be set in .env"
    );

    process.exit(1);

}

if (isProduction && process.env.JWT_SECRET.length < 32) {

    console.warn(
        "WARNING: JWT_SECRET is shorter than 32 characters. " +
        "Use a long random value in production."
    );

}


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

const projectRoutes =
    require("./routes/projectRoutes");

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

const attendanceRoutes =
    require("./routes/attendanceRoutes");

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


// ================= Reverse proxy =================
// In production the app runs behind Nginx. Trusting one proxy hop makes
// req.ip the real visitor address, which the rate limiters depend on.
// (Set NODE_ENV=production on the server.)

if (isProduction) {

    app.set("trust proxy", 1);

}


// ================= Security headers =================

app.use(
    helmet({
        crossOriginResourcePolicy: {
            policy: "cross-origin"
        }
    })
);


// ================= CORS =================
// Production: set CORS_ORIGINS in .env to a comma-separated list, e.g.
//   CORS_ORIGINS=https://app.example.org,https://www.example.org
// Development: localhost frontends are allowed automatically.
// Requests without an Origin header (curl, server-to-server) are allowed.

const allowedOrigins = (process.env.CORS_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim().replace(/\/$/, ""))
    .filter(Boolean);

if (!isProduction) {

    allowedOrigins.push(
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000"
    );

}

app.use(
    cors({
        origin(origin, callback) {

            if (!origin) {
                return callback(null, true);
            }

            return callback(null, allowedOrigins.includes(origin));

        }
    })
);

app.use(express.json());


// ================= Rate limiting =================
// In-memory counters (reset when the server restarts). Limits are per IP,
// and offices often share one IP, so the general limit is generous.

const apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 2000,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many requests. Please try again later."
    }
});

// Login and other auth calls: only failed attempts count toward the limit.
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 20,
    skipSuccessfulRequests: true,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many attempts. Please try again in 15 minutes."
    }
});

// Public organization sign-up.
const signupLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: "Too many sign-up attempts. Please try again later."
    }
});

app.use("/api", apiLimiter);

app.use("/api/v1/auth", authLimiter);

app.post("/api/v1/organizations", signupLimiter);


// ================= Database =================

connectDB().then(async () => {

    // A fresh database gets the default plans (sign-up needs
    // the Free plan). Existing plans are never changed.

    try {
        await require("./services/planBootstrap").ensureDefaultPlans();
    }
    catch (error) {
        console.error("Default plan check failed:", error.message);
    }

});


// ================= Background Jobs =================

require("./jobs/scheduler");


// ================= API Routes =================

app.use("/api/v1/super-admin", superAdminRoutes);

app.use("/api/v1/admin/dashboard", adminDashboardRoutes);

app.use("/api/v1/organizations", organizationRoutes);

app.use("/api/v1/admin/users", adminUserRoutes);

app.use("/api/v1/admin/organizations", adminOrganizationRoutes);

app.use("/api/v1/auth", authRoutes);

app.use(
    "/api/v1/beneficiaries/import",
    require("./routes/beneficiaryImportRoutes")
);

app.use("/api/v1/beneficiaries", beneficiaryRoutes);

app.use("/api/v1/enterprises", enterpriseRoutes);

app.use("/api/v1/enterprise-members", enterpriseMemberRoutes);

app.use("/api/v1/users", userRoutes);

app.use("/api/v1/programs", programRoutes);

app.use("/api/v1/projects", projectRoutes);

app.use("/api/v1/enrollments", enrollmentRoutes);

app.use("/api/v1/donors", donorRoutes);

app.use("/api/v1/donations", donationRoutes);

app.use("/api/v1/service-deliveries", servicedeliveryRoutes);

app.use("/api/v1/dashboard", dashboardRoutes);

app.use("/api/v1/report-center", require("./routes/reportCenterRoutes"));

app.use("/api/v1/subscriptions", subscriptionRoutes);

app.use("/api/v1/plans", planRoutes);

app.use("/api/v1/admin/audit-logs", AdminAuditLogRoutes);

app.use("/api/v1/organization/audit-logs", OrganizationAuditLogRoutes);

app.use("/api/v1/notifications", notificationRoutes);

app.use("/api/v1/super-admin/analytics", superAdminAnalyticsRoutes);

app.use("/api/v1/custom-fields", customfieldsRoutes);

app.use("/api/v1/activities", activityRoutes);

app.use("/api/v1/activity-runs", activityRunRoutes);

app.use("/api/v1/attendance", attendanceRoutes);

app.use(
    "/api/v1/lookups",
    require("./routes/lookupRoutes")
);

app.use(
    "/api/v1/locations",
    require("./routes/locationRoutes")
);

app.use(
    "/api/v1/tors",
    require("./routes/torRoutes")
);

app.use(
    "/api/v1/budgets",
    require("./routes/budgetRoutes")
);

app.use(
    "/api/v1/expenses",
    require("./routes/expenseRoutes")
);

app.use(
    "/api/v1/donation-trace",
    require("./routes/donationTraceRoutes")
);

app.use(
    "/api/v1/donor-share-links",
    require("./routes/donorShareRoutes").staffRouter
);

// Public (no login): donor share links

app.use(
    "/api/v1/public/donor-share",
    require("./routes/donorShareRoutes").publicRouter
);


// ================= Test / Health Routes =================

app.get("/health", (req, res) => {

    res.json({
        status: "ok"
    });

});


// Unknown API paths: JSON 404 (never the frontend page)

app.use("/api", (req, res) => {

    res.status(404).json({
        success: false,
        message: "API route not found"
    });

});


// ================= Frontend (single-service deploy) =================
// When the frontend has been built (frontend/dist), the API also serves
// it, so one Render Web Service hosts the whole system on one URL.
// Any non-API GET returns index.html so client-side routes such as
// /share/donor/:token work on refresh or when opened from a link.

const frontendDist =
    path.join(__dirname, "..", "frontend", "dist");

const frontendIndex =
    path.join(frontendDist, "index.html");

if (fs.existsSync(frontendIndex)) {

    app.use(
        express.static(frontendDist, {
            index: false,
            maxAge: "1h"
        })
    );

    app.get(/^(?!\/api\/).*/, (req, res) => {

        res.setHeader("Cache-Control", "no-cache");

        res.sendFile(frontendIndex);

    });

}
else {

    app.get("/", (req, res) => {

        res.json({
            message: "NGO SaaS API is running"
        });

    });

}


// ================= Error Middleware =================

app.use(errorHandler);


// ================= Start Server =================

const PORT =
    process.env.PORT || 5000;

app.listen(
    PORT,
    () => {

        console.log(
            `Server running on port ${PORT}`
        );

    }
);
