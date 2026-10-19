import {
    Routes,
    Route,
    Navigate
} from "react-router-dom";


// ==========================================================
// LAYOUT / ROUTE GUARDS
// ==========================================================

import DashboardLayout
    from "../layouts/components/DashboardLayout";

import ProtectedRoute
    from "./ProtectedRoute";

import PermissionRoute
    from "./PermissionRoute";

import SuperAdminRoute
    from "./SuperAdminRoute";


// ==========================================================
// AUTH
// ==========================================================

import {
    LoginPage
} from "../features/auth";


// ==========================================================
// NORMAL DASHBOARD
// ==========================================================

import DashboardPage
    from "../features/dashboard/pages/DashboardPage";


// ==========================================================
// SUPER ADMIN
// ==========================================================

import {
    SuperAdminDashboardPage,
    OrganizationListPage,
    OrganizationCreatePage,
    OrganizationDetailsPage,
    OrganizationEditPage,
    PlanListPage,
    SubscriptionManagementPage
} from "../features/superadmin";


// ==========================================================
// ORGANIZATION SETTINGS
// ==========================================================

import OrganizationSettingsPage
    from "../features/organizations/pages/OrganizationSettingsPage";


// ==========================================================
// CUSTOM FIELDS
// ==========================================================

import CustomFieldListPage
    from "../features/customfields/pages/CustomFieldListPage";

import CustomFieldCreatePage
    from "../features/customfields/pages/CustomFieldCreatePage";

import CustomFieldEditPage
    from "../features/customfields/pages/CustomFieldEditPage";


// ==========================================================
// PROGRAMS
// ==========================================================

import {
    ProgramListPage,
    ProgramCreatePage,
    ProgramDetailsPage,
    ProgramEditPage
} from "../features/programs";


// ==========================================================
// BENEFICIARIES
// ==========================================================

import {
    BeneficiaryListPage,
    BeneficiaryCreatePage,
    BeneficiaryDetailsPage,
    BeneficiaryEditPage
} from "../features/beneficiaries";

import BeneficiaryImportPage
    from "../features/beneficiaries/pages/BeneficiaryImportPage";


// ==========================================================
// ENTERPRISES
// ==========================================================

import EnterpriseListPage
    from "../features/enterprise/pages/EnterpriseListPage";

import EnterpriseCreatePage
    from "../features/enterprise/pages/EnterpriseCreatePage";

import EnterpriseDetailsPage
    from "../features/enterprise/pages/EnterpriseDetailsPage";

import EnterpriseEditPage
    from "../features/enterprise/pages/EnterpriseEditPage";

import EnterpriseMemberListPage
    from "../features/enterprise/pages/EnterpriseMemberListPage";

import EnterpriseMemberCreatePage
    from "../features/enterprise/pages/EnterpriseMemberCreatePage";

import EnterpriseMemberDetailsPage
    from "../features/enterprise/pages/EnterpriseMemberDetailsPage";

import EnterpriseMemberEditPage
    from "../features/enterprise/pages/EnterpriseMemberEditPage";

// ==========================================================
// PROJECTS
// ==========================================================

import {
    ProjectListPage,
    ProjectCreatePage,
    ProjectDetailsPage,
    ProjectEditPage
} from "../features/projects";


// ==========================================================
// ACTIVITIES
// ==========================================================

import ActivityListPage
    from "../features/activities/pages/ActivityListPage";

import ActivityCreatePage
    from "../features/activities/pages/ActivityCreatePage";

import ActivityDetailsPage
    from "../features/activities/pages/ActivityDetailsPage";

import ActivityEditPage
    from "../features/activities/pages/ActivityEditPage";


// ==========================================================
// ACTIVITY RUNS
// ==========================================================

import {
    ActivityRunListPage,
    ActivityRunCreatePage,
    ActivityRunDetailsPage,
    ActivityRunEditPage
} from "../features/activityRuns";


// ==========================================================
// TERMS OF REFERENCE
// ==========================================================

import {
    TorListPage,
    TorCreatePage,
    TorDetailsPage,
    TorEditPage
} from "../features/tor";


// ==========================================================
// ATTENDANCE
// ==========================================================

import AttendanceListPage
    from "../features/attendance/pages/AttendanceListPage";

import AttendanceCreatePage
    from "../features/attendance/pages/AttendanceCreatePage";

import AttendanceEditPage
    from "../features/attendance/pages/AttendanceEditPage";

import AttendanceSheetPage
    from "../features/attendance/pages/AttendanceSheetPage";


// ==========================================================
// ENROLLMENTS
// ==========================================================

import {
    EnrollmentListPage,
    EnrollmentCreatePage,
    EnrollmentDetailsPage,
    EnrollmentEditPage
} from "../features/enrollments";


// ==========================================================
// SERVICE DELIVERY
// ==========================================================

import {
    ServiceDeliveryListPage,
    ServiceDeliveryCreatePage,
    ServiceDeliveryDetailsPage,
    ServiceDeliveryEditPage
} from "../features/ServiceDelivery";


// ==========================================================
// LOOKUPS
// ==========================================================

import LookupListPage
    from "../features/lookups/pages/LookupListPage";

import LookupCreatePage
    from "../features/lookups/pages/LookupCreatePage";

import LookupCategoryPage
    from "../features/lookups/pages/LookupCategoryPage";

import LookupEditPage
    from "../features/lookups/pages/LookupEditPage";


// ==========================================================
// USERS
// ==========================================================

import {
    UserListPage,
    UserCreatePage,
    UserEditPage
} from "../features/users";


// ==========================================================
// DONORS
// ==========================================================

import DonorListPage
    from "../features/donors/pages/DonorListPage";

import DonorCreatePage
    from "../features/donors/pages/DonorCreatePage";

import DonorDetailsPage
    from "../features/donors/pages/DonorDetailsPage";

import DonorEditPage
    from "../features/donors/pages/DonorEditPage";


// ==========================================================
// DONATIONS
// ==========================================================

import DonationListPage
    from "../features/donations/pages/DonationListPage";

import DonationCreatePage
    from "../features/donations/pages/DonationCreatePage";

import DonationDetailsPage
    from "../features/donations/pages/DonationDetailsPage";

import DonationEditPage
    from "../features/donations/pages/DonationEditPage";

import DonationTracePage
    from "../features/donations/pages/DonationTracePage";

import UntracedSpendingPage
    from "../features/donations/pages/UntracedSpendingPage";

import DonorSharePage
    from "../features/donations/pages/DonorSharePage";



    // ==========================================================
// REPORTS
// ==========================================================

import ReportsPage
    from "../features/reports/pages/ReportsPage";

// ==========================================================
// APP ROUTES
// ==========================================================

const AppRoutes = () => {

    return (

        <Routes>

            {/* ==================================================
                PUBLIC
            ================================================== */}

            <Route
                path="/login"
                element={
                    <LoginPage />
                }
            />

            {/* Donor share link: no login, read-only */}

            <Route
                path="/share/donor/:token"
                element={
                    <DonorSharePage />
                }
            />


            {/* ==================================================
                PROTECTED APPLICATION
            ================================================== */}

            <Route
                element={
                    <ProtectedRoute>
                        <DashboardLayout />
                    </ProtectedRoute>
                }
            >

                {/* ==================================================
                    DEFAULT
                ================================================== */}

                <Route
                    index
                    element={
                        <Navigate
                            to="/dashboard"
                            replace
                        />
                    }
                />


                {/* ==================================================
                    DASHBOARD
                ================================================== */}

                <Route
                    path="/dashboard"
                    element={
                        <DashboardPage />
                    }
                />


                {/* ==================================================
                    SUPER ADMIN
                ================================================== */}

                <Route
                    path="/superadmin"
                    element={
                        <SuperAdminRoute>
                            <SuperAdminDashboardPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations"
                    element={
                        <SuperAdminRoute>
                            <OrganizationListPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations/create"
                    element={
                        <SuperAdminRoute>
                            <OrganizationCreatePage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations/:id"
                    element={
                        <SuperAdminRoute>
                            <OrganizationDetailsPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/organizations/:id/edit"
                    element={
                        <SuperAdminRoute>
                            <OrganizationEditPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/plans"
                    element={
                        <SuperAdminRoute>
                            <PlanListPage />
                        </SuperAdminRoute>
                    }
                />

                <Route
                    path="/superadmin/subscriptions"
                    element={
                        <SuperAdminRoute>
                            <SubscriptionManagementPage />
                        </SuperAdminRoute>
                    }
                />


                {/* ==================================================
                    ORGANIZATION SETTINGS
                ================================================== */}

                <Route
                    path="/settings/organization"
                    element={
                        <OrganizationSettingsPage />
                    }
                />


                {/* ==================================================
                    USERS
                ================================================== */}

                <Route
                    path="/users"
                    element={
                        <PermissionRoute
                            permission="user.read"
                        >
                            <UserListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/users/create"
                    element={
                        <PermissionRoute
                            permission="user.create"
                        >
                            <UserCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/users/:id/edit"
                    element={
                        <PermissionRoute
                            permission="user.update"
                        >
                            <UserEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    PROGRAMS
                ================================================== */}

                <Route
                    path="/programs"
                    element={
                        <ProgramListPage />
                    }
                />

                <Route
                    path="/programs/create"
                    element={
                        <ProgramCreatePage />
                    }
                />

                <Route
                    path="/programs/:id"
                    element={
                        <ProgramDetailsPage />
                    }
                />

                <Route
                    path="/programs/:id/edit"
                    element={
                        <ProgramEditPage />
                    }
                />


                {/* ==================================================
                    BENEFICIARIES
                ================================================== */}

                <Route
                    path="/beneficiaries"
                    element={
                        <BeneficiaryListPage />
                    }
                />

                <Route
                    path="/beneficiaries/create"
                    element={
                        <BeneficiaryCreatePage />
                    }
                />

                <Route
                    path="/beneficiaries/:id"
                    element={
                        <BeneficiaryDetailsPage />
                    }
                />

                <Route
                    path="/beneficiaries/:id/edit"
                    element={
                        <BeneficiaryEditPage />
                    }
                />

                <Route
                    path="/beneficiaries/import"
                    element={
                        <BeneficiaryImportPage />
                    }
                />


{/* ==================================================
    ENTERPRISES
================================================== */}

<Route
    path="/enterprises"
    element={
        <EnterpriseListPage />
    }
/>


<Route
    path="/enterprises/create"
    element={
        <EnterpriseCreatePage />
    }
/>


<Route
    path="/enterprises/:id"
    element={
        <EnterpriseDetailsPage />
    }
/>


<Route
    path="/enterprises/:id/edit"
    element={
        <EnterpriseEditPage />
    }
/>


{/* ==================================================
    ENTERPRISE MEMBERS
================================================== */}

<Route
    path="/enterprise-members"
    element={
        <EnterpriseMemberListPage />
    }
/>


<Route
    path="/enterprise-members/:id"
    element={
        <EnterpriseMemberDetailsPage />
    }
/>


<Route
    path="/enterprise-members/:id/edit"
    element={
        <EnterpriseMemberEditPage />
    }
/>


{/* ==================================================
    ENTERPRISE MEMBERS BY ENTERPRISE
================================================== */}

<Route
    path="/enterprises/:enterpriseId/members"
    element={
        <EnterpriseMemberListPage />
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/create"
    element={
        <EnterpriseMemberCreatePage />
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/:memberId"
    element={
        <EnterpriseMemberDetailsPage />
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/:memberId/edit"
    element={
        <EnterpriseMemberEditPage />
    }
/>

                {/* ==================================================
                    ENROLLMENTS
                ================================================== */}

                <Route
                    path="/enrollments"
                    element={
                        <EnrollmentListPage />
                    }
                />

                <Route
                    path="/enrollments/create"
                    element={
                        <EnrollmentCreatePage />
                    }
                />

                <Route
                    path="/enrollments/:id"
                    element={
                        <EnrollmentDetailsPage />
                    }
                />

                <Route
                    path="/enrollments/:id/edit"
                    element={
                        <EnrollmentEditPage />
                    }
                />


                {/* ==================================================
                    PROJECTS
                ================================================== */}

                <Route
                    path="/projects"
                    element={
                        <ProjectListPage />
                    }
                />

                <Route
                    path="/projects/create"
                    element={
                        <ProjectCreatePage />
                    }
                />

                <Route
                    path="/projects/:id"
                    element={
                        <ProjectDetailsPage />
                    }
                />

                <Route
                    path="/projects/:id/edit"
                    element={
                        <ProjectEditPage />
                    }
                />


                {/* ==================================================
                    ACTIVITIES
                ================================================== */}

                <Route
                    path="/activities"
                    element={
                        <ActivityListPage />
                    }
                />

                <Route
                    path="/activities/create"
                    element={
                        <ActivityCreatePage />
                    }
                />

                <Route
                    path="/activities/:id"
                    element={
                        <ActivityDetailsPage />
                    }
                />

                <Route
                    path="/activities/:id/edit"
                    element={
                        <ActivityEditPage />
                    }
                />


                {/* ==================================================
                    ACTIVITY RUNS
                ================================================== */}

                <Route
                    path="/activity-runs"
                    element={
                        <ActivityRunListPage />
                    }
                />

                <Route
                    path="/activity-runs/create"
                    element={
                        <ActivityRunCreatePage />
                    }
                />

                <Route
                    path="/activity-runs/:id"
                    element={
                        <ActivityRunDetailsPage />
                    }
                />

                <Route
                    path="/activity-runs/:id/edit"
                    element={
                        <ActivityRunEditPage />
                    }
                />


                {/* ==================================================
                    TERMS OF REFERENCE
                ================================================== */}

                <Route
                    path="/tors"
                    element={
                        <PermissionRoute
                            permission="tor.read"
                        >
                            <TorListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/tors/create"
                    element={
                        <PermissionRoute
                            permission="tor.create"
                        >
                            <TorCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/tors/:id"
                    element={
                        <PermissionRoute
                            permission="tor.read"
                        >
                            <TorDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/tors/:id/edit"
                    element={
                        <PermissionRoute
                            permission="tor.update"
                        >
                            <TorEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    ATTENDANCE
                ================================================== */}

                <Route
                    path="/attendance"
                    element={
                        <AttendanceListPage />
                    }
                />

                <Route
                    path="/attendance/create"
                    element={
                        <AttendanceCreatePage />
                    }
                />

                <Route
                    path="/attendance/:id/edit"
                    element={
                        <AttendanceEditPage />
                    }
                />

                <Route
                    path="/attendance/:id/sheet"
                    element={
                        <AttendanceSheetPage />
                    }
                />


                {/* ==================================================
                    SERVICE DELIVERY
                ================================================== */}

                <Route
                    path="/service-deliveries"
                    element={
                        <ServiceDeliveryListPage />
                    }
                />

                <Route
                    path="/service-deliveries/create"
                    element={
                        <ServiceDeliveryCreatePage />
                    }
                />

                <Route
                    path="/service-deliveries/:id"
                    element={
                        <ServiceDeliveryDetailsPage />
                    }
                />

                <Route
                    path="/service-deliveries/:id/edit"
                    element={
                        <ServiceDeliveryEditPage />
                    }
                />


                {/* ==================================================
                    CUSTOM FIELDS
                ================================================== */}

                <Route
                    path="/settings/custom-fields"
                    element={
                        <PermissionRoute
                            permission="customfield.read"
                        >
                            <CustomFieldListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/settings/custom-fields/create"
                    element={
                        <PermissionRoute
                            permission="customfield.create"
                        >
                            <CustomFieldCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/settings/custom-fields/:id/edit"
                    element={
                        <PermissionRoute
                            permission="customfield.update"
                        >
                            <CustomFieldEditPage />
                        </PermissionRoute>
                    }
                />


{/* ==================================================
    LOOKUPS
================================================== */}

<Route
    path="/lookups"
    element={
        <LookupListPage />
    }
/>

<Route
    path="/lookups/create"
    element={
        <LookupCreatePage />
    }
/>

<Route
    path="/lookups/module/:module/category/:category"
    element={
        <LookupCategoryPage />
    }
/>

<Route
    path="/lookups/:id/edit"
    element={
        <LookupEditPage />
    }
/>


                {/* ==================================================
                    DONORS
                ================================================== */}

                <Route
                    path="/donors"
                    element={
                        <DonorListPage />
                    }
                />

                <Route
                    path="/donors/create"
                    element={
                        <DonorCreatePage />
                    }
                />

                <Route
                    path="/donors/:id"
                    element={
                        <DonorDetailsPage />
                    }
                />

                <Route
                    path="/donors/:id/edit"
                    element={
                        <DonorEditPage />
                    }
                />


                {/* ==================================================
                    DONATIONS
                ================================================== */}

                <Route
                    path="/donations"
                    element={
                        <DonationListPage />
                    }
                />

                <Route
                    path="/donations/create"
                    element={
                        <DonationCreatePage />
                    }
                />

                <Route
                    path="/donations/untraced"
                    element={
                        <UntracedSpendingPage />
                    }
                />

                <Route
                    path="/donations/:id"
                    element={
                        <DonationDetailsPage />
                    }
                />

                <Route
                    path="/donations/:id/trace"
                    element={
                        <DonationTracePage />
                    }
                />

                                <Route
                    path="/donations/:id/edit"
                    element={
                        <DonationEditPage />
                    }
                />


                {/* ==================================================
                    REPORTS
                ================================================== */}

                <Route
                    path="/reports"
                    element={
                        <ReportsPage />
                    }
                />

            </Route>

            {/* ==================================================
                FALLBACK
            ================================================== */}

            <Route
                path="*"
                element={
                    <Navigate
                        to="/dashboard"
                        replace
                    />
                }
            />

        </Routes>

    );

};


export default AppRoutes;