import {
    lazy,
    Suspense
} from "react";

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

import {
    LoadingState
} from "../components/ui";

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



// ==========================================================
// SUPER ADMIN
// ==========================================================



// ==========================================================
// ORGANIZATION SETTINGS
// ==========================================================



// ==========================================================
// CUSTOM FIELDS
// ==========================================================





// ==========================================================
// PROGRAMS
// ==========================================================



// ==========================================================
// BENEFICIARIES
// ==========================================================




// ==========================================================
// ENTERPRISES
// ==========================================================









// ==========================================================
// PROJECTS
// ==========================================================



// ==========================================================
// ACTIVITIES
// ==========================================================






// ==========================================================
// ACTIVITY RUNS
// ==========================================================



// ==========================================================
// TERMS OF REFERENCE
// ==========================================================



// ==========================================================
// ATTENDANCE
// ==========================================================






// ==========================================================
// ENROLLMENTS
// ==========================================================



// ==========================================================
// SERVICE DELIVERY
// ==========================================================



// ==========================================================
// LOOKUPS
// ==========================================================






// ==========================================================
// USERS
// ==========================================================



// ==========================================================
// DONORS
// ==========================================================






// ==========================================================
// DONATIONS
// ==========================================================










    // ==========================================================
// REPORTS
// ==========================================================


// ==========================================================
// APP ROUTES
// ==========================================================

// ==========================================================
// PAGES (loaded on demand)
// ==========================================================
//
// Each page is its own file, downloaded the first time it
// is opened. After a new deploy an open tab may ask for a
// file that no longer exists: reload once to get the new
// version instead of showing an error.
//
const lazyPage = (load) =>
    lazy(() =>
        load()
            .then(module => {
                sessionStorage.removeItem("page-reload");
                return module;
            })
            .catch(error => {
                if (!sessionStorage.getItem("page-reload")) {
                    sessionStorage.setItem("page-reload", "1");
                    window.location.reload();
                    return new Promise(() => {});
                }
                throw error;
            })
    );

const DashboardPage = lazyPage(() => import("../features/dashboard/pages/DashboardPage"));
const OrganizationSettingsPage = lazyPage(() => import("../features/organizations/pages/OrganizationSettingsPage"));
const CustomFieldListPage = lazyPage(() => import("../features/customfields/pages/CustomFieldListPage"));
const RolesPage = lazyPage(() => import("../features/roles/RolesPage"));
const CustomFieldCreatePage = lazyPage(() => import("../features/customfields/pages/CustomFieldCreatePage"));
const CustomFieldEditPage = lazyPage(() => import("../features/customfields/pages/CustomFieldEditPage"));
const BeneficiaryImportPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryImportPage"));
const EnterpriseListPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseListPage"));
const EnterpriseCreatePage = lazyPage(() => import("../features/enterprise/pages/EnterpriseCreatePage"));
const EnterpriseDetailsPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseDetailsPage"));
const EnterpriseEditPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseEditPage"));
const EnterpriseMemberListPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberListPage"));
const EnterpriseMemberCreatePage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberCreatePage"));
const EnterpriseMemberDetailsPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberDetailsPage"));
const EnterpriseMemberEditPage = lazyPage(() => import("../features/enterprise/pages/EnterpriseMemberEditPage"));
const ActivityListPage = lazyPage(() => import("../features/activities/pages/ActivityListPage"));
const ActivityCreatePage = lazyPage(() => import("../features/activities/pages/ActivityCreatePage"));
const ActivityDetailsPage = lazyPage(() => import("../features/activities/pages/ActivityDetailsPage"));
const ActivityEditPage = lazyPage(() => import("../features/activities/pages/ActivityEditPage"));
const AttendanceListPage = lazyPage(() => import("../features/attendance/pages/AttendanceListPage"));
const AttendanceCreatePage = lazyPage(() => import("../features/attendance/pages/AttendanceCreatePage"));
const AttendanceEditPage = lazyPage(() => import("../features/attendance/pages/AttendanceEditPage"));
const AttendanceSheetPage = lazyPage(() => import("../features/attendance/pages/AttendanceSheetPage"));
const LookupListPage = lazyPage(() => import("../features/lookups/pages/LookupListPage"));
const LookupCreatePage = lazyPage(() => import("../features/lookups/pages/LookupCreatePage"));
const LookupCategoryPage = lazyPage(() => import("../features/lookups/pages/LookupCategoryPage"));
const LookupEditPage = lazyPage(() => import("../features/lookups/pages/LookupEditPage"));
const DonorListPage = lazyPage(() => import("../features/donors/pages/DonorListPage"));
const DonorCreatePage = lazyPage(() => import("../features/donors/pages/DonorCreatePage"));
const DonorDetailsPage = lazyPage(() => import("../features/donors/pages/DonorDetailsPage"));
const DonorEditPage = lazyPage(() => import("../features/donors/pages/DonorEditPage"));
const DonationListPage = lazyPage(() => import("../features/donations/pages/DonationListPage"));
const DonationCreatePage = lazyPage(() => import("../features/donations/pages/DonationCreatePage"));
const DonationDetailsPage = lazyPage(() => import("../features/donations/pages/DonationDetailsPage"));
const DonationEditPage = lazyPage(() => import("../features/donations/pages/DonationEditPage"));
const DonationTracePage = lazyPage(() => import("../features/donations/pages/DonationTracePage"));
const UntracedSpendingPage = lazyPage(() => import("../features/donations/pages/UntracedSpendingPage"));
const DoubleCountingPage = lazyPage(() => import("../features/donations/pages/DoubleCountingPage"));
const DonorSharePage = lazyPage(() => import("../features/donations/pages/DonorSharePage"));
const ReportCenterPage = lazyPage(() => import("../features/reportCenter/ReportCenterPage"));
const ReportDetailPage = lazyPage(() => import("../features/reportCenter/ReportDetailPage"));
const ChangePasswordPage = lazyPage(() => import("../features/auth/pages/ChangePasswordPage"));
const SuperAdminDashboardPage = lazyPage(() => import("../features/superadmin/pages/SuperAdminDashboardPage"));
const OrganizationListPage = lazyPage(() => import("../features/superadmin/pages/OrganizationListPage"));
const OrganizationCreatePage = lazyPage(() => import("../features/superadmin/pages/OrganizationCreatePage"));
const OrganizationDetailsPage = lazyPage(() => import("../features/superadmin/pages/OrganizationDetailsPage"));
const OrganizationEditPage = lazyPage(() => import("../features/superadmin/pages/OrganizationEditPage"));
const PlanListPage = lazyPage(() => import("../features/superadmin/pages/PlanListPage"));
const SubscriptionManagementPage = lazyPage(() => import("../features/superadmin/pages/SubscriptionManagementPage"));
const ProgramListPage = lazyPage(() => import("../features/programs/pages/ProgramListPage"));
const ProgramCreatePage = lazyPage(() => import("../features/programs/pages/ProgramCreatePage"));
const ProgramDetailsPage = lazyPage(() => import("../features/programs/pages/ProgramDetailsPage"));
const ProgramEditPage = lazyPage(() => import("../features/programs/pages/ProgramEditPage"));
const BeneficiaryListPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryListPage"));
const BeneficiaryCreatePage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryCreatePage"));
const BeneficiaryDetailsPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryDetailsPage"));
const BeneficiaryEditPage = lazyPage(() => import("../features/beneficiaries/pages/BeneficiaryEditPage"));
const ProjectListPage = lazyPage(() => import("../features/projects/pages/projectListPage"));
const ProjectCreatePage = lazyPage(() => import("../features/projects/pages/projectCreatePage"));
const ProjectDetailsPage = lazyPage(() => import("../features/projects/pages/projectDetailsPage"));
const ProjectEditPage = lazyPage(() => import("../features/projects/pages/projectEditPage"));
const ActivityRunListPage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunListPage"));
const ActivityRunCreatePage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunCreatePage"));
const ActivityRunDetailsPage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunDetailsPage"));
const ActivityRunEditPage = lazyPage(() => import("../features/activityRuns/pages/ActivityRunEditPage"));
const TorListPage = lazyPage(() => import("../features/tor/pages/TorListPage"));
const TorCreatePage = lazyPage(() => import("../features/tor/pages/TorCreatePage"));
const TorDetailsPage = lazyPage(() => import("../features/tor/pages/TorDetailsPage"));
const TorEditPage = lazyPage(() => import("../features/tor/pages/TorEditPage"));
const BudgetListPage = lazyPage(() => import("../features/budgets/pages/BudgetListPage"));
const BudgetFormPage = lazyPage(() => import("../features/budgets/pages/BudgetFormPage"));
const BudgetDetailsPage = lazyPage(() => import("../features/budgets/pages/BudgetDetailsPage"));
const ExpenseListPage = lazyPage(() => import("../features/expenses/pages/ExpenseListPage"));
const ExpenseFormPage = lazyPage(() => import("../features/expenses/pages/ExpenseFormPage"));
const ExpenseDetailsPage = lazyPage(() => import("../features/expenses/pages/ExpenseDetailsPage"));
const EnrollmentListPage = lazyPage(() => import("../features/enrollments/pages/EnrollmentListPage"));
const EnrollmentCreatePage = lazyPage(() => import("../features/enrollments/pages/EnrollmentCreatePage"));
const EnrollmentDetailsPage = lazyPage(() => import("../features/enrollments/pages/EnrollmentDetailsPage"));
const EnrollmentEditPage = lazyPage(() => import("../features/enrollments/pages/EnrollmentEditPage"));
const ServiceDeliveryListPage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryListPage"));
const ServiceDeliveryCreatePage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryCreatePage"));
const ServiceDeliveryDetailsPage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryDetailsPage"));
const ServiceDeliveryEditPage = lazyPage(() => import("../features/ServiceDelivery/pages/ServiceDeliveryEditPage"));
const UserListPage = lazyPage(() => import("../features/users/pages/UserListPage"));
const UserCreatePage = lazyPage(() => import("../features/users/pages/UserCreatePage"));
const UserEditPage = lazyPage(() => import("../features/users/pages/UserEditPage"));


const PageFallback = () => (
    <LoadingState message="Loading..." />
);


const AppRoutes = () => {

    return (

        <Suspense fallback={<PageFallback />}>

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
                    MY ACCOUNT
                ================================================== */}

                <Route
                    path="/account/password"
                    element={
                        <ChangePasswordPage />
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
                        <PermissionRoute permission="organization.read">
                            <OrganizationSettingsPage />
                        </PermissionRoute>
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
                        <PermissionRoute permission="program.read">
                            <ProgramListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/programs/create"
                    element={
                        <PermissionRoute permission="program.create">
                            <ProgramCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/programs/:id"
                    element={
                        <PermissionRoute permission="program.read">
                            <ProgramDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/programs/:id/edit"
                    element={
                        <PermissionRoute permission="program.update">
                            <ProgramEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    BENEFICIARIES
                ================================================== */}

                <Route
                    path="/beneficiaries"
                    element={
                        <PermissionRoute permission="beneficiary.read">
                            <BeneficiaryListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/beneficiaries/create"
                    element={
                        <PermissionRoute permission="beneficiary.create">
                            <BeneficiaryCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/beneficiaries/:id"
                    element={
                        <PermissionRoute permission="beneficiary.read">
                            <BeneficiaryDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/beneficiaries/:id/edit"
                    element={
                        <PermissionRoute permission="beneficiary.update">
                            <BeneficiaryEditPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/beneficiaries/import"
                    element={
                        <PermissionRoute permission="beneficiary.create">
                            <BeneficiaryImportPage />
                        </PermissionRoute>
                    }
                />


{/* ==================================================
    ENTERPRISES
================================================== */}

<Route
    path="/enterprises"
    element={
        <PermissionRoute permission="enterprise.read">
            <EnterpriseListPage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprises/create"
    element={
        <PermissionRoute permission="enterprise.create">
            <EnterpriseCreatePage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprises/:id"
    element={
        <PermissionRoute permission="enterprise.read">
            <EnterpriseDetailsPage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprises/:id/edit"
    element={
        <PermissionRoute permission="enterprise.update">
            <EnterpriseEditPage />
        </PermissionRoute>
    }
/>


{/* ==================================================
    ENTERPRISE MEMBERS
================================================== */}

<Route
    path="/enterprise-members"
    element={
        <PermissionRoute permission="enterprise.read">
            <EnterpriseMemberListPage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprise-members/:id"
    element={
        <PermissionRoute permission="enterprise.read">
            <EnterpriseMemberDetailsPage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprise-members/:id/edit"
    element={
        <PermissionRoute permission="enterprise.update">
            <EnterpriseMemberEditPage />
        </PermissionRoute>
    }
/>


{/* ==================================================
    ENTERPRISE MEMBERS BY ENTERPRISE
================================================== */}

<Route
    path="/enterprises/:enterpriseId/members"
    element={
        <PermissionRoute permission="enterprise.read">
            <EnterpriseMemberListPage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/create"
    element={
        <PermissionRoute permission="enterprise.update">
            <EnterpriseMemberCreatePage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/:memberId"
    element={
        <PermissionRoute permission="enterprise.read">
            <EnterpriseMemberDetailsPage />
        </PermissionRoute>
    }
/>


<Route
    path="/enterprises/:enterpriseId/members/:memberId/edit"
    element={
        <PermissionRoute permission="enterprise.update">
            <EnterpriseMemberEditPage />
        </PermissionRoute>
    }
/>

                {/* ==================================================
                    ENROLLMENTS
                ================================================== */}

                <Route
                    path="/enrollments"
                    element={
                        <PermissionRoute permission="enrollment.read">
                            <EnrollmentListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/enrollments/create"
                    element={
                        <PermissionRoute permission="enrollment.create">
                            <EnrollmentCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/enrollments/:id"
                    element={
                        <PermissionRoute permission="enrollment.read">
                            <EnrollmentDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/enrollments/:id/edit"
                    element={
                        <PermissionRoute permission="enrollment.update">
                            <EnrollmentEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    PROJECTS
                ================================================== */}

                <Route
                    path="/projects"
                    element={
                        <PermissionRoute permission="project.read">
                            <ProjectListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/projects/create"
                    element={
                        <PermissionRoute permission="project.create">
                            <ProjectCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/projects/:id"
                    element={
                        <PermissionRoute permission="project.read">
                            <ProjectDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/projects/:id/edit"
                    element={
                        <PermissionRoute permission="project.update">
                            <ProjectEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    ACTIVITIES
                ================================================== */}

                <Route
                    path="/activities"
                    element={
                        <PermissionRoute permission="activity.read">
                            <ActivityListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/activities/create"
                    element={
                        <PermissionRoute permission="activity.create">
                            <ActivityCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/activities/:id"
                    element={
                        <PermissionRoute permission="activity.read">
                            <ActivityDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/activities/:id/edit"
                    element={
                        <PermissionRoute permission="activity.update">
                            <ActivityEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    ACTIVITY RUNS
                ================================================== */}

                <Route
                    path="/activity-runs"
                    element={
                        <PermissionRoute permission="activity_run.read">
                            <ActivityRunListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/activity-runs/create"
                    element={
                        <PermissionRoute permission="activity_run.create">
                            <ActivityRunCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/activity-runs/:id"
                    element={
                        <PermissionRoute permission="activity_run.read">
                            <ActivityRunDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/activity-runs/:id/edit"
                    element={
                        <PermissionRoute permission="activity_run.update">
                            <ActivityRunEditPage />
                        </PermissionRoute>
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
                    BUDGETS
                ================================================== */}

                <Route
                    path="/budgets"
                    element={
                        <PermissionRoute permission="budget.read">
                            <BudgetListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/budgets/create"
                    element={
                        <PermissionRoute permission="budget.create">
                            <BudgetFormPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/budgets/:id"
                    element={
                        <PermissionRoute permission="budget.read">
                            <BudgetDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/budgets/:id/edit"
                    element={
                        <PermissionRoute permission="budget.update">
                            <BudgetFormPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/budgets/:id/revise"
                    element={
                        <PermissionRoute permission="budget.update">
                            <BudgetFormPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    EXPENSES
                ================================================== */}

                <Route
                    path="/expenses"
                    element={
                        <PermissionRoute permission="expense.read">
                            <ExpenseListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/expenses/create"
                    element={
                        <PermissionRoute permission="expense.create">
                            <ExpenseFormPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/expenses/:id"
                    element={
                        <PermissionRoute permission="expense.read">
                            <ExpenseDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/expenses/:id/edit"
                    element={
                        <PermissionRoute permission="expense.update">
                            <ExpenseFormPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    ATTENDANCE
                ================================================== */}

                <Route
                    path="/attendance"
                    element={
                        <PermissionRoute permission="attendance.read">
                            <AttendanceListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/attendance/create"
                    element={
                        <PermissionRoute permission="attendance.create">
                            <AttendanceCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/attendance/:id/edit"
                    element={
                        <PermissionRoute permission="attendance.update">
                            <AttendanceEditPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/attendance/:id/sheet"
                    element={
                        <PermissionRoute permission="attendance.read">
                            <AttendanceSheetPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    SERVICE DELIVERY
                ================================================== */}

                <Route
                    path="/service-deliveries"
                    element={
                        <PermissionRoute permission="service.read">
                            <ServiceDeliveryListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/service-deliveries/create"
                    element={
                        <PermissionRoute permission="service.create">
                            <ServiceDeliveryCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/service-deliveries/:id"
                    element={
                        <PermissionRoute permission="service.read">
                            <ServiceDeliveryDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/service-deliveries/:id/edit"
                    element={
                        <PermissionRoute permission="service.update">
                            <ServiceDeliveryEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    CUSTOM FIELDS
                ================================================== */}

                <Route
                    path="/settings/roles"
                    element={
                        <PermissionRoute
                            permission="role.manage"
                        >
                            <RolesPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/settings/custom-fields"
                    element={
                        <PermissionRoute
                            permission="customfield.update"
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
        // Admin only: other roles read lookups for dropdowns,
        // they do not manage them
        <PermissionRoute permission="lookup.update">
            <LookupListPage />
        </PermissionRoute>
    }
/>

<Route
    path="/lookups/create"
    element={
        <PermissionRoute permission="lookup.create">
            <LookupCreatePage />
        </PermissionRoute>
    }
/>

<Route
    path="/lookups/module/:module/category/:category"
    element={
        <PermissionRoute permission="lookup.update">
            <LookupCategoryPage />
        </PermissionRoute>
    }
/>

<Route
    path="/lookups/:id/edit"
    element={
        <PermissionRoute permission="lookup.update">
            <LookupEditPage />
        </PermissionRoute>
    }
/>


                {/* ==================================================
                    DONORS
                ================================================== */}

                <Route
                    path="/donors"
                    element={
                        <PermissionRoute permission="donor.read">
                            <DonorListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donors/create"
                    element={
                        <PermissionRoute permission="donor.create">
                            <DonorCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donors/:id"
                    element={
                        <PermissionRoute permission="donor.read">
                            <DonorDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donors/:id/edit"
                    element={
                        <PermissionRoute permission="donor.update">
                            <DonorEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    DONATIONS
                ================================================== */}

                <Route
                    path="/donations"
                    element={
                        <PermissionRoute permission="donation.read">
                            <DonationListPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donations/create"
                    element={
                        <PermissionRoute permission="donation.create">
                            <DonationCreatePage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donations/double-counting"
                    element={
                        <PermissionRoute permission="donation.read">
                            <DoubleCountingPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donations/untraced"
                    element={
                        <PermissionRoute permission="donation.read">
                            <UntracedSpendingPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donations/:id"
                    element={
                        <PermissionRoute permission="donation.read">
                            <DonationDetailsPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/donations/:id/trace"
                    element={
                        <PermissionRoute permission="donation.read">
                            <DonationTracePage />
                        </PermissionRoute>
                    }
                />

                                <Route
                    path="/donations/:id/edit"
                    element={
                        <PermissionRoute permission="donation.update">
                            <DonationEditPage />
                        </PermissionRoute>
                    }
                />


                {/* ==================================================
                    REPORTS
                ================================================== */}

                <Route
                    path="/reports"
                    element={
                        <PermissionRoute permission="report.read">
                            <ReportCenterPage />
                        </PermissionRoute>
                    }
                />

                <Route
                    path="/reports/detail/:kind/:id"
                    element={
                        <PermissionRoute permission="report.read">
                            <ReportDetailPage />
                        </PermissionRoute>
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

        </Suspense>

    );

};


export default AppRoutes;