// =====================================================
// ENROLLMENTS: FROM PROGRAMS TO PROJECTS (one time)
// =====================================================
//
// Enrollments now belong to a project (or a phase). This:
//
// 1. drops the old unique index "once per program"
//    (organization, program, beneficiary, isDeleted), so a
//    person can be in several projects of one program; the
//    new one is (organization, program, project, beneficiary,
//    isDeleted);
// 2. gives older enrollments without a project their project
//    when the program has exactly one project people can be
//    enrolled in (a project on its own, or a phase); the
//    others stay "project not set" for the admin to choose.
//
//   node scripts/migrateEnrollmentsToProjects.js --dry-run
//   node scripts/migrateEnrollmentsToProjects.js
//   node scripts/migrateEnrollmentsToProjects.js --uri-file .env.atlas --db ngo_system --dry-run
//
// Safe to run again.
//
// =====================================================

require("dotenv").config({ quiet: true });

const mongoose = require("mongoose");

const { connectForScript } = require("../utils/scriptConnection");

const OLD_INDEX = "organization_1_program_1_beneficiary_1_isDeleted_1";

const dryRun = process.argv.includes("--dry-run");


const main = async () => {

    await connectForScript();

    const db = mongoose.connection.db;

    console.log(`Database: ${mongoose.connection.name}${dryRun ? " (dry run)" : ""}`);

    // ---------------- 1. the old index
    const indexes = await db.collection("enrollments").indexes();

    if (indexes.some(index => index.name === OLD_INDEX)) {
        console.log(`- unique index once per program: ${dryRun ? "would be dropped" : "dropped"}`);
        if (!dryRun) await db.collection("enrollments").dropIndex(OLD_INDEX);
    }
    else {
        console.log("- unique index once per program: already gone");
    }

    if (!dryRun) {
        await require("../models/enrollment").syncIndexes();
        console.log("- indexes in line with the model");
    }

    // ---------------- 2. older enrollments without a project
    const open = await db.collection("enrollments").find({ isDeleted: { $ne: true }, $or: [{ project: null }, { project: { $exists: false } }] }).project({ organization: 1, program: 1, beneficiary: 1 }).toArray();

    const projects = await db.collection("projects").find({ isDeleted: { $ne: true } }).project({ program: 1, parentProject: 1, name: 1 }).toArray();

    const mains = new Set(projects.filter(project => project.parentProject).map(project => String(project.parentProject)));

    // per program: the projects people can be enrolled in
    const enrollable = new Map();
    for (const project of projects) {
        if (mains.has(String(project._id))) continue;
        const key = String(project.program);
        enrollable.set(key, [...(enrollable.get(key) || []), project]);
    }

    // where each person was served: { beneficiary: Set(project) }
    const deliveries = await db.collection("servicedeliveries").find({ isDeleted: { $ne: true }, status: { $ne: "Cancelled" }, project: { $ne: null } }).project({ project: 1 }).toArray();
    const projectOfDelivery = new Map(deliveries.map(delivery => [String(delivery._id), String(delivery.project)]));
    const served = new Map();
    const links = await db.collection("servicedeliverybeneficiaries").find({}).project({ serviceDelivery: 1, beneficiary: 1 }).toArray();
    for (const link of links) {
        const project = projectOfDelivery.get(String(link.serviceDelivery));
        if (!project) continue;
        const key = String(link.beneficiary);
        served.set(key, (served.get(key) || new Set()).add(project));
    }

    let alone = 0;
    let byDeliveries = 0;
    let left = 0;

    for (const enrollment of open) {
        const choices = enrollable.get(String(enrollment.program)) || [];
        let chosen = null;
        // the only project of the program
        if (choices.length === 1) {
            chosen = choices[0]._id;
            alone += 1;
        }
        // the only project of the program where the person was served
        else {
            const where = choices.filter(project => served.get(String(enrollment.beneficiary))?.has(String(project._id)));
            if (where.length === 1) {
                chosen = where[0]._id;
                byDeliveries += 1;
            }
        }
        if (!chosen) { left += 1; continue; }
        if (!dryRun) {
            await db.collection("enrollments").updateOne({ _id: enrollment._id }, { $set: { project: chosen } });
        }
    }

    console.log(`- enrollments without a project: ${open.length}`);
    console.log(`  ${dryRun ? "would get" : "got"} their project: ${alone + byDeliveries} (only project of the program: ${alone}; the only project where the person was served: ${byDeliveries})`);
    console.log(`  left for the admin to choose: ${left}`);

    await mongoose.disconnect();

};

main().catch(error => {
    console.error(error.message);
    process.exit(1);
});
