# GreenGrid — Solar PV & BESS Project Control Dashboard

## Run locally
1. Extract the ZIP.
2. Open `index.html` in Chrome, Edge, or Firefox.
3. The app works without installing packages or an internet connection.

## Included
- Overview with weighted progress KPIs and planned-vs-actual view
- Solar PV mechanical/electrical activity register
- BESS activity register and six block status cards
- Daily, weekly, monthly progress update log
- QA/QC, HSE, manpower/equipment, and issue registers
- CSV activity export, JSON backup/restore, print-to-PDF report
- Browser-local persistence using localStorage

## Important limitations
This is a functional local-first prototype. Records are stored only in the browser profile on the device where they are entered. The role selector is a demonstration control, not real authentication or access control. It does not yet synchronize multiple users or devices.

To make it a true multi-user company website, deploy the frontend and connect a hosted database/authentication service (for example Supabase), then configure user accounts, role-based permissions, audit history, backups, and HTTPS. Do not enter confidential company data until that backend and access control are configured.

## Sample data
Initial activities and quantities are illustrative only. Replace them with approved project baseline quantities and verified installed quantities before issuing any report.
