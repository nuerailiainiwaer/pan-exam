# Pan-Exam system for Acupuncture (v10)
Vanilla HTML/CSS/JS + Node/Express + MongoDB.

## Features
- Word-inspired UI; background `#f2f7f4`
- Practice page: no duplicate headers; border highlight on expand; Known/Mark toggles
- Users can only delete their own comments; username badge shown after login
- **Exam Mode**: 50 random questions in 60 minutes, excluding Known (green)
- **Exam History**: list attempts; review grid with wrong answers highlighted red; click to see details and correct answer

## Quick Start
1. Create `.env` from `.env.example` and set `MONGODB_URI` + `SESSION_SECRET` (+ optional admin envs).
2. `npm install`
3. `npm start`
4. Open `http://localhost:3000`
5. Admin default (seeded if missing): `aili / Nur%123n...`

## Importing Questions
Use MongoDB Compass (GUI) or mongoimport to import JSON arrays into the `questions` collection of DB `panexamv9`.
