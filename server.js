// --- server.js (Render-ready) ---
require('dotenv').config();

const express = require('express');
const path = require('path');
const mongoose = require('mongoose');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = process.env.PORT || 3000;

// Trust Render/Heroku-style proxy so secure cookies work
app.set('trust proxy', 1);

// Security & performance
app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false }));
app.use(compression());

// Parsers
app.use(express.json({ limit: '200kb' }));
app.use(express.urlencoded({ extended: false, limit: '200kb' }));

/* ----- Mongo ----- */
const mongoUrl = process.env.MONGODB_URI || 'mongodb://localhost:27017/panexamv9';
mongoose
    .connect(mongoUrl, { dbName: 'panexamv9', serverSelectionTimeoutMS: 20000 })
    .then(() => console.log('MongoDB connected'))
    .catch((err) => {
        console.error('Mongo error:', err);
        process.exit(1);
    });

/* ----- Sessions (Mongo store; no MemoryStore warning) ----- */
const useSecureCookies = process.env.NODE_ENV === 'production';
app.use(
    session({
        name: 'sid',
        secret: process.env.SESSION_SECRET || 'change-me',
        resave: false,
        saveUninitialized: false,
        proxy: true,
        store: MongoStore.create({
            mongoUrl,
            dbName: 'panexamv9',
            collectionName: 'sessions',
            ttl: 60 * 60 * 24 * 7, // 7 days
            autoRemove: 'native',
        }),
        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure: useSecureCookies, // true on Render (HTTPS), false locally
            maxAge: 1000 * 60 * 60 * 24 * 7,
        },
    })
);

// Optional gentle rate limits
const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 20 });
app.use('/api/admin/login', authLimiter);
app.use('/api/user/login', authLimiter);

// Static files
app.use(express.static(path.join(__dirname, 'public')));

/* =========================
   ====== Schemas ==========
   ========================= */
const UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], required: true, default: 'user' },
    knownQuestionIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Question' }],
    markedQuestionIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Question' }],
}, { timestamps: true });

const QuestionSchema = new mongoose.Schema({
    topic: { type: String, required: true, trim: true },
    options: {
        A: { type: String, required: true },
        B: { type: String, required: true },
        C: { type: String, required: true },
        D: { type: String, required: true },
    },
    correct: { type: String, enum: ['A', 'B', 'C', 'D'], required: true },
    imageUrl: { type: String },
}, { timestamps: true });

const CaseSchema = new mongoose.Schema({
    text: { type: String, required: true },
    imageUrl: { type: String },
}, { timestamps: true });

const CommentSchema = new mongoose.Schema({
    caseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Case', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    username: { type: String, required: true },
    text: { type: String, required: true },
}, { timestamps: true });

const NoteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    questionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Question', required: true },
    text: { type: String, default: '' },
}, { timestamps: true });

const ExamTemplateSchema = new mongoose.Schema({
    title: String,
    description: String,
    durationMinutes: Number,
    questionCount: Number,
    randomize: { type: Boolean, default: true },
    passMark: { type: Number, default: 70 },
    allowReview: { type: Boolean, default: true },
}, { timestamps: true });

const ExamAttemptSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    examId: { type: mongoose.Schema.Types.ObjectId, ref: 'ExamTemplate', required: true },
    startedAt: { type: Date, required: true },
    submittedAt: { type: Date },
    status: { type: String, enum: ['in_progress', 'submitted', 'expired'], default: 'in_progress' },
    durationSec: { type: Number, required: true },
    questionIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Question', required: true }],
    currentIndex: { type: Number, default: 0 },
    answers: { type: Map, of: String, default: {} },
    flagged: { type: Map, of: Boolean, default: {} },
    scorePct: Number,
    correctCount: Number,
    pass: Boolean,
}, { timestamps: true });

const User = mongoose.model('User', UserSchema);
const Question = mongoose.model('Question', QuestionSchema);
const Case = mongoose.model('Case', CaseSchema);
const Comment = mongoose.model('Comment', CommentSchema);
const Note = mongoose.model('Note', NoteSchema);
const ExamTemplate = mongoose.model('ExamTemplate', ExamTemplateSchema);
const ExamAttempt = mongoose.model('ExamAttempt', ExamAttemptSchema);

/* =========================
   ======= Seeds ===========
   ========================= */
function seedAdmin() {
    const defU = process.env.DEFAULT_ADMIN_USERNAME || 'aili';
    const defP = process.env.DEFAULT_ADMIN_PASSWORD || 'Nur%123n...';
    const force = process.env.DEFAULT_ADMIN_FORCE_RESET === '1';
    User.findOne({ username: defU })
        .then((u) => {
            const hash = bcrypt.hashSync(defP, 10);
            if (!u) {
                return User.create({ username: defU, passwordHash: hash, role: 'admin' }).then(() =>
                    console.log('Seeded admin:', defU)
                );
            } else {
                const updates = {};
                if (u.role !== 'admin') updates.role = 'admin';
                if (force) updates.passwordHash = hash;
                if (Object.keys(updates).length) {
                    Object.assign(u, updates);
                    return u.save().then(() => {
                        console.log('Updated admin:', defU, '(role' + (updates.passwordHash ? ', password' : '') + ' reset)');
                    });
                }
            }
        })
        .catch((e) => console.error('Seed admin error:', e));
}

function seedDefaultExam() {
    ExamTemplate.findOne({ title: 'Quick 50 (60 min)' })
        .then((t) => {
            if (!t) {
                return ExamTemplate.create({
                    title: 'Quick 50 (60 min)',
                    description: '50 random questions in 60 minutes. Known (green) are excluded.',
                    durationMinutes: 60,
                    questionCount: 50,
                    randomize: true,
                    passMark: 70,
                    allowReview: true,
                }).then(() => console.log('Seeded default exam template.'));
            }
        })
        .catch((e) => console.error('Seed default exam error:', e));
}

// Kick off seeds after Mongo connects (already connected above)
seedAdmin();
seedDefaultExam();

/* =========================
   ======= Helpers =========
   ========================= */
function requireAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.role === 'admin') return next();
    return res.status(401).json({ error: 'Admin login required' });
}

function requireUser(req, res, next) {
    if (req.session && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'user')) return next();
    return res.status(401).json({ error: 'User login required' });
}

function escRegex(str) {
    return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function wordsSnippet(t) {
    if (!t) return '';
    return t.trim().split(/\s+/).slice(0, 20).join(' ');
}

/* =========================
   ======= Routes ==========
   ========================= */

// Health check
app.get('/healthz', (_, res) => res.json({ ok: true }));

/* Session: who am I */
app.get('/api/me', (req, res) => {
    if (req.session && req.session.user) {
        return res.json({ ok: true, username: req.session.user.username, role: req.session.user.role });
    }
    res.json({ ok: false });
});

/* Admin Auth */
app.post('/api/admin/login', (req, res) => {
    const username = (req.body.username || '').trim();
    const password = String(req.body.password || '');
    User.findOne({ username, role: 'admin' })
        .then((u) => {
            if (!u) return res.status(400).json({ error: 'Invalid admin credentials' });
            const ok = bcrypt.compareSync(password, u.passwordHash);
            if (!ok) return res.status(400).json({ error: 'Invalid admin credentials' });
            req.session.user = { id: u._id.toString(), username: u.username, role: 'admin' };
            res.json({ ok: true });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* User Auth */
app.post('/api/user/login', (req, res) => {
    const username = (req.body.username || '').trim();
    const password = String(req.body.password || '');
    User.findOne({ username })
        .then((u) => {
            if (!u) return res.status(400).json({ error: 'Wrong username or password' });
            const ok = bcrypt.compareSync(password, u.passwordHash);
            if (!ok) return res.status(400).json({ error: 'Wrong username or password' });
            req.session.user = { id: u._id.toString(), username: u.username, role: u.role };
            res.json({ ok: true });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.post('/api/logout', (req, res) => {
    req.session.destroy(() => res.json({ ok: true }));
});

/* Admin Stats */
app.get('/api/admin/stats', requireAdmin, (req, res) => {
    Promise.all([
            User.countDocuments({ role: { $in: ['user', 'admin'] } }),
            Question.countDocuments({}),
            Case.countDocuments({}),
            Comment.countDocuments({}),
        ])
        .then((arr) => res.json({ userCount: arr[0], questionCount: arr[1], caseCount: arr[2], commentCount: arr[3] }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* Admin Questions */
app.post('/api/admin/questions', requireAdmin, (req, res) => {
    const topic = (req.body.topic || '').trim();
    const imageUrl = (req.body.imageUrl || '').trim();
    const options = req.body.options || {};
    const correct = (req.body.correct || '').trim();
    if (!topic || !options.A || !options.B || !options.C || !options.D || !correct)
        return res.status(400).json({ error: 'All fields (except image) required.' });
    if (!['A', 'B', 'C', 'D'].includes(correct)) return res.status(400).json({ error: 'Correct must be A/B/C/D' });
    Question.create({ topic, options, correct, imageUrl })
        .then((q) => res.json({ ok: true, id: q._id.toString() }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/admin/questions', requireAdmin, (req, res) => {
    const search = (req.query.search || '').trim();
    const q = {};
    if (search) q.topic = { $regex: new RegExp(escRegex(search), 'i') };
    Question.find(q)
        .sort({ topic: 1 })
        .select({ topic: 1 })
        .then((items) => res.json({ items: items.map((x) => ({ id: x._id.toString(), topic: x.topic })) }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.delete('/api/admin/questions/:id', requireAdmin, (req, res) => {
    const id = req.params.id;
    Question.findByIdAndDelete(id)
        .then((x) => {
            if (!x) return res.status(404).json({ error: 'Not found' });
            return Promise.all([
                User.updateMany({}, { $pull: { knownQuestionIds: x._id, markedQuestionIds: x._id } }),
                Note.deleteMany({ questionId: x._id }),
            ]).then(() => res.json({ ok: true }));
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* Admin Users */
app.post('/api/admin/users', requireAdmin, (req, res) => {
    const username = (req.body.username || '').trim();
    const password = String(req.body.password || '');
    if (!username || !password) return res.status(400).json({ error: 'Both fields required' });
    const hash = bcrypt.hashSync(password, 10);
    User.create({ username, passwordHash: hash, role: 'user' })
        .then((u) => res.json({ ok: true, id: u._id.toString() }))
        .catch((e) => {
            if (e && e.code === 11000) return res.status(400).json({ error: 'Username already exists' });
            res.status(500).json({ error: 'Server error' });
        });
});

app.get('/api/admin/users', requireAdmin, (req, res) => {
    const search = (req.query.search || '').trim();
    const q = {};
    if (search) q.username = { $regex: new RegExp(escRegex(search), 'i') };
    User.find(q)
        .sort({ username: 1 })
        .select({ username: 1, role: 1 })
        .then((items) => res.json({ items: items.map((u) => ({ id: u._id.toString(), username: u.username, role: u.role })) }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.delete('/api/admin/users/:id', requireAdmin, (req, res) => {
    const id = req.params.id;
    User.findByIdAndDelete(id)
        .then((u) => {
            if (!u) return res.status(404).json({ error: 'Not found' });
            return Promise.all([Note.deleteMany({ userId: u._id }), Comment.deleteMany({ userId: u._id })]).then(() =>
                res.json({ ok: true })
            );
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* Admin Cases & Comments */
app.post('/api/admin/cases', requireAdmin, (req, res) => {
    const text = (req.body.text || '').trim();
    const imageUrl = (req.body.imageUrl || '').trim();
    if (!text) return res.status(400).json({ error: 'Text required' });
    Case.create({ text, imageUrl })
        .then((c) => res.json({ ok: true, id: c._id.toString() }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/admin/cases', requireAdmin, (req, res) => {
    const search = (req.query.search || '').trim();
    const q = {};
    if (search) q.text = { $regex: new RegExp(escRegex(search), 'i') };
    Case.find(q)
        .sort({ createdAt: -1 })
        .then((items) => res.json({ items: items.map((c) => ({ id: c._id.toString(), snippet: wordsSnippet(c.text) })) }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/admin/cases/:id', requireAdmin, (req, res) => {
    Case.findById(req.params.id)
        .then((c) => {
            if (!c) return res.status(404).json({ error: 'Not found' });
            res.json({ id: c._id.toString(), text: c.text, imageUrl: c.imageUrl });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.delete('/api/admin/cases/:id', requireAdmin, (req, res) => {
    const id = req.params.id;
    Case.findByIdAndDelete(id)
        .then((c) => {
            if (!c) return res.status(404).json({ error: 'Not found' });
            return Comment.deleteMany({ caseId: c._id }).then(() => res.json({ ok: true }));
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/admin/comments', requireAdmin, (req, res) => {
    const caseId = req.query.caseId;
    const q = {};
    if (caseId) q.caseId = caseId;
    Comment.find(q)
        .sort({ createdAt: -1 })
        .then((items) => res.json({ items: items.map((cm) => ({ id: cm._id.toString(), username: cm.username, text: cm.text })) }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.delete('/api/admin/comments/:id', requireAdmin, (req, res) => {
    Comment.findByIdAndDelete(req.params.id)
        .then((c) => {
            if (!c) return res.status(404).json({ error: 'Not found' });
            res.json({ ok: true });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* User: Questions list/search */
app.get('/api/user/questions', requireUser, (req, res) => {
    const search = (req.query.search || '').trim();
    const q = {};
    if (search) q.topic = { $regex: new RegExp(escRegex(search), 'i') };
    Question.find(q)
        .sort({ topic: 1 })
        .select({ topic: 1 })
        .then((items) => {
            const uid = req.session.user.id;
            User.findById(uid).then((u) => {
                const knownSet = new Set((u.knownQuestionIds || []).map((x) => String(x)));
                const markedSet = new Set((u.markedQuestionIds || []).map((x) => String(x)));
                res.json({
                    items: items.map((x) => ({
                        id: x._id.toString(),
                        topic: x.topic,
                        known: knownSet.has(String(x._id)),
                        marked: markedSet.has(String(x._id)),
                    })),
                });
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/user/questions/:id', requireUser, (req, res) => {
    const id = req.params.id;
    const uid = req.session.user.id;
    Promise.all([Question.findById(id), User.findById(uid)])
        .then(([q, u]) => {
            if (!q) return res.status(404).json({ error: 'Not found' });
            const known = (u.knownQuestionIds || []).some((x) => String(x) === String(q._id));
            const marked = (u.markedQuestionIds || []).some((x) => String(x) === String(q._id));
            res.json({
                id: q._id.toString(),
                topic: q.topic,
                options: q.options,
                correct: q.correct,
                imageUrl: q.imageUrl,
                known,
                marked,
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.post('/api/user/known', requireUser, (req, res) => {
    const qid = req.body.questionId;
    const known = !!req.body.known;
    const uid = req.session.user.id;
    User.findById(uid)
        .then((u) => {
            if (!u) return res.status(401).json({ error: 'Login' });
            const hasKnown = (u.knownQuestionIds || []).some((x) => String(x) === String(qid));
            const hasMarked = (u.markedQuestionIds || []).some((x) => String(x) === String(qid));
            const upd = {};
            if (known && !hasKnown) upd.$addToSet = { knownQuestionIds: qid };
            if (!known && hasKnown) upd.$pull = Object.assign({}, upd.$pull || {}, { knownQuestionIds: qid });
            if (hasMarked && known) upd.$pull = Object.assign({}, upd.$pull || {}, { markedQuestionIds: qid });
            if (Object.keys(upd).length === 0) return res.json({ ok: true });
            User.updateOne({ _id: u._id }, upd).then(() => res.json({ ok: true }));
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.post('/api/user/mark', requireUser, (req, res) => {
    const qid = req.body.questionId;
    const marked = !!req.body.marked;
    const uid = req.session.user.id;
    User.findById(uid)
        .then((u) => {
            if (!u) return res.status(401).json({ error: 'Login' });
            const hasKnown = (u.knownQuestionIds || []).some((x) => String(x) === String(qid));
            const hasMarked = (u.markedQuestionIds || []).some((x) => String(x) === String(qid));
            const upd = {};
            if (marked && !hasMarked) upd.$addToSet = { markedQuestionIds: qid };
            if (!marked && hasMarked) upd.$pull = Object.assign({}, upd.$pull || {}, { markedQuestionIds: qid });
            if (hasKnown && marked) upd.$pull = Object.assign({}, upd.$pull || {}, { knownQuestionIds: qid });
            if (Object.keys(upd).length === 0) return res.json({ ok: true });
            User.updateOne({ _id: u._id }, upd).then(() => res.json({ ok: true }));
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* Notes */
app.get('/api/user/notes/:qid', requireUser, (req, res) => {
    Note.findOne({ userId: req.session.user.id, questionId: req.params.qid })
        .then((n) => res.json({ text: n ? n.text : '' }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});
app.post('/api/user/notes/:qid', requireUser, (req, res) => {
    const text = String(req.body.text || '');
    Note.findOneAndUpdate({ userId: req.session.user.id, questionId: req.params.qid }, { $set: { text } }, { upsert: true, new: true })
        .then(() => res.json({ ok: true }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* User Cases & Comments */
app.get('/api/user/cases', requireUser, (req, res) => {
    const search = (req.query.search || '').trim();
    const q = {};
    if (search) q.text = { $regex: new RegExp(escRegex(search), 'i') };
    Case.find(q)
        .sort({ createdAt: -1 })
        .then((items) => {
            const ids = items.map((c) => c._id);
            if (ids.length === 0) return res.json({ items: [] });
            Comment.find({ caseId: { $in: ids }, userId: req.session.user.id }).then((comments) => {
                const set = new Set(comments.map((cm) => String(cm.caseId)));
                const out = items.map((c) => ({
                    id: c._id.toString(),
                    snippet: wordsSnippet(c.text),
                    commented: set.has(String(c._id)),
                }));
                res.json({ items: out });
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/user/cases/:id', requireUser, (req, res) => {
    Case.findById(req.params.id)
        .then((c) => {
            if (!c) return res.status(404).json({ error: 'Not found' });
            res.json({ id: c._id.toString(), text: c.text, imageUrl: c.imageUrl });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/user/cases/:id/comments', requireUser, (req, res) => {
    Comment.find({ caseId: req.params.id })
        .sort({ createdAt: -1 })
        .then((items) => {
            const uid = req.session.user.id;
            res.json({
                items: items.map((cm) => ({
                    id: cm._id.toString(),
                    username: cm.username,
                    text: cm.text,
                    isOwner: String(cm.userId) === String(uid),
                })),
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.post('/api/user/cases/:id/comments', requireUser, (req, res) => {
    const text = (req.body.text || '').trim();
    if (!text) return res.status(400).json({ error: 'Text required' });
    const u = req.session.user;
    Comment.create({ caseId: req.params.id, userId: u.id, username: u.username, text })
        .then(() => res.json({ ok: true }))
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.delete('/api/user/comments/:id', requireUser, (req, res) => {
    Comment.findById(req.params.id)
        .then((c) => {
            if (!c) return res.status(404).json({ error: 'Not found' });
            if (String(c.userId) !== String(req.session.user.id))
                return res.status(403).json({ error: 'You can only delete your own comment' });
            return c.deleteOne().then(() => res.json({ ok: true }));
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* ===== Exam helpers ===== */
function finishIfExpired(attempt) {
    const now = new Date();
    const end = new Date(attempt.startedAt.getTime() + attempt.durationSec * 1000);
    if (attempt.status === 'in_progress' && now > end) {
        return finalizeAttempt(attempt._id, true);
    }
    return Promise.resolve(attempt);
}

function finalizeAttempt(attemptId, markExpired) {
    return ExamAttempt.findById(attemptId).then((at) => {
        if (!at) return null;
        if (at.status !== 'in_progress' && !markExpired) return at;
        return Question.find({ _id: { $in: at.questionIds } }).then((questions) => {
            let correctCount = 0;
            const mapQ = {};
            questions.forEach((q) => (mapQ[String(q._id)] = q));
            (at.questionIds || []).forEach((qid) => {
                const q = mapQ[String(qid)];
                if (!q) return;
                const ans = at.answers.get(String(qid));
                if (ans && ans === q.correct) correctCount++;
            });
            const score = Math.round((100 * correctCount) / (at.questionIds.length || 1));
            return ExamTemplate.findById(at.examId).then((tpl) => {
                at.correctCount = correctCount;
                at.scorePct = score;
                at.pass = score >= (tpl ? tpl.passMark : 70);
                at.status = markExpired ? 'expired' : 'submitted';
                at.submittedAt = new Date();
                return at.save();
            });
        });
    });
}

/* ===== Exams ===== */
app.get('/api/exams', requireUser, async(req, res) => {
    try {
        const templates = await ExamTemplate.find({}, { title: 1, questionCount: 1, durationMinutes: 1, passMark: 1 })
            .sort({ createdAt: -1 })
            .lean();
        res.json({
            exams: (templates || []).map((t) => ({
                id: String(t._id),
                title: t.title || 'Exam',
                questionCount: t.questionCount || 0,
                durationMinutes: t.durationMinutes || 0,
                passMark: typeof t.passMark === 'number' ? t.passMark : 70,
            })),
        });
    } catch (e) {
        console.error('GET /api/exams error:', e);
        res.status(500).json({ error: 'Server error' });
    }
});

app.post('/api/exams/:id/start', requireUser, (req, res) => {
    const uid = req.session.user.id;
    const examId = req.params.id;

    // Expire any lingering in-progress attempts for this user (no resume)
    ExamAttempt.find({ userId: uid, status: 'in_progress' })
        .then((list) => {
            const proms = (list || []).map((a) => finalizeAttempt(a._id, true));
            Promise.all(proms).then(() => startNew());
        })
        .catch(() => startNew());

    function startNew() {
        ExamTemplate.findById(examId).then((tpl) => {
            if (!tpl) return res.status(404).json({ error: 'Exam not found' });
            User.findById(uid).then((u) => {
                const exclude = u.knownQuestionIds || [];
                const match = { _id: { $nin: exclude } };
                const size = tpl.questionCount || 50;
                Question.aggregate([{ $match: match }, { $sample: { size } }, { $project: { _id: 1 } }]).then((arr) => {
                    const ids = arr.map((x) => x._id);
                    if (ids.length < size) {
                        const remain = size - ids.length;
                        Question.aggregate([{ $sample: { size: remain * 2 } }, { $project: { _id: 1 } }]).then((arr2) => {
                            const set = new Set(ids.map(String));
                            for (let i = 0; i < arr2.length && ids.length < size; i++) {
                                const id = arr2[i]._id;
                                if (!set.has(String(id))) {
                                    ids.push(id);
                                    set.add(String(id));
                                }
                            }
                            createAttempt(ids, tpl);
                        });
                    } else {
                        createAttempt(ids, tpl);
                    }
                });
            });
        });
    }

    function createAttempt(ids, tpl) {
        const dur = (tpl.durationMinutes || 60) * 60;
        ExamAttempt.create({
                userId: req.session.user.id,
                examId: tpl._id,
                startedAt: new Date(),
                durationSec: dur,
                questionIds: ids,
                currentIndex: 0,
                answers: {},
                flagged: {},
            })
            .then((a) => res.json({ ok: true, attemptId: a._id.toString() }))
            .catch(() => res.status(500).json({ error: 'Server error' }));
    }
});

app.get('/api/attempts/:id/summary', requireUser, (req, res) => {
    ExamAttempt.findById(req.params.id)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
            return finishIfExpired(a).then((a2) => {
                a = a2 || a;
                const now = new Date();
                const end = new Date(a.startedAt.getTime() + a.durationSec * 1000);
                const rem = Math.max(0, Math.floor((end - now) / 1000));
                const ansMap = {};
                const flagMap = {};
                for (let i = 0; i < a.questionIds.length; i++) {
                    const qid = String(a.questionIds[i]);
                    if (a.answers.has(qid)) ansMap[i] = true;
                    if (a.flagged.get(qid)) flagMap[i] = true;
                }
                res.json({
                    total: a.questionIds.length,
                    currentIndex: a.currentIndex || 0,
                    questionIds: a.questionIds.map(String),
                    answered: ansMap,
                    flagged: flagMap,
                    remainingSec: rem,
                });
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/attempts/:id/q/:index', requireUser, (req, res) => {
    const idx = parseInt(req.params.index, 10) || 0;
    ExamAttempt.findById(req.params.id)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
            if (idx < 0 || idx >= a.questionIds.length) return res.status(400).json({ error: 'Bad index' });
            a.currentIndex = idx;
            a.save();
            const qid = a.questionIds[idx];
            Question.findById(qid).then((q) => {
                if (!q) return res.status(404).json({ error: 'Question missing' });
                const ch = a.answers.get(String(q._id)) || null;
                const fl = !!a.flagged.get(String(q._id));
                res.json({ id: q._id.toString(), topic: q.topic, options: q.options, imageUrl: q.imageUrl, choice: ch, flagged: fl });
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* === Mutually exclusive: selecting clears flag; flagging clears answer === */
app.post('/api/attempts/:id/answer', requireUser, (req, res) => {
    const qid = String(req.body.questionId || '');
    const choice = req.body.choice; // may be null
    ExamAttempt.findById(req.params.id)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });

            if (choice === null || choice === undefined || choice === '') {
                a.answers.delete(qid);
            } else {
                if (!['A', 'B', 'C', 'D'].includes(String(choice))) return res.status(400).json({ error: 'Bad choice' });
                a.answers.set(qid, String(choice));
                // Selecting an answer clears the flag
                a.flagged.set(qid, false);
            }
            return a.save().then(() => res.json({ ok: true }));
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.post('/api/attempts/:id/flag', requireUser, (req, res) => {
    const qid = String(req.body.questionId || '');
    const flagged = !!req.body.flagged;
    ExamAttempt.findById(req.params.id)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
            a.flagged.set(qid, flagged);
            if (flagged) {
                // Flagging clears any selected answer
                a.answers.delete(qid);
            }
            return a.save().then(() => res.json({ ok: true }));
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

// Abandon (expire) an attempt explicitly (used when user exits exam)
app.post('/api/attempts/:id/abandon', requireUser, (req, res) => {
    finalizeAttempt(req.params.id, true)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            res.json({ ok: true });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.post('/api/attempts/:id/submit', requireUser, (req, res) => {
    finalizeAttempt(req.params.id, false)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            res.json({ ok: true });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/attempts/:id/result', requireUser, (req, res) => {
    ExamAttempt.findById(req.params.id)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
            const timeUsed = a.submittedAt ? Math.round((a.submittedAt - a.startedAt) / 1000) : 0;
            ExamTemplate.findById(a.examId).then((tpl) => {
                Question.find({ _id: { $in: a.questionIds } }).then((questions) => {
                    const mapQ = {};
                    questions.forEach((q) => (mapQ[String(q._id)] = q));
                    const items = a.questionIds
                        .map((qid) => {
                            const q = mapQ[String(qid)];
                            if (!q) return null;
                            return { topic: q.topic, options: q.options, correct: q.correct, answer: a.answers.get(String(q._id)) || null };
                        })
                        .filter(Boolean);
                    res.json({
                        scorePct: a.scorePct || 0,
                        correctCount: a.correctCount || 0,
                        total: a.questionIds.length,
                        timeUsedSec: timeUsed,
                        passMark: tpl ? tpl.passMark : 70,
                        pass: !!a.pass,
                        allowReview: tpl ? tpl.allowReview : true,
                        items,
                    });
                });
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* Admin Exam Results APIs (unchanged functional surface) */
app.get('/api/admin/exam-users', requireAdmin, (req, res) => {
    const search = (req.query.search || '').trim();
    ExamAttempt.aggregate([{ $match: { status: 'submitted' } }, { $group: { _id: '$userId', attemptCount: { $sum: 1 } } }])
        .then((rows) => {
            const ids = rows.map((r) => r._id);
            return User.find({ _id: { $in: ids } }).then((users) => {
                const mapCount = {};
                rows.forEach((r) => (mapCount[String(r._id)] = r.attemptCount));
                let list = users.map((u) => ({ id: String(u._id), username: u.username, attemptCount: mapCount[String(u._id)] || 0 }));
                if (search) {
                    const re = new RegExp(escRegex(search), 'i');
                    list = list.filter((x) => re.test(x.username));
                }
                list.sort((a, b) => a.username.localeCompare(b.username));
                res.json({ items: list });
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/admin/user-attempts', requireAdmin, (req, res) => {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: 'userId required' });
    Promise.all([User.findById(userId), ExamAttempt.find({ userId, status: 'submitted' }).sort({ startedAt: -1 })])
        .then(([u, items]) => {
            if (!u) return res.json({ username: null, items: [] });
            const examIds = items.map((a) => a.examId);
            ExamTemplate.find({ _id: { $in: examIds } }).then((templates) => {
                const mapT = {};
                templates.forEach((t) => (mapT[String(t._id)] = t));
                const out = items.map((a) => {
                    const tpl = mapT[String(a.examId)];
                    const timeUsed = a.submittedAt ? Math.round((a.submittedAt - a.startedAt) / 1000) : a.durationSec || 0;
                    return {
                        id: a._id.toString(),
                        examTitle: tpl ? tpl.title : 'Exam',
                        startedAt: a.startedAt,
                        submittedAt: a.submittedAt,
                        status: a.status,
                        scorePct: a.scorePct || 0,
                        correctCount: a.correctCount || 0,
                        total: (a.questionIds || []).length,
                        timeUsedSec: timeUsed,
                        pass: !!a.pass,
                    };
                });
                res.json({ username: u.username, items: out });
            });
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

app.get('/api/admin/attempts/:id/result', requireAdmin, (req, res) => {
    ExamAttempt.findById(req.params.id)
        .then((a) => {
            if (!a) return res.status(404).json({ error: 'Not found' });
            const timeUsed = a.submittedAt ? Math.round((a.submittedAt - a.startedAt) / 1000) : 0;
            Promise.all([ExamTemplate.findById(a.examId), Question.find({ _id: { $in: a.questionIds } }), User.findById(a.userId)]).then(
                ([tpl, questions, user]) => {
                    const mapQ = {};
                    questions.forEach((q) => (mapQ[String(q._id)] = q));
                    const items = a.questionIds
                        .map((qid) => {
                            const q = mapQ[String(qid)];
                            if (!q) return null;
                            return { topic: q.topic, options: q.options, correct: q.correct, answer: a.answers.get(String(q._id)) || null };
                        })
                        .filter(Boolean);
                    res.json({
                        username: user ? user.username : '',
                        scorePct: a.scorePct || 0,
                        correctCount: a.correctCount || 0,
                        total: a.questionIds.length,
                        timeUsedSec: timeUsed,
                        passMark: tpl ? tpl.passMark : 70,
                        pass: !!a.pass,
                        allowReview: true,
                        items,
                    });
                }
            );
        })
        .catch(() => res.status(500).json({ error: 'Server error' }));
});

/* ----- Start server ----- */
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});