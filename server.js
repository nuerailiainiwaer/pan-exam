var express = require('express');
var session = require('express-session');
var path = require('path');
var bcrypt = require('bcryptjs');
var mongoose = require('mongoose');
var dotenv = require('dotenv');
dotenv.config();

var app = express();
var PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(session({
    secret: process.env.SESSION_SECRET || 'change_me',
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, sameSite: 'lax' }
}));
app.use(express.static(path.join(__dirname, 'public')));

/* ----- Mongo ----- */
var uri = process.env.MONGODB_URI || 'mongodb://localhost:27017/panexamv9';
mongoose.connect(uri, { dbName: 'panexamv9' }).then(function() {
    console.log('MongoDB connected');
    seedAdmin();
    seedDefaultExam();
}).catch(function(err) { console.error('Mongo error:', err); });

/* ----- Schemas ----- */
var UserSchema = new mongoose.Schema({
    username: { type: String, unique: true, required: true, trim: true },
    passwordHash: { type: String, required: true },
    role: { type: String, enum: ['admin', 'user'], required: true, default: 'user' },
    knownQuestionIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Question' }],
    markedQuestionIds: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Question' }]
}, { timestamps: true });

var QuestionSchema = new mongoose.Schema({
    topic: { type: String, required: true, trim: true },
    options: { A: { type: String, required: true }, B: { type: String, required: true }, C: { type: String, required: true }, D: { type: String, required: true } },
    correct: { type: String, enum: ['A', 'B', 'C', 'D'], required: true },
    imageUrl: { type: String }
}, { timestamps: true });

var CaseSchema = new mongoose.Schema({
    text: { type: String, required: true },
    imageUrl: { type: String }
}, { timestamps: true });

var CommentSchema = new mongoose.Schema({
    caseId: { type: mongoose.Schema.Types.ObjectId, ref: 'Case', required: true },
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    username: { type: String, required: true },
    text: { type: String, required: true }
}, { timestamps: true });

var NoteSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    questionId: { type: mongoose.Schema.Types.ObjectId, ref: 'Question', required: true },
    text: { type: String, default: '' }
}, { timestamps: true });

var ExamTemplateSchema = new mongoose.Schema({
    title: String,
    description: String,
    durationMinutes: Number,
    questionCount: Number,
    randomize: { type: Boolean, default: true },
    passMark: { type: Number, default: 70 },
    allowReview: { type: Boolean, default: true }
}, { timestamps: true });

var ExamAttemptSchema = new mongoose.Schema({
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
    pass: Boolean
}, { timestamps: true });

var User = mongoose.model('User', UserSchema);
var Question = mongoose.model('Question', QuestionSchema);
var Case = mongoose.model('Case', CaseSchema);
var Comment = mongoose.model('Comment', CommentSchema);
var Note = mongoose.model('Note', NoteSchema);
var ExamTemplate = mongoose.model('ExamTemplate', ExamTemplateSchema);
var ExamAttempt = mongoose.model('ExamAttempt', ExamAttemptSchema);

/* ----- Seeds ----- */
function seedAdmin() {
    var defU = process.env.DEFAULT_ADMIN_USERNAME || 'aili';
    var defP = process.env.DEFAULT_ADMIN_PASSWORD || 'Nur%123n...';
    var force = process.env.DEFAULT_ADMIN_FORCE_RESET === '1';
    User.findOne({ username: defU }).then(function(u) {
        var hash = bcrypt.hashSync(defP, 10);
        if (!u) {
            return User.create({ username: defU, passwordHash: hash, role: 'admin' })
                .then(function() { console.log('Seeded admin:', defU); });
        } else {
            var updates = {};
            if (u.role !== 'admin') updates.role = 'admin';
            if (force) updates.passwordHash = hash;
            if (Object.keys(updates).length) {
                Object.assign(u, updates);
                return u.save().then(function() {
                    console.log('Updated admin:', defU, '(role' + (updates.passwordHash ? ', password' : '') + ' reset)');
                });
            }
        }
    }).catch(function(e) { console.error('Seed admin error:', e); });
}

function seedDefaultExam() {
    ExamTemplate.findOne({ title: 'Quick 50 (60 min)' }).then(function(t) {
        if (!t) {
            return ExamTemplate.create({
                title: 'Quick 50 (60 min)',
                description: '50 random questions in 60 minutes. Known (green) are excluded.',
                durationMinutes: 60,
                questionCount: 50,
                randomize: true,
                passMark: 70,
                allowReview: true
            }).then(function() { console.log('Seeded default exam template.'); });
        }
    }).catch(function(e) { console.error('Seed default exam error:', e); });
}

/* ----- Helpers ----- */
function requireAdmin(req, res, next) {
    if (req.session && req.session.user && req.session.user.role === 'admin') { return next(); }
    return res.status(401).json({ error: 'Admin login required' });
}

function requireUser(req, res, next) {
    if (req.session && req.session.user && (req.session.user.role === 'admin' || req.session.user.role === 'user')) { return next(); }
    return res.status(401).json({ error: 'User login required' });
}

function escRegex(str) {
    return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function wordsSnippet(t) {
    if (!t) return '';
    var a = t.trim().split(/\s+/).slice(0, 20);
    return a.join(' ');
}

/* ----- Session: who am I ----- */
app.get('/api/me', function(req, res) {
    if (req.session && req.session.user) {
        return res.json({ ok: true, username: req.session.user.username, role: req.session.user.role });
    }
    res.json({ ok: false });
});

/* ----- Admin Auth ----- */
app.post('/api/admin/login', function(req, res) {
    var username = (req.body.username || '').trim();
    var password = String(req.body.password || '');
    User.findOne({ username: username, role: 'admin' }).then(function(u) {
        if (!u) { return res.status(400).json({ error: 'Invalid admin credentials' }); }
        var ok = bcrypt.compareSync(password, u.passwordHash);
        if (!ok) { return res.status(400).json({ error: 'Invalid admin credentials' }); }
        req.session.user = { id: u._id.toString(), username: u.username, role: 'admin' };
        res.json({ ok: true });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- User Auth ----- */
app.post('/api/user/login', function(req, res) {
    var username = (req.body.username || '').trim();
    var password = String(req.body.password || '');
    User.findOne({ username: username }).then(function(u) {
        if (!u) { return res.status(400).json({ error: 'Wrong username or password' }); }
        var ok = bcrypt.compareSync(password, u.passwordHash);
        if (!ok) { return res.status(400).json({ error: 'Wrong username or password' }); }
        req.session.user = { id: u._id.toString(), username: u.username, role: u.role };
        res.json({ ok: true });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.post('/api/logout', function(req, res) { req.session.destroy(function() { res.json({ ok: true }); }); });

/* ----- Admin Stats ----- */
app.get('/api/admin/stats', requireAdmin, function(req, res) {
    Promise.all([
            User.countDocuments({ role: { $in: ['user', 'admin'] } }),
            Question.countDocuments({}),
            Case.countDocuments({}),
            Comment.countDocuments({})
        ]).then(function(arr) { res.json({ userCount: arr[0], questionCount: arr[1], caseCount: arr[2], commentCount: arr[3] }); })
        .catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- Admin Questions ----- */
app.post('/api/admin/questions', requireAdmin, function(req, res) {
    var topic = (req.body.topic || '').trim();
    var imageUrl = (req.body.imageUrl || '').trim();
    var options = req.body.options || {};
    var correct = (req.body.correct || '').trim();
    if (!topic || !options.A || !options.B || !options.C || !options.D || !correct) { return res.status(400).json({ error: 'All fields (except image) required.' }); }
    if (['A', 'B', 'C', 'D'].indexOf(correct) === -1) { return res.status(400).json({ error: 'Correct must be A/B/C/D' }); }
    Question.create({ topic: topic, options: options, correct: correct, imageUrl: imageUrl }).then(function(q) {
        res.json({ ok: true, id: q._id.toString() });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/admin/questions', requireAdmin, function(req, res) {
    var search = (req.query.search || '').trim();
    var q = {};
    if (search) { q.topic = { $regex: new RegExp(escRegex(search), 'i') }; }
    Question.find(q).sort({ topic: 1 }).select({ topic: 1 }).then(function(items) {
        res.json({ items: items.map(function(x) { return { id: x._id.toString(), topic: x.topic }; }) });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.delete('/api/admin/questions/:id', requireAdmin, function(req, res) {
    var id = req.params.id;
    Question.findByIdAndDelete(id).then(function(x) {
        if (!x) { return res.status(404).json({ error: 'Not found' }); }
        // Clean known/marked and notes for this question
        return Promise.all([
            User.updateMany({}, { $pull: { knownQuestionIds: x._id, markedQuestionIds: x._id } }),
            Note.deleteMany({ questionId: x._id })
        ]).then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- Admin Users ----- */
app.post('/api/admin/users', requireAdmin, function(req, res) {
    var username = (req.body.username || '').trim();
    var password = String(req.body.password || '');
    if (!username || !password) { return res.status(400).json({ error: 'Both fields required' }); }
    var hash = bcrypt.hashSync(password, 10);
    User.create({ username: username, passwordHash: hash, role: 'user' }).then(function(u) { res.json({ ok: true, id: u._id.toString() }); })
        .catch(function(e) {
            if (e && e.code === 11000) { return res.status(400).json({ error: 'Username already exists' }); }
            res.status(500).json({ error: 'Server error' });
        });
});

app.get('/api/admin/users', requireAdmin, function(req, res) {
    var search = (req.query.search || '').trim();
    var q = {};
    if (search) { q.username = { $regex: new RegExp(escRegex(search), 'i') }; }
    User.find(q).sort({ username: 1 }).select({ username: 1, role: 1 }).then(function(items) {
        res.json({ items: items.map(function(u) { return { id: u._id.toString(), username: u.username, role: u.role }; }) });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.delete('/api/admin/users/:id', requireAdmin, function(req, res) {
    var id = req.params.id;
    User.findByIdAndDelete(id).then(function(u) {
        if (!u) { return res.status(404).json({ error: 'Not found' }); }
        // Cascade delete notes & comments
        return Promise.all([
            Note.deleteMany({ userId: u._id }),
            Comment.deleteMany({ userId: u._id })
        ]).then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- Admin Cases & Comments ----- */
app.post('/api/admin/cases', requireAdmin, function(req, res) {
    var text = (req.body.text || '').trim();
    var imageUrl = (req.body.imageUrl || '').trim();
    if (!text) { return res.status(400).json({ error: 'Text required' }); }
    Case.create({ text: text, imageUrl: imageUrl }).then(function(c) { res.json({ ok: true, id: c._id.toString() }); })
        .catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/admin/cases', requireAdmin, function(req, res) {
    var search = (req.query.search || '').trim();
    var q = {};
    if (search) { q.text = { $regex: new RegExp(escRegex(search), 'i') }; }
    Case.find(q).sort({ createdAt: -1 }).then(function(items) {
        res.json({ items: items.map(function(c) { return { id: c._id.toString(), snippet: wordsSnippet(c.text) }; }) });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/admin/cases/:id', requireAdmin, function(req, res) {
    Case.findById(req.params.id).then(function(c) {
        if (!c) return res.status(404).json({ error: 'Not found' });
        res.json({ id: c._id.toString(), text: c.text, imageUrl: c.imageUrl });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.delete('/api/admin/cases/:id', requireAdmin, function(req, res) {
    var id = req.params.id;
    Case.findByIdAndDelete(id).then(function(c) {
        if (!c) return res.status(404).json({ error: 'Not found' });
        return Comment.deleteMany({ caseId: c._id }).then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/admin/comments', requireAdmin, function(req, res) {
    var caseId = req.query.caseId;
    var q = {};
    if (caseId) { q.caseId = caseId; }
    Comment.find(q).sort({ createdAt: -1 }).then(function(items) {
        res.json({ items: items.map(function(cm) { return { id: cm._id.toString(), username: cm.username, text: cm.text }; }) });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.delete('/api/admin/comments/:id', requireAdmin, function(req, res) {
    Comment.findByIdAndDelete(req.params.id).then(function(c) {
        if (!c) return res.status(404).json({ error: 'Not found' });
        res.json({ ok: true });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- User: Questions list/search ----- */
app.get('/api/user/questions', requireUser, function(req, res) {
    var search = (req.query.search || '').trim();
    var q = {};
    if (search) { q.topic = { $regex: new RegExp(escRegex(search), 'i') }; }
    Question.find(q).sort({ topic: 1 }).select({ topic: 1 }).then(function(items) {
        var uid = req.session.user.id;
        User.findById(uid).then(function(u) {
            var knownSet = new Set((u.knownQuestionIds || []).map(function(x) { return String(x); }));
            var markedSet = new Set((u.markedQuestionIds || []).map(function(x) { return String(x); }));
            res.json({ items: items.map(function(x) { return { id: x._id.toString(), topic: x.topic, known: knownSet.has(String(x._id)), marked: markedSet.has(String(x._id)) }; }) });
        });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/user/questions/:id', requireUser, function(req, res) {
    var id = req.params.id;
    var uid = req.session.user.id;
    Promise.all([Question.findById(id), User.findById(uid)]).then(function(arr) {
        var q = arr[0],
            u = arr[1];
        if (!q) return res.status(404).json({ error: 'Not found' });
        var known = (u.knownQuestionIds || []).some(function(x) { return String(x) === String(q._id); });
        var marked = (u.markedQuestionIds || []).some(function(x) { return String(x) === String(q._id); });
        res.json({ id: q._id.toString(), topic: q.topic, options: q.options, correct: q.correct, imageUrl: q.imageUrl, known: known, marked: marked });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.post('/api/user/known', requireUser, function(req, res) {
    var qid = req.body.questionId;
    var known = !!req.body.known;
    var uid = req.session.user.id;
    User.findById(uid).then(function(u) {
        if (!u) return res.status(401).json({ error: 'Login' });
        var hasKnown = (u.knownQuestionIds || []).some(function(x) { return String(x) === String(qid); });
        var hasMarked = (u.markedQuestionIds || []).some(function(x) { return String(x) === String(qid); });
        var upd = {};
        if (known && !hasKnown) { upd.$addToSet = { knownQuestionIds: qid }; }
        if (!known && hasKnown) { upd.$pull = Object.assign({}, upd.$pull || {}, { knownQuestionIds: qid }); }
        if (hasMarked && known) { upd.$pull = Object.assign({}, upd.$pull || {}, { markedQuestionIds: qid }); }
        if (Object.keys(upd).length === 0) return res.json({ ok: true });
        User.updateOne({ _id: u._id }, upd).then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.post('/api/user/mark', requireUser, function(req, res) {
    var qid = req.body.questionId;
    var marked = !!req.body.marked;
    var uid = req.session.user.id;
    User.findById(uid).then(function(u) {
        if (!u) return res.status(401).json({ error: 'Login' });
        var hasKnown = (u.knownQuestionIds || []).some(function(x) { return String(x) === String(qid); });
        var hasMarked = (u.markedQuestionIds || []).some(function(x) { return String(x) === String(qid); });
        var upd = {};
        if (marked && !hasMarked) { upd.$addToSet = { markedQuestionIds: qid }; }
        if (!marked && hasMarked) { upd.$pull = Object.assign({}, upd.$pull || {}, { markedQuestionIds: qid }); }
        if (hasKnown && marked) { upd.$pull = Object.assign({}, upd.$pull || {}, { knownQuestionIds: qid }); }
        if (Object.keys(upd).length === 0) return res.json({ ok: true });
        User.updateOne({ _id: u._id }, upd).then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/user/progress', requireUser, function(req, res) {
    var uid = req.session.user.id;
    Promise.all([User.findById(uid).select({ knownQuestionIds: 1 }), Question.countDocuments({})]).then(function(arr) {
        var knownCount = (arr[0].knownQuestionIds || []).length;
        res.json({ knownCount: knownCount, totalQuestions: arr[1] });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- Notes ----- */
app.get('/api/user/notes/:qid', requireUser, function(req, res) {
    Note.findOne({ userId: req.session.user.id, questionId: req.params.qid }).then(function(n) {
        res.json({ text: n ? n.text : '' });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});
app.post('/api/user/notes/:qid', requireUser, function(req, res) {
    var text = String(req.body.text || '');
    Note.findOneAndUpdate({ userId: req.session.user.id, questionId: req.params.qid }, { $set: { text: text } }, { upsert: true, new: true }).then(function() { res.json({ ok: true }); }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- User Cases & Comments ----- */
app.get('/api/user/cases', requireUser, function(req, res) {
    var search = (req.query.search || '').trim();
    var q = {};
    if (search) { q.text = { $regex: new RegExp(escRegex(search), 'i') }; }
    Case.find(q).sort({ createdAt: -1 }).then(function(items) {
        var ids = items.map(function(c) { return c._id; });
        if (ids.length === 0) { return res.json({ items: [] }); }
        Comment.find({ caseId: { $in: ids }, userId: req.session.user.id }).then(function(comments) {
            var set = new Set(comments.map(function(cm) { return String(cm.caseId); }));
            var out = items.map(function(c) {
                return { id: c._id.toString(), snippet: wordsSnippet(c.text), commented: set.has(String(c._id)) };
            });
            res.json({ items: out });
        });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});
app.get('/api/user/cases/:id', requireUser, function(req, res) {
    Case.findById(req.params.id).then(function(c) {
        if (!c) return res.status(404).json({ error: 'Not found' });
        res.json({ id: c._id.toString(), text: c.text, imageUrl: c.imageUrl });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});
app.get('/api/user/cases/:id/comments', requireUser, function(req, res) {
    Comment.find({ caseId: req.params.id }).sort({ createdAt: -1 }).then(function(items) {
        var uid = req.session.user.id;
        res.json({ items: items.map(function(cm) { return { id: cm._id.toString(), username: cm.username, text: cm.text, isOwner: String(cm.userId) === String(uid) }; }) });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});
app.post('/api/user/cases/:id/comments', requireUser, function(req, res) {
    var text = (req.body.text || '').trim();
    if (!text) { return res.status(400).json({ error: 'Text required' }); }
    var u = req.session.user;
    Comment.create({ caseId: req.params.id, userId: u.id, username: u.username, text: text }).then(function() { res.json({ ok: true }); })
        .catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});
app.delete('/api/user/comments/:id', requireUser, function(req, res) {
    Comment.findById(req.params.id).then(function(c) {
        if (!c) return res.status(404).json({ error: 'Not found' });
        if (String(c.userId) !== String(req.session.user.id)) { return res.status(403).json({ error: 'You can only delete your own comment' }); }
        return c.deleteOne().then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- Exam History (User) ----- */
app.get('/api/my-attempts', requireUser, function(req, res) {
    var uid = req.session.user.id;
    ExamAttempt.find({ userId: uid, status: 'submitted' }).sort({ startedAt: -1 })
        .then(function(items) {
            if (!items) items = [];
            var ids = items.map(function(a) { return a.examId; });
            ExamTemplate.find({ _id: { $in: ids } }).then(function(templates) {
                var mapT = {};
                templates.forEach(function(t) { mapT[String(t._id)] = t; });
                var out = items.map(function(a) {
                    var tpl = mapT[String(a.examId)];
                    var timeUsed = a.submittedAt ? Math.round((a.submittedAt - a.startedAt) / 1000) : (a.durationSec || 0);
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
                        pass: !!a.pass
                    };
                });
                res.json({ items: out });
            });
        }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

/* ----- Exams ----- */
function finishIfExpired(attempt) {
    var now = new Date();
    var end = new Date(attempt.startedAt.getTime() + attempt.durationSec * 1000);
    if (attempt.status === 'in_progress' && now > end) {
        // Auto-submit
        return finalizeAttempt(attempt._id, true);
    }
    return Promise.resolve(attempt);
}

function finalizeAttempt(attemptId, markExpired) {
    return ExamAttempt.findById(attemptId).then(function(at) {
        if (!at) return null;
        if (at.status !== 'in_progress' && !markExpired) return at;
        return Question.find({ _id: { $in: at.questionIds } }).then(function(questions) {
            var correctCount = 0;
            var mapQ = {};
            questions.forEach(function(q) { mapQ[String(q._id)] = q; });
            (at.questionIds || []).forEach(function(qid) {
                var q = mapQ[String(qid)];
                if (!q) return;
                var ans = at.answers.get(String(qid));
                if (ans && ans === q.correct) { correctCount++; }
            });
            var score = Math.round(100 * correctCount / (at.questionIds.length || 1));
            return ExamTemplate.findById(at.examId).then(function(tpl) {
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

app.get('/api/exams', requireUser, function(req, res) {
    ExamTemplate.find({}).then(function(templates) {
        res.json({ exams: templates.map(function(t) { return { id: t._id.toString(), title: t.title, questionCount: t.questionCount, durationMinutes: t.durationMinutes, passMark: t.passMark }; }) });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});


app.post('/api/exams/:id/start', requireUser, function(req, res) {
    var uid = req.session.user.id;
    var examId = req.params.id;

    // Expire any lingering in-progress attempts for this user (no resume)
    ExamAttempt.find({ userId: uid, status: 'in_progress' }).then(function(list) {
        var proms = (list || []).map(function(a) { return finalizeAttempt(a._id, true); });
        Promise.all(proms).then(function() { startNew(); });
    }).catch(function() { startNew(); });

    function startNew() {
        ExamTemplate.findById(examId).then(function(tpl) {
            if (!tpl) return res.status(404).json({ error: 'Exam not found' });
            User.findById(uid).then(function(u) {
                var exclude = u.knownQuestionIds || [];
                var match = { _id: { $nin: exclude } };
                var size = tpl.questionCount || 50;
                Question.aggregate([{ $match: match }, { $sample: { size: size } }, { $project: { _id: 1 } }]).then(function(arr) {
                    var ids = arr.map(function(x) { return x._id; });
                    if (ids.length < size) {
                        var remain = size - ids.length;
                        Question.aggregate([{ $sample: { size: remain * 2 } }, { $project: { _id: 1 } }]).then(function(arr2) {
                            var set = new Set(ids.map(String));
                            for (var i = 0; i < arr2.length && ids.length < size; i++) {
                                var id = arr2[i]._id;
                                if (!set.has(String(id))) { ids.push(id);
                                    set.add(String(id)); }
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
        var dur = (tpl.durationMinutes || 60) * 60;
        ExamAttempt.create({
            userId: req.session.user.id,
            examId: tpl._id,
            startedAt: new Date(),
            durationSec: dur,
            questionIds: ids,
            currentIndex: 0,
            answers: {},
            flagged: {}
        }).then(function(a) {
            res.json({ ok: true, attemptId: a._id.toString() });
        }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
    }
});

app.get('/api/attempts/:id/summary', requireUser, function(req, res) {
    ExamAttempt.findById(req.params.id).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
        return finishIfExpired(a).then(function(a2) {
            a = a2 || a;
            var now = new Date();
            var end = new Date(a.startedAt.getTime() + a.durationSec * 1000);
            var rem = Math.max(0, Math.floor((end - now) / 1000));
            var ansMap = {};
            var flagMap = {};
            for (var i = 0; i < a.questionIds.length; i++) {
                var qid = String(a.questionIds[i]);
                if (a.answers.has(qid)) ansMap[i] = true;
                if (a.flagged.get(qid)) flagMap[i] = true;
            }
            res.json({ total: a.questionIds.length, currentIndex: a.currentIndex || 0, questionIds: a.questionIds.map(String), answered: ansMap, flagged: flagMap, remainingSec: rem });
        });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/attempts/:id/q/:index', requireUser, function(req, res) {
    var idx = parseInt(req.params.index, 10) || 0;
    ExamAttempt.findById(req.params.id).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
        if (idx < 0 || idx >= a.questionIds.length) return res.status(400).json({ error: 'Bad index' });
        a.currentIndex = idx;
        a.save();
        var qid = a.questionIds[idx];
        Question.findById(qid).then(function(q) {
            if (!q) return res.status(404).json({ error: 'Question missing' });
            var ch = a.answers.get(String(q._id)) || null;
            var fl = !!a.flagged.get(String(q._id));
            res.json({ id: q._id.toString(), topic: q.topic, options: q.options, imageUrl: q.imageUrl, choice: ch, flagged: fl });
        });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.post('/api/attempts/:id/answer', requireUser, function(req, res) {
    var qid = String(req.body.questionId || '');
    var choice = req.body.choice; // may be null
    ExamAttempt.findById(req.params.id).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
        if (choice === null || choice === undefined || choice === '') {
            a.answers.delete(qid);
        } else {
            if (['A', 'B', 'C', 'D'].indexOf(String(choice)) === -1) return res.status(400).json({ error: 'Bad choice' });
            a.answers.set(qid, String(choice));
        }
        return a.save().then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.post('/api/attempts/:id/flag', requireUser, function(req, res) {
    var qid = String(req.body.questionId || '');
    var flagged = !!req.body.flagged;
    ExamAttempt.findById(req.params.id).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
        a.flagged.set(qid, flagged);
        return a.save().then(function() { res.json({ ok: true }); });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

// Abandon (expire) an attempt explicitly (used when user exits exam)
app.post('/api/attempts/:id/abandon', requireUser, function(req, res) {
    finalizeAttempt(req.params.id, true).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        res.json({ ok: true });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});
app.post('/api/attempts/:id/submit', requireUser, function(req, res) {
    finalizeAttempt(req.params.id, false).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        res.json({ ok: true });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

app.get('/api/attempts/:id/result', requireUser, function(req, res) {
    ExamAttempt.findById(req.params.id).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        if (String(a.userId) !== String(req.session.user.id)) return res.status(403).json({ error: 'Forbidden' });
        var timeUsed = a.submittedAt ? Math.round((a.submittedAt - a.startedAt) / 1000) : 0;
        ExamTemplate.findById(a.examId).then(function(tpl) {
            Question.find({ _id: { $in: a.questionIds } }).then(function(questions) {
                var mapQ = {};
                questions.forEach(function(q) { mapQ[String(q._id)] = q; });
                var items = a.questionIds.map(function(qid) {
                    var q = mapQ[String(qid)];
                    if (!q) return null;
                    return { topic: q.topic, options: q.options, correct: q.correct, answer: a.answers.get(String(q._id)) || null };
                }).filter(function(x) { return !!x; });
                res.json({ scorePct: a.scorePct || 0, correctCount: a.correctCount || 0, total: a.questionIds.length, timeUsedSec: timeUsed, passMark: tpl ? tpl.passMark : 70, pass: !!a.pass, allowReview: tpl ? tpl.allowReview : true, items: items });
            });
        });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});


/* ----- Admin Exam Results APIs ----- */
// List users who have attempts (submitted/expired)
app.get('/api/admin/exam-users', requireAdmin, function(req, res) {
    var search = (req.query.search || '').trim();
    ExamAttempt.aggregate([
        { $match: { status: 'submitted' } },
        { $group: { _id: '$userId', attemptCount: { $sum: 1 } } }
    ]).then(function(rows) {
        var ids = rows.map(function(r) { return r._id; });
        return User.find({ _id: { $in: ids } }).then(function(users) {
            var mapCount = {};
            rows.forEach(function(r) { mapCount[String(r._id)] = r.attemptCount; });
            var list = users.map(function(u) { return { id: String(u._id), username: u.username, attemptCount: mapCount[String(u._id)] || 0 }; });
            if (search) {
                var re = new RegExp(escRegex(search), 'i');
                list = list.filter(function(x) { return re.test(x.username); });
            }
            list.sort(function(a, b) { return a.username.localeCompare(b.username); });
            res.json({ items: list });
        });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

// List a specific user's attempts
app.get('/api/admin/user-attempts', requireAdmin, function(req, res) {
    var userId = req.query.userId;
    if (!userId) { return res.status(400).json({ error: 'userId required' }); }
    Promise.all([User.findById(userId), ExamAttempt.find({ userId: userId, status: 'submitted' }).sort({ startedAt: -1 })])
        .then(function(arr) {
            var u = arr[0],
                items = arr[1] || [];
            if (!u) { return res.json({ username: null, items: [] }); }
            var examIds = items.map(function(a) { return a.examId; });
            ExamTemplate.find({ _id: { $in: examIds } }).then(function(templates) {
                var mapT = {};
                templates.forEach(function(t) { mapT[String(t._id)] = t; });
                var out = items.map(function(a) {
                    var tpl = mapT[String(a.examId)];
                    var timeUsed = a.submittedAt ? Math.round((a.submittedAt - a.startedAt) / 1000) : (a.durationSec || 0);
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
                        pass: !!a.pass
                    };
                });
                res.json({ username: u.username, items: out });
            });
        }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});

// Admin fetch attempt result for review grid (no ownership restriction)
app.get('/api/admin/attempts/:id/result', requireAdmin, function(req, res) {
    ExamAttempt.findById(req.params.id).then(function(a) {
        if (!a) return res.status(404).json({ error: 'Not found' });
        var timeUsed = a.submittedAt ? Math.round((a.submittedAt - a.startedAt) / 1000) : 0;
        Promise.all([ExamTemplate.findById(a.examId), Question.find({ _id: { $in: a.questionIds } }), User.findById(a.userId)]).then(function(arr) {
            var tpl = arr[0] || null,
                questions = arr[1] || [],
                user = arr[2] || null;
            var mapQ = {};
            questions.forEach(function(q) { mapQ[String(q._id)] = q; });
            var items = a.questionIds.map(function(qid) {
                var q = mapQ[String(qid)];
                if (!q) return null;
                return { topic: q.topic, options: q.options, correct: q.correct, answer: a.answers.get(String(q._id)) || null };
            }).filter(function(x) { return !!x; });
            res.json({ username: user ? user.username : '', scorePct: a.scorePct || 0, correctCount: a.correctCount || 0, total: a.questionIds.length, timeUsedSec: timeUsed, passMark: tpl ? tpl.passMark : 70, pass: !!a.pass, allowReview: true, items: items });
        });
    }).catch(function(e) { res.status(500).json({ error: 'Server error' }); });
});


/* ----- Start server ----- */
app.listen(PORT, function() { console.log('Server running on http://localhost:' + PORT); });