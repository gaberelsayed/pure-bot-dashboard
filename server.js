const { resolve } = require('path');
const { Client, EvaluatedPermissions } = require('discord.js');
const express = require('express');
const passport = require('passport');
const session = require('express-session');
const MemoryStore = require('memorystore')(session);
const Strategy = require('passport-discord').Strategy;
const url = require('url');
const helmet = require('helmet');
const moment = require('moment');
const client = new Client();
client.login("NTU4MTQ4NTMzNTY0NDczMzUw.XfjlFQ.eRRg7NEHR1MAobDF4xJ4-jqRmTo")

const app = express();
app.set('view engine', 'ejs');
app.use(express.static(resolve(__dirname, 'public')));
app.set('views', __dirname);

app.get('/support', (req, res) => {
	res.redirect('https://discord.gg/');
});
passport.serializeUser((user, done) => {
	done(null, user);
});
passport.deserializeUser((obj, done) => {
	done(null, obj);
});

passport.use(new Strategy({
	clientID: '656801153547370496',
	clientSecret: 'MhzNEeNAAfX44JTFaVyS3n7Zx_GBSC_u',
	callbackURL: 'https://pure-dashboard.glitch.me/auth',
	scope: ['identify', 'guilds', 'guilds.join']
},
(accessToken, refreshToken, profile, done) => {
	process.nextTick(() => done(null, profile));
}));
app.use(session({
	store: new MemoryStore({
		checkPeriod: 86400000
	}),
	secret: 'clientsessiosPuresecret123123123',
	resave: false,
	saveUninitialized: false
}));
app.use(passport.initialize());
app.use(passport.session());
app.use(helmet());
app.locals.domain = 'pure-dashboard.glitch.me';
const bodyParser = require('body-parser');
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({
	extended: true
}));
function checkAuth(req, res, next) {
	if (req.isAuthenticated()) return next();
	req.session.backURL = req.url;
	res.redirect('/login');
}
app.get('/login', (req, res, next) => {
	if (req.session.backURL) {
		req.session.backURL = 'https://pure-dashboard.glitch.me/auth';
	} else if (req.headers.referer) {
		const parsed = url.parse(req.headers.referer);
		if (parsed.hostname === app.locals.domain) {
			req.session.backURL = parsed.path;
		}
	} else {
		req.session.backURL = '/dashboard';
	}
	next();
},
passport.authenticate('discord'));
app.get('/auth', passport.authenticate('discord', {
	failureRedirect: '/autherror'
}), (req, res) => {
	if (req.session.backURL) {
		const refurl = req.session.backURL;
		req.session.backURL = null;
		res.redirect(refurl);
	} else {
		res.redirect('/dashboard');
	}
});

app.get('/leaderboard/servers', (req, res) => {
	const bot = client;
	const user = req.isAuthenticated() ? req.user : null;
	res.render('views/pages/gleaders', {
		bot, user
	});
});

app.get('/leaderboard/servers/2', (req, res) => {
	const bot = client;
	const user = req.isAuthenticated() ? req.user : null;
	res.render('views/pages/gleaders2', {
		bot, user
	});
});

app.get('/leaderboard/servers/3', (req, res) => {
	const bot = client;
	const user = req.isAuthenticated() ? req.user : null;
	res.render('views/pages/gleaders3', {
		bot, user
	});
});

app.post('/guilds/:guildID/manage', checkAuth, (req, res) => {
	const guild = client.guilds.get(req.params.guildID);
	if (!guild) return res.status(404);
	const isManaged = guild && Boolean(guild.member(req.user.id)) ? guild.member(req.user.id).permissions.has('MANAGE_GUILD') : false;
	if (!isManaged && !req.session.isAdmin) res.redirect('/');
	// client.writeSettings(guild.id, req.body);
	res.redirect(`/guilds/${req.params.guildID}/manage`);
});



app.get('/logout', (req, res) => {
	req.session.destroy(() => {
		req.logout();
		res.redirect('/');
	});
});

app.get('/', (req, res) => {
	const guildCount = client.guilds.size;
	const usersCount = client.users.size;
	const bot = client;
	const user = req.isAuthenticated() ? req.user : null;
	const useradmin = req.session.isAdmin;
	res.render('views/pages/index', {
		guildCount, usersCount, bot, user, useradmin
	});
});

app.get('/dashboard', checkAuth, (req, res) => {
	const user = req.isAuthenticated() ? req.user : null;
	const botStats = [{
		botty: client,
		perms: EvaluatedPermissions,
		user: req.isAuthenticated() ? req.user : null
	}];
	res.render('views/pages/dashboard', {
		bot: botStats, user
	});
});

app.get('/guilds/:guildID/manags', checkAuth, (req, res) => {
	const guild = client.guilds.get(req.params.guildID);
	if (!guild) return res.status(404);
const server = guild;
	const isManaged = guild && Boolean(guild.member(req.user.id)) ? guild.member(req.user.id).permissions.has('MANAGE_GUILD') : false;
	if (!isManaged && !req.session.isAdmin) res.redirect('/');
	const groles = app.get(`https://discordapp.com/api/v6/guilds/${req.params.guildID}/roles`);
	const user = req.isAuthenticated() ? req.user : null;
	const botStats = [{
		bot: client,
		perms: EvaluatedPermissions,
		moment,
		guildroles: groles
	}];
	res.render('views/guild/manage.ejs', {
		guild,
		server,
		user,
		bot: botStats
	});
});
app.get('/commands', (req, res) => {
	const bot = client;
	const user = req.isAuthenticated() ? req.user : null;
	const useradmin = req.session.isAdmin;
	res.render('views/pages/commands', {
	bot, user, useradmin
	});
});

app.get('/subscriptions', (req, res) => {
	const bot = client;
	const user = req.isAuthenticated() ? req.user : null;
	const useradmin = req.session.isAdmin;
	res.render('views/pages/subscriptions', {
	bot, user, useradmin
	});
});
app.get('/invite', (req, res) => {
	res.redirect(`https://discordapp.com/api/oauth2/authorize?client_id=${client.user.id}&permissions=8&scope=bot`);
});

app.listen(3000);

app.get('*', (req, res) => {
	if (res.status(404)) {
		const bot = client;
		const user = req.isAuthenticated() ? req.user : null;
		res.render('views/errors/notfound.ejs', {
			bot, user
		});
	}
});
