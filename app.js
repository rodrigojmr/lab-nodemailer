const { join } = require('path');
const express = require('express');
const logger = require('morgan');
const sassMiddleware = require('node-sass-middleware');

const mongoose = require('mongoose');
const expressSession = require('express-session');
const connectMongo = require('connect-mongo');

const MongoStore = connectMongo(expressSession);

const indexRouter = require('./routes/index');
const authenticationRouter = require('./routes/authentication');
const User = require('./models/user');

const app = express();

app.set('views', join(__dirname, 'views'));
app.set('view engine', 'hbs');

app.use(logger('dev'));
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(
  sassMiddleware({
    src: join(__dirname, 'public'),
    dest: join(__dirname, 'public'),
    outputStyle:
      process.env.NODE_ENV === 'development' ? 'nested' : 'compressed',
    sourceMap: false,
    force: true
  })
);
app.use(express.static(join(__dirname, 'public')));

app.use(
  expressSession({
    secret: process.env.SESSION_SECRET,
    resave: true,
    saveUninitialized: false,
    cookie: {
      maxAge: 60 * 60 * 24 * 15,
      httpOnly: true
    },
    store: new MongoStore({
      mongooseConnection: mongoose.connection,
      ttl: 60 * 60 * 24
    })
  })
);

app.use((req, res, next) => {
  const userId = req.session.user;
  if (userId) {
    User.findById(userId)
      .then(user => {
        req.user = user;
        res.locals.user = req.user;
        next();
      })
      .catch(error => {
        next(error);
      });
  } else {
    next();
  }
});

app.use('/', indexRouter);
app.use('/', authenticationRouter);

app.use('*', (req, res, next) => {
  const error = new Error('Page not found.');
  error.status = 404;
  next(error);
});

app.use((error, req, res, next) => {
  res.status(error.status || 400);
  res.render('error', { error });
});

module.exports = app;
