const { Router } = require('express');
const router = new Router();

const routeGuard = require('./../middleware/route-guard');

const User = require('./../models/user');
const bcryptjs = require('bcryptjs');

const dotenv = require('dotenv');
dotenv.config();

const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  service: 'Gmail',
  auth: {
    user: process.env.NODEMAILER_EMAIL,
    pass: process.env.NODEMAILER_PASSWORD
  }
});

router.get('/', (req, res, next) => {
  res.render('index');
});

router.get('/sign-up', (req, res, next) => {
  res.render('sign-up');
});

router.post('/sign-up', (req, res, next) => {
  let userSignedUp;

  const { name, email, password } = req.body;
  const generateRandomToken = length => {
    const characters =
      '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
    let token = '';
    for (let i = 0; i < length; i++) {
      token += characters[Math.floor(Math.random() * characters.length)];
    }
    return token;
  };
  bcryptjs
    .hash(password, 10)
    .then(hash => {
      return User.create({
        name,
        email,
        passwordHash: hash,
        confirmationToken: generateRandomToken(20)
      });
    })
    .then(user => {
      userSignedUp = user;

      transport
        .sendMail({
          from: process.env.NODEMAILER_EMAIL,
          to: user.email,
          subject: 'Please confirm your new account',
          html:
            '<a href="http://localhost:3000/authentication/confirm-email?token=' +
            user.confirmationToken +
            '">Confirm your email</a>'
        })
        .then(result => {
          console.log('Email was sent');
          console.log(result);
        });
    })
    .then(() => {
      req.session.user = userSignedUp._id;
      res.redirect('/');
    })
    .catch(error => {
      next(error);
    });
});

router.get('/authentication/confirm-email', (req, res, next) => {
  const token = req.query.token;
  User.findOneAndUpdate({ confirmationToken: token }, { status: 'active' })
    .then(user => {
      if (!user) {
        return Promise.reject(
          new Error('Confirmation unsuccessful. Please try again.')
        );
      } else {
        console.log({ user });
        res.render('confirmation', { user: user });
      }
    })
    .catch(error => {
      next(error);
    });
});

router.get('/profile', routeGuard, (req, res, next) => {
  const id = req.session.user;
  User.findById(id).then(user => {
    res.render('profile', { user: user });
  });
});

router.get('/sign-in', (req, res, next) => {
  res.render('sign-in');
});

router.post('/sign-in', (req, res, next) => {
  let userId;
  const { email, password } = req.body;
  User.findOne({ email })
    .then(user => {
      if (!user) {
        return Promise.reject(new Error("There's no user with that email."));
      } else {
        userId = user._id;
        return bcryptjs.compare(password, user.passwordHash);
      }
    })
    .then(result => {
      if (result) {
        req.session.user = userId;
        res.redirect('/');
      } else {
        return Promise.reject(new Error('Wrong password.'));
      }
    })
    .catch(error => {
      next(error);
    });
});

router.post('/sign-out', (req, res, next) => {
  req.session.destroy();
  res.redirect('/');
});

router.get('/private', routeGuard, (req, res, next) => {
  res.render('private');
});

module.exports = router;
