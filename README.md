# Koa Mongoose Sanitize
---

[![Build Status][travis-img]][travis-url]
[![Coverage Status][coverage-img]][coverage-url]
[![NPM version][npm-badge]][npm-url]
[![License][license-badge]][license-url]
![Code Size][code-size-badge]

<!-- ***************** -->

[travis-img]: https://travis-ci.org/3imed-jaberi/koa-mongo-sanitize.svg?branch=master
[travis-url]: https://travis-ci.org/3imed-jaberi/koa-mongo-sanitize
[coverage-img]: https://coveralls.io/repos/github/3imed-jaberi/koa-mongo-sanitize/badge.svg?branch=master
[coverage-url]: https://coveralls.io/github/3imed-jaberi/koa-mongo-sanitize?branch=master
[npm-badge]: https://img.shields.io/npm/v/koa-mongo-sanitize.svg?style=flat
[npm-url]: https://www.npmjs.com/package/koa-mongo-sanitize
[license-badge]: https://img.shields.io/badge/license-MIT-green.svg?style=flat-square
[license-url]: https://github.com/3imed-jaberi/koa-mongo-sanitize/blob/master/LICENSE
[code-size-badge]: https://img.shields.io/github/languages/code-size/3imed-jaberi/koa-mongo-sanitize

<!-- ***************** -->

Koa.js middleware which sanitizes user-supplied data to prevent MongoDB Operator Injection.

__Inspired by `mongo-sanitize` and based on the pure logic of `express-mongo-sanitize`.__


## `Installation`

```bash
# npm
$ npm install koa-mongo-sanitize
# yarn
$ yarn add koa-mongo-sanitize
```


## `Usage`

This is a practical example of how to use.

```javascript
const Koa = require('koa');
const Router = require('koa-router');
const bodyParser = require('koa-bodyparser');
const mongoSanitize = require('koa-mongo-sanitize');

const app = new Koa();

app.use(bodyParser());

// To remove data, use:
app.use(mongoSanitize());

// Or, to replace prohibited characters with _, use:
app.use(mongoSanitize({
  replaceWith: '_'
}))
```

## `What?`

This module searches for any keys in objects that begin with a `$` sign or contain a `.`, from `ctx.request.body`, `ctx.request.query` or `ctx.request.params`. It can then either:

- completely remove these keys and associated data from the object, or
- replace the prohibited characters with another allowed character.

The behaviour is governed by the passed option, `replaceWith`. Set this option to have the sanitizer replace the prohibited characters with the character passed in.

See the spec file for more examples.

## `Why?`

Object keys starting with a `$` or containing a `.` are _reserved_ for use by MongoDB as operators. Without this sanitization,  malicious users could send an object containing a `$` operator, or including a `.`, which could change the context of a database operation. Most notorious is the `$where` operator, which can execute arbitrary JavaScript on the database.

The best way to prevent this is to sanitize the received data, and remove any offending keys, or replace the characters with a 'safe' one.

## `Note`

You can use pure mongo sanitize logic.

```javascript
const { sanitize } = require('koa-mongo-sanitize');
// do any think you want.
```


#### License
---

[MIT](LICENSE) &copy;	[Imed Jaberi](https://github.com/3imed-jaberi)
