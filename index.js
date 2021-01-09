/*!
 * koa-mongo-sanitize
 *
 * Copyright(c) 2021 Imed Jaberi
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 */
const { sanitize } = require('express-mongo-sanitize')

/**
 * Expose `mongoSanitize()`.
 */

module.exports = mongoSanitize
// use directly the santize function
module.exports.sanitize = sanitize

/**
 * Sanitize your Koa payload to prevent MongoDB operator injection.
 *
 * @api public
 */
function mongoSanitize (options) {
  return function (ctx, next) {
    [
      'body',
      'params',
      'headers',
      'query',
      'search'
    ].forEach(function (k) {
      if (ctx.request[k]) {
        ctx.request[k] = sanitize(ctx.request[k], options)
      }
    })

    next()
  }
}
