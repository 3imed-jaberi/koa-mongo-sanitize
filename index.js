/*!
 * koa-mongo-sanitize
 *
 * Copyright(c) 2021-2022 imed jaberi (imed-jaberi) <https://www.3imed-jaberi.com>
 * MIT Licensed
 */

'use strict'

/**
 * Module dependencies.
 */
const { sanitize } = require('express-mongo-sanitize')

/**
 * Sanitize your Koa payload to prevent MongoDB operator injection.
 *
 * @api public
 */
function mongoSanitize (options) {
  return async (ctx, next) => {
    for (const key of ['body', 'params', 'headers', 'query', 'search']) {
      if (!ctx.request[key]) continue
      ctx.request[key] = sanitize(ctx.request[key], options)
    }

    await next()
  }
}

/**
 * Expose `mongoSanitize()`.
 */

module.exports = mongoSanitize
module.exports.mongoSanitize = mongoSanitize
module.exports.sanitize = sanitize
