'use strict'

const Koa = require('koa')
const Router = require('koa-router')
const bodyParser = require('koa-bodyparser')
const request = require('supertest')
const expect = require('chai').expect

const sanitize = require('.')

describe('Koa Mongo Sanitize', function () {
  describe('Remove Data', function () {
    const app = new Koa()
    const router = new Router()
    app.use(bodyParser())
    app.use(sanitize())

    router.post('/body', function (ctx) {
      ctx.status = 200
      ctx.body = { body: ctx.request.body }
    })

    router.post('/headers', function (ctx) {
      ctx.status = 200
      ctx.body = { headers: ctx.request.headers }
    })

    router.get('/query', function (ctx) {
      ctx.status = 200
      ctx.body = { query: ctx.request.query }
    })

    app.use(router.routes())
    app.use(router.allowedMethods())

    describe('Top-level object', function () {
      it('should sanitize the query string', function (done) {
        request(app.listen())
          .get('/query?q=search&$where=malicious&dotted.data=some_data')
          .set('Accept', 'application/json')
          .expect(200, {
            query: {
              q: 'search'
            }
          }, done)
      })

      it('should sanitize a JSON body', function (done) {
        request(app.listen())
          .post('/body')
          .send({
            q: 'search',
            is: true,
            and: 1,
            even: null,
            stop: undefined,
            $where: 'malicious',
            'dotted.data': 'some_data'
          })
          .set('Content-Type', 'application/json')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              q: 'search',
              is: true,
              and: 1,
              even: null
            }
          }, done)
      })

      it('should sanitize HTTP headers', function (done) {
        request(app.listen())
          .post('/headers')
          .set({
            q: 'search',
            is: true,
            and: 1,
            even: null,
            $where: 'malicious',
            'dotted.data': 'some_data'
          })
          .expect(200)
          .expect(function (res) {
            expect(res.body.headers).to.include({
              q: 'search',
              is: 'true',
              and: '1',
              even: 'null'
            })
          })
          .end(done)
      })

      it('should sanitize a form url-encoded body', function (done) {
        request(app.listen())
          .post('/body')
          .send('q=search&$where=malicious&dotted.data=some_data')
          .set('Content-Type', 'application/x-www-form-urlencoded')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              dotted: {
                data: 'some_data'
              },
              q: 'search'
            }
          }, done)
      })
    })
  })

  describe('Preserve Data', function () {
    const app = new Koa()
    const router = new Router()
    app.use(bodyParser())
    app.use(sanitize({ replaceWith: '_' }))

    router.post('/body', function (ctx) {
      ctx.status = 200
      ctx.body = { body: ctx.request.body }
    })

    router.post('/headers', function (ctx) {
      ctx.status = 200
      ctx.body = { headers: ctx.request.headers }
    })

    router.get('/query', function (ctx) {
      ctx.status = 200
      ctx.body = { query: ctx.request.query }
    })

    app.use(router.routes())
    app.use(router.allowedMethods())

    describe('Top-level object', function () {
      it('should sanitize the query string', function (done) {
        request(app.listen())
          .get('/query?q=search&$where=malicious&dotted.data=some_data')
          .set('Accept', 'application/json')
          .expect(200, {
            query: {
              q: 'search',
              _where: 'malicious',
              dotted_data: 'some_data'
            }
          }, done)
      })

      it('should sanitize a JSON body', function (done) {
        request(app.listen())
          .post('/body')
          .send({
            q: 'search',
            is: true,
            and: 1,
            even: null,
            stop: undefined,
            $where: 'malicious',
            'dotted.data': 'some_data'
          })
          .set('Content-Type', 'application/json')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              q: 'search',
              is: true,
              and: 1,
              even: null,
              _where: 'malicious',
              dotted_data: 'some_data'
            }
          }, done)
      })

      it('should sanitize HTTP headers', function (done) {
        request(app.listen())
          .post('/headers')
          .set({
            q: 'search',
            is: true,
            and: 1,
            even: null,
            $where: 'malicious',
            'dotted.data': 'some_data'
          })
          .expect(function (res) {
            expect(res.body.headers).to.include({
              q: 'search',
              is: 'true',
              and: '1',
              even: 'null',
              _where: 'malicious',
              dotted_data: 'some_data'
            })
          })
          .end(done)
      })

      it('should sanitize a form url-encoded body', function (done) {
        request(app.listen())
          .post('/body')
          .send('q=search&$where=malicious&dotted.data=some_data')
          .set('Content-Type', 'application/x-www-form-urlencoded')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              q: 'search',
              dotted: {
                data: 'some_data'
              },
              _where: 'malicious'
            }
          }, done)
      })
    })

    describe('Nested Object inside one with prohibited chars', function () {
      it('should sanitize a nested object inside one with prohibited chars in a JSON body', function (done) {
        request(app.listen())
          .post('/body')
          .send({
            username: {
              $gt: 'foo',
              'dotted.data': {
                'more.dotted.data': 'some_data'
              }
            }
          })
          .set('Content-Type', 'application/json')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              username: {
                _gt: 'foo',
                dotted_data: {
                  more_dotted_data: 'some_data'
                }
              }
            }
          }, done)
      })
    })

    describe('prototype pollution', function () {
      const createApp = (options) => {
        const app = new Koa()
        const router = new Router()
        app.use(bodyParser())
        app.use(sanitize(options))

        router.post('/body', function (ctx) {
          // should not inject valued
          // eslint-disable-next-line no-unused-expressions
          expect(ctx.request.body.injected).to.be.undefined

          ctx.status = 200
          ctx.body = { body: ctx.request.body }
        })

        app.use(router.routes())
        app.use(router.allowedMethods())

        return app
      }

      it('should not set __proto__ property', function (done) {
        const app = createApp({
          replaceWith: '_'
        })

        request(app.listen())
          .post('/body')
          .send({
            // replace $ with _
            $_proto__: {
              injected: 'injected value'
            },
            query: {
              q: 'search'
            }
          })
          .set('Content-Type', 'application/json')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              query: {
                q: 'search'
              }
            }
          }, done)
      })
      it('should not set constructor property', function (done) {
        const app = createApp({
          replaceWith: 'c'
        })
        request(app.listen())
          .post('/body')
          .send({
            // replace $ with c
            $onstructor: {
              injected: 'injected value'
            },
            query: {
              q: 'search'
            }
          })
          .set('Content-Type', 'application/json')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              query: {
                q: 'search'
              }
            }
          }, done)
      })
      it('should not set prototype property', function (done) {
        const app = createApp({
          replaceWith: 'p'
        })

        request(app.listen())
          .post('/body')
          .send({
            // replace $ with empty p
            $rototype: {
              injected: 'injected value'
            },
            query: {
              q: 'search'
            }
          })
          .set('Content-Type', 'application/json')
          .set('Accept', 'application/json')
          .expect(200, {
            body: {
              query: {
                q: 'search'
              }
            }
          }, done)
      })
    })
  })

  describe('Preserve Data: prohibited characters', function () {
    it('should not allow data to be replaced with a `$`', function (done) {
      const app = new Koa()
      const router = new Router()
      app.use(bodyParser())
      app.use(sanitize({
        replaceWith: '$'
      }))

      router.get('/query', function (ctx) {
        ctx.status = 200
        ctx.body = { query: ctx.request.query }
      })

      app.use(router.routes())
      app.use(router.allowedMethods())

      request(app.listen())
        .get('/query?q=search&$where=malicious&dotted.data=some_data')
        .set('Accept', 'application/json')
        .expect(200, {
          query: {
            q: 'search'
          }
        }, done)
    })

    it('should not allow data to be replaced with a `.`', function (done) {
      const app = new Koa()
      const router = new Router()
      app.use(bodyParser())
      app.use(sanitize({
        replaceWith: '.'
      }))

      router.get('/query', function (ctx) {
        ctx.status = 200
        ctx.body = { query: ctx.request.query }
      })

      app.use(router.routes())
      app.use(router.allowedMethods())

      request(app.listen())
        .get('/query?q=search&$where=malicious&dotted.data=some_data')
        .set('Accept', 'application/json')
        .expect(200, {
          query: {
            q: 'search'
          }
        }, done)
    })
  })
})
