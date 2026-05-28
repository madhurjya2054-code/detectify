// tests/api.test.js — API Tests
const request = require('supertest');
const app     = require('../server/index');

describe('Health Check', () => {
  test('GET /api/health returns 200', async () => {
    const res = await request(app).get('/api/health');
    expect(res.statusCode).toBe(200);
    expect(res.body.status).toBe('ok');
    expect(res.body.service).toBe('Detectify API v4');
  });
});

describe('Scan Endpoint', () => {
  test('POST /api/scan rejects missing URL', async () => {
    const res = await request(app).post('/api/scan').send({});
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  test('POST /api/scan rejects javascript: scheme', async () => {
    const res = await request(app).post('/api/scan').send({ url: 'javascript:alert(1)' });
    expect(res.statusCode).toBe(400);
    expect(res.body.error).toMatch(/Blocked/);
  });

  test('POST /api/scan rejects data: scheme', async () => {
    const res = await request(app).post('/api/scan').send({ url: 'data:text/html,<h1>test</h1>' });
    expect(res.statusCode).toBe(400);
  });

  test('POST /api/scan rejects URL over 2000 chars', async () => {
    const res = await request(app).post('/api/scan').send({ url: 'https://' + 'a'.repeat(2001) });
    expect(res.statusCode).toBe(400);
  });

  test('POST /api/scan accepts valid URL and returns result', async () => {
    const res = await request(app)
      .post('/api/scan')
      .send({ url: 'https://google.com', localChecks: { localScore: 0, hasHTTPS: true } });
    expect(res.statusCode).toBe(200);
    expect(res.body.finalScore).toBeDefined();
    expect(res.body.verdict).toMatch(/Safe|Suspicious|Phishing/);
  }, 20000);
});

describe('Auth Endpoints', () => {
  test('POST /api/auth/register requires all fields', async () => {
    const res = await request(app).post('/api/auth/register').send({ email: 'test@test.com' });
    expect(res.statusCode).toBe(400);
  });

  test('POST /api/auth/register rejects short password', async () => {
    const res = await request(app).post('/api/auth/register')
      .send({ name: 'Test', email: 'test@test.com', password: '123' });
    expect(res.statusCode).toBe(400);
  });

  test('POST /api/auth/login requires credentials', async () => {
    const res = await request(app).post('/api/auth/login').send({});
    expect(res.statusCode).toBe(400);
  });
});
