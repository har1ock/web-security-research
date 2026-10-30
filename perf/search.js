import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5001';

const QUERIES = ['alice', 'bob', 'admin', 'a', ''];

export const options = {
  scenarios: {
    search_load: {
      executor: 'constant-vus',
      vus: 50,
      duration: '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
};

export default function () {
  const q = QUERIES[Math.floor(Math.random() * QUERIES.length)];
  const res = http.get(`${BASE_URL}/search?q=${encodeURIComponent(q)}`);
  check(res, { 'status 200': (r) => r.status === 200 });
}