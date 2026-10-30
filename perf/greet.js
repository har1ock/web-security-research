import http from 'k6/http';
import { check } from 'k6';

const BASE_URL = __ENV.BASE_URL || 'http://localhost:5001';
const NAMES = ['Alice', 'Bob', 'Guest', 'World'];

export const options = {
  scenarios: {
    greet_load: {
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
  const n = NAMES[Math.floor(Math.random() * NAMES.length)];
  const res = http.get(`${BASE_URL}/greet?name=${encodeURIComponent(n)}`);
  check(res, { 'status 200': (r) => r.status === 200 });
}