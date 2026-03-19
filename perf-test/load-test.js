import http from 'k6/http';
import { check, sleep } from 'k6';

// Read configuration from environment variables
const VUS = parseInt(__ENV.VUS || '20');
const DURATION = __ENV.DURATION || '2m';
const SLEEP_DELAY = parseFloat(__ENV.SLEEP || '0.5');

// File specific configuration
const FILES_COUNT = parseInt(__ENV.FILES_COUNT || '10');
const MIN_SIZE = parseInt(__ENV.MIN_SIZE || '1');
const MAX_SIZE = parseInt(__ENV.MAX_SIZE || '100');

export const options = {
  stages: [
    { duration: '10s', target: VUS },
    { duration: DURATION, target: VUS },
    { duration: '10s', target: 0 },
  ],
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<120000'], 
  },
};

const BASE_URL = 'http://localhost:8000';

// Loading binary data source
const DATA_SOURCE = open('./test_data.bin', 'b');

function getRandomSize(minMb, maxMb) {
    return Math.floor(Math.random() * (maxMb - minMb + 1) + minMb) * 1024 * 1024;
}

function shuffle(array) {
    let currentIndex = array.length,  randomIndex;
    while (currentIndex != 0) {
      randomIndex = Math.floor(Math.random() * currentIndex);
      currentIndex--;
      [array[currentIndex], array[randomIndex]] = [array[randomIndex], array[currentIndex]];
    }
    return array;
}

export default function () {
  const username = `user_${__VU}`;
  const password = 'TestPassword123!@#Stronger';

  // 1. Login
  const loginRes = http.post(`${BASE_URL}/session/create`, JSON.stringify({
    username: username,
    password: password,
  }), { headers: { 'Content-Type': 'application/json' } });

  check(loginRes, { 'auth successful': (r) => r.status === 204 });
  if (loginRes.status !== 204) return;

  // Generate file list
  let fileConfigs = [];
  for (let i = 0; i < FILES_COUNT; i++) {
    fileConfigs.push({
      name: `perf_${__VU}_file_${i}_${Math.floor(Math.random() * 10000)}.bin`,
      size: getRandomSize(MIN_SIZE, MAX_SIZE)
    });
  }

  // 2. Upload Phase (Randomized Order)
  let uploadQueue = shuffle([...fileConfigs]);
  uploadQueue.forEach(file => {
    const data = DATA_SOURCE.slice(0, file.size);
    const res = http.put(`${BASE_URL}/file/${file.name}`, data, {
      headers: { 'Content-Type': 'application/octet-stream' },
      timeout: '180s',
    });
    check(res, { [`upload ok`]: (r) => r.status === 201 });
  });

  // 3. Download Phase (Randomized Order)
  let downloadQueue = shuffle([...fileConfigs]);
  downloadQueue.forEach(file => {
    const res = http.get(`${BASE_URL}/file/${file.name}`, { 
      timeout: '180s',
      responseType: 'binary' 
    });
    check(res, { 
        [`download ok`]: (r) => r.status === 200,
        // Verification: ArrayBuffer has byteLength
        [`content size correct`]: (r) => (r.body && r.body.byteLength) === file.size
    });
  });

  // 4. Cleanup Phase
  fileConfigs.forEach(file => {
    const res = http.del(`${BASE_URL}/file/${file.name}`);
    check(res, { [`delete ok`]: (r) => r.status === 204 });
  });

  sleep(SLEEP_DELAY);
}
