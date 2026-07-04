import http from 'k6/http';
import { check, sleep, group } from 'k6';
import { Trend, Rate, Counter } from 'k6/metrics';

// Custom Metrics for deep insights
const uploadTime = new Trend('upload_time');
const downloadTime = new Trend('download_time');
const loginTime = new Trend('login_time');
const deleteTime = new Trend('delete_time');

const uploadSuccessRate = new Rate('upload_success_rate');
const downloadSuccessRate = new Rate('download_success_rate');

const totalDataUploaded = new Counter('total_data_uploaded');
const totalDataDownloaded = new Counter('total_data_downloaded');

// Read configuration from environment variables
const VUS = parseInt(__ENV.VUS || '20');
const DURATION = __ENV.DURATION || '2m';
const SLEEP_DELAY = parseFloat(__ENV.SLEEP || '0.5');
const UPLOAD_MODE = __ENV.UPLOAD_MODE || 'chunked'; // 'stream' or 'chunked'

// File specific configuration
const FILES_COUNT = parseInt(__ENV.FILES_COUNT || '10');
const MIN_SIZE = parseInt(__ENV.MIN_SIZE || '1');
const MAX_SIZE = parseInt(__ENV.MAX_SIZE || '100');
const REQUEST_CHUNK_SIZE = 1024 * 1024; // 1MB chunks for chunked upload

export const options = {
  stages: [
    { duration: '30s', target: VUS }, // Ramp up
    { duration: DURATION, target: VUS }, // Steady state
    { duration: '30s', target: 0 }, // Ramp down
  ],
  thresholds: {
    http_req_failed: ['rate<0.05'],
    http_req_duration: ['p(95)<120000'],
    upload_success_rate: ['rate>0.95'],
    download_success_rate: ['rate>0.95'],
  },
};

const BASE_URL = 'http://localhost:8000';

// Loading binary data source
const DATA_SOURCE = open('./test_data.bin', 'b');

function getRandomSize(minMb, maxMb) {
  return Math.floor(Math.random() * (maxMb - minMb + 1) + minMb) * 1024 * 1024;
}

function shuffle(array) {
  let currentIndex = array.length, randomIndex;
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

  let loggedIn = false;

  group('1. Authentication Phase', function () {
    const startTime = Date.now();
    const loginRes = http.post(`${BASE_URL}/session`, JSON.stringify({
      username: username,
      password: password,
    }), { headers: { 'Content-Type': 'application/json' }, tags: { name: 'Login' } });

    loginTime.add(Date.now() - startTime);
    loggedIn = check(loginRes, { 'auth successful': (r) => r.status === 201 });
  });

  if (!loggedIn) return;

  // Generate file list for the user
  let fileConfigs = [];
  for (let i = 0; i < FILES_COUNT; i++) {
    fileConfigs.push({
      name: `perf_${__VU}_file_${i}_${Math.floor(Math.random() * 10000)}.bin`,
      size: getRandomSize(MIN_SIZE, MAX_SIZE)
    });
  }

  group('2. Upload Phase', function () {
    let uploadQueue = shuffle([...fileConfigs]);
    uploadQueue.forEach(file => {
      const startTime = Date.now();

      if (UPLOAD_MODE === 'stream') {
        const data = DATA_SOURCE.slice(0, file.size);
        const res = http.put(`${BASE_URL}/file/${file.name}`, data, {
          headers: { 'Content-Type': 'application/octet-stream' },
          timeout: '180s',
          tags: { name: 'UploadFileStream' }
        });
        
        const success = check(res, { [`stream upload ok`]: (r) => r.status === 201 });
        uploadSuccessRate.add(success);
        if (success) {
          totalDataUploaded.add(file.size);
        }
      } else {
        // Chunked upload
        const initRes = http.post(`${BASE_URL}/file/upload/initiate/${file.name}`, null, {
          tags: { name: 'UploadInit' }
        });
        
        if (initRes.status !== 200) {
          check(initRes, { [`initiate chunked upload ok`]: (r) => r.status === 200 });
          uploadSuccessRate.add(0);
          uploadTime.add(Date.now() - startTime);
          return;
        }

        const uploadId = initRes.json('upload_id');
        let offset = 0;
        let chunkedSuccess = true;

        while (offset < file.size) {
          const end = Math.min(offset + REQUEST_CHUNK_SIZE, file.size);
          const chunkData = DATA_SOURCE.slice(offset, end);
          
          const chunkRes = http.put(`${BASE_URL}/file/upload/chunk/${uploadId}?offset=${offset}`, chunkData, {
            headers: { 'Content-Type': 'application/octet-stream' },
            timeout: '180s',
            tags: { name: 'UploadChunk' }
          });
          
          if (chunkRes.status !== 204) {
            chunkedSuccess = false;
            break;
          }
          offset += (end - offset);
        }

        if (chunkedSuccess) {
          const finalizeRes = http.post(`${BASE_URL}/file/upload/finalize/${uploadId}?total_size=${file.size}`, null, {
            tags: { name: 'UploadFinalize' }
          });
          const success = check(finalizeRes, { [`finalize chunked upload ok`]: (r) => r.status === 201 });
          uploadSuccessRate.add(success);
          if (success) {
            totalDataUploaded.add(file.size);
          }
        } else {
          check({ status: 500 }, { [`chunk upload ok`]: (r) => false });
          uploadSuccessRate.add(0);
        }
      }
      
      uploadTime.add(Date.now() - startTime);
    });
  });

  group('3. Download Phase', function () {
    let downloadQueue = shuffle([...fileConfigs]);
    downloadQueue.forEach(file => {
      // Full Download
      const startTime = Date.now();
      const res = http.get(`${BASE_URL}/file/${file.name}`, {
        timeout: '180s',
        responseType: 'binary',
        tags: { name: 'DownloadFile' }
      });
      downloadTime.add(Date.now() - startTime);

      const success = check(res, {
        [`download ok`]: (r) => r.status === 200,
        [`content size correct`]: (r) => (r.body && r.body.byteLength) === file.size
      });
      downloadSuccessRate.add(success);
      if (success) {
        totalDataDownloaded.add(file.size);
      }

      // Range Download (First 1MB)
      if (file.size > 1024 * 1024) {
        const rangeRes = http.get(`${BASE_URL}/file/${file.name}`, {
          headers: { 'Range': 'bytes=0-1048575' },
          timeout: '180s',
          responseType: 'binary',
          tags: { name: 'DownloadRange' }
        });
        check(rangeRes, {
          [`range download ok`]: (r) => r.status === 206,
          [`range content size correct`]: (r) => (r.body && r.body.byteLength) === 1048576
        });
      }
    });
  });

  group('4. Cleanup Phase', function () {
    fileConfigs.forEach(file => {
      const startTime = Date.now();
      const res = http.del(`${BASE_URL}/file/${file.name}`, null, { tags: { name: 'DeleteFile' } });
      deleteTime.add(Date.now() - startTime);
      check(res, { [`delete ok`]: (r) => r.status === 204 });
    });
  });

  sleep(SLEEP_DELAY);
}
