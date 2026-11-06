// 최소 서비스 워커: 설치 가능하게만 하고, 데이터는 항상 서버에서 받는다
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => self.clients.claim());
self.addEventListener('fetch', e => {});
