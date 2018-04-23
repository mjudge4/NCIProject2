//names the current sw cache version to be used
var staticCacheName = 'babiesgrow-static-v4';


//installs the service worker
self.addEventListener('install', function(event) {
    event.waitUntil(
        caches.open(staticCacheName).then(function(cache) {
            return cache.addAll([
                '/',
                '/offerings',
                '/static/js/offerings.js',
                '/static/styles.css'
            ]);
        })
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then(function(cacheNames) {
            return Promise.all(
                cacheNames.filter(function(cacheName) {
                    return cacheName.startsWith('babiesgrow-') &&
                        cacheName != staticCacheName;
                }).map(function(cacheName) {
                    return caches.delete(cacheName);
                })
            );
        })
    );
});

self.addEventListener('fetch', function(event) {
  event.respondWith(
    caches.match(event.request).then(function(response) {
      return response || fetch(event.request);
    })
  );
});



/*
self.addEventListener('fetch', function (event) {
    event.respondWith(
        fetch(event.request).then(function (response) {
            if (response.status === 404) {
                return new Response("Hmmm, page not found");
            }
            return response;
        }).catch(function () {
            return new Response("Whatever you tried to do, it did not work");
        })
    );
});
*/

