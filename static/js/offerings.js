//https://developer.mozilla.org/en-US/docs/Web/API/ServiceWorkerRegistration

 if ('serviceWorker' in navigator) {
  // Register a service worker hosted at the root of the
  // site using a more restrictive scope.
  navigator.serviceWorker.register('../sw.js').then(function() {
    console.log('Service worker registration succeeded:');
  }).catch(function() {
    console.log('Service worker registration failed:');
  });
} else {
  console.log('Service workers are not supported.');
}


