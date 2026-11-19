const routes = { settings: () => import("./Settings-9c1d.js") };
export function track(evt) { navigator.sendBeacon("https://telemetry.acme-cdn.com/v1/collect?app=dash&evt=" + evt); }
export default routes;
