declare module 'geoip-lite' {
  interface GeoIpLookup {
    range: [number, number];
    country: string;
    region: string;
    city: string;
    ll: [number, number];
    metro: number;
    zip: string;
    timezone: string;
    eu: string;
    area: number;
  }
  function lookup(ip: string): GeoIpLookup | null;
}
