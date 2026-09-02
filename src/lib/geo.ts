import geoip from 'geoip-lite';

export interface GeoResult {
  country: string | null;
  countryCode: string | null;
  region: string | null;
  city: string | null;
  timezone: string | null;
  lat: number | null;
  lon: number | null;
}

const NULL_GEO: GeoResult = { country: null, countryCode: null, region: null, city: null, timezone: null, lat: null, lon: null };
const PRIVATE_RE = /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|fc|fd)/i;

// In-memory cache for ip-api.com results (free tier: 45 req/min)
const geoCache = new Map<string, GeoResult>();
const CACHE_TTL = 24 * 60 * 60 * 1000;
const cacheExpiry = new Map<string, number>();

function cacheSet(ip: string, result: GeoResult) {
  geoCache.set(ip, result);
  cacheExpiry.set(ip, Date.now() + CACHE_TTL);
  // Evict oldest entries if cache grows too large
  if (geoCache.size > 5000) {
    const oldest = [...cacheExpiry.entries()].sort((a, b) => a[1] - b[1]).slice(0, 1000);
    for (const [key] of oldest) { geoCache.delete(key); cacheExpiry.delete(key); }
  }
}

function cacheGet(ip: string): GeoResult | null {
  const cached = geoCache.get(ip);
  if (cached && (cacheExpiry.get(ip) ?? 0) > Date.now()) return cached;
  return null;
}

async function ipApiLookup(ip: string): Promise<GeoResult> {
  const cached = cacheGet(ip);
  if (cached) return cached;
  try {
    const res = await fetch(`http://ip-api.com/json/${ip}?fields=country,countryCode,regionName,city,timezone,lat,lon`, {
      signal: AbortSignal.timeout(3000),
    });
    const data = await res.json();
    if (data.status === 'success') {
      const result: GeoResult = {
        country: data.country || null,
        countryCode: data.countryCode || null,
        region: data.regionName || null,
        city: data.city || null,
        timezone: data.timezone || null,
        lat: data.lat ?? null,
        lon: data.lon ?? null,
      };
      cacheSet(ip, result);
      return result;
    }
  } catch {}
  return NULL_GEO;
}

// Primary: geoip-lite (fast, unlimited, synchronous)
// Fallback: ip-api.com (more accurate for VPNs, rate-limited, cached)
export async function lookupIp(ip: string): Promise<GeoResult> {
  if (PRIVATE_RE.test(ip)) return NULL_GEO;

  const local = geoip.lookup(ip);
  if (local) {
    return {
      country: local.country || null,
      countryCode: local.country || null,
      region: local.region || null,
      city: local.city || null,
      timezone: local.timezone || null,
      lat: local.ll ? local.ll[0] : null,
      lon: local.ll ? local.ll[1] : null,
    };
  }

  // geoip-lite had no result — try ip-api.com (cached)
  return ipApiLookup(ip);
}

export function parseAcceptLanguage(header: string | undefined): { language: string | null; region: string | null } {
  if (!header) return { language: null, region: null };
  const primary = header.split(',')[0]?.trim();
  if (!primary) return { language: null, region: null };
  const parts = primary.split(';')[0].split('-');
  return {
    language: parts[0] || null,
    region: parts[1] || null,
  };
}
