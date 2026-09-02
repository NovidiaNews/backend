const FREE_EMAIL_PROVIDERS = new Set([
  'gmail.com', 'yahoo.com', 'yahoo.pl', 'outlook.com', 'hotmail.com',
  'wp.pl', 'o2.pl', 'interia.pl', 'onet.pl', 'poczta.onet.pl',
  'protonmail.com', 'proton.me', 'icloud.com', 'aol.com',
  'mail.com', 'zoho.com', 'yandex.com', 'gmx.com', 'tlen.pl',
  'op.pl', 'gazeta.pl', 'fastmail.com', 'tutamail.com',
]);

const KNOWN_SCHOOL_DOMAIN_PATTERNS = [
  /\.edu\.pl$/i,
  /\.szkola\.pl$/i,
  /\.edupage\.org$/i,
  /\.liceum\.pl$/i,
  /\.technikum\.pl$/i,
  /\.sp\d+\.$/i,
  /\.edu\.\w{2}$/i,
  /novidia\.eu$/i,
];

const RSPO_API_BASE = 'https://api-rspo.mein.gov.pl';

function isFreeEmailDomain(domain: string): boolean {
  return FREE_EMAIL_PROVIDERS.has(domain.toLowerCase());
}

function matchesKnownSchoolPattern(domain: string): boolean {
  return KNOWN_SCHOOL_DOMAIN_PATTERNS.some((pattern) => pattern.test(domain));
}

interface RspoInstitution {
  rspoNumber?: string;
  institutionName?: string;
  city?: string;
  address?: string;
  postalCode?: string;
  voivodeship?: string;
  website?: string;
  email?: string;
  phone?: string;
}

async function lookupRspoByDomain(domain: string): Promise<RspoInstitution | null> {
  try {
    const searchUrl = `${RSPO_API_BASE}/api/institution/search?size=10&page=0`;
    const res = await fetch(searchUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ website: domain }),
    });

    if (!res.ok) {
      const searchByName = `${RSPO_API_BASE}/api/institution/search?size=10&page=0`;
      const nameRes = await fetch(searchByName, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: domain.split('.')[0] }),
      });

      if (!nameRes.ok) return null;

      const nameData = await nameRes.json();
      return extractFirstResult(nameData);
    }

    const data = await res.json();
    return extractFirstResult(data);
  } catch {
    return null;
  }
}

function extractFirstResult(data: any): RspoInstitution | null {
  const institutions = data?._embedded?.institution || data?.content || data?.results || data?.data || [];
  if (!institutions.length) return null;

  const inst = institutions[0];
  return {
    rspoNumber: inst.rspoNumber || inst.rspo || inst.id?.toString(),
    institutionName: inst.institutionName || inst.name || inst.schoolName,
    city: inst.city || inst.place || inst.locality,
    address: inst.address || inst.street,
    postalCode: inst.postalCode || inst.zipCode || inst.postcode,
    voivodeship: inst.voivodeship || inst.province || inst.region,
    website: inst.website || inst.url,
    email: inst.email,
    phone: inst.phone || inst.telephone,
  };
}

async function lookupClearbitDomain(domain: string, apiKey?: string): Promise<RspoInstitution | null> {
  if (!apiKey) return null;

  try {
    const res = await fetch(`https://company.clearbit.com/v1/domains/find?domain=${domain}`, {
      headers: { Authorization: `Bearer ${apiKey}` },
    });

    if (!res.ok) return null;

    const data = await res.json();
    if (!data?.name) return null;

    return {
      institutionName: data.name,
      city: data.geo?.city,
      address: data.geo?.streetNumber ? `${data.geo.streetNumber} ${data.geo.streetName}` : undefined,
      postalCode: data.geo?.postalCode,
      website: data.domain ? `https://${data.domain}` : undefined,
      phone: data.phone,
    };
  } catch {
    return null;
  }
}

export interface DomainVerificationResult {
  valid: boolean;
  domain: string;
  isSchoolDomain: boolean;
  rspoData: RspoInstitution | null;
  message: string;
}

export async function verifySchoolDomain(email: string): Promise<DomainVerificationResult> {
  const domain = email.split('@')[1]?.toLowerCase();
  if (!domain) {
    return { valid: false, domain: '', isSchoolDomain: false, rspoData: null, message: 'Nieprawidłowy adres e-mail.' };
  }

  if (isFreeEmailDomain(domain)) {
    return {
      valid: false,
      domain,
      isSchoolDomain: false,
      rspoData: null,
      message: 'Użyj szkolnego adresu e-mail, a nie prywatnego (np. Gmail, WP, O2).',
    };
  }

  let rspoData: RspoInstitution | null = null;
  let isSchoolDomain = matchesKnownSchoolPattern(domain);

  const clearbitKey = process.env.CLEARBIT_API_KEY || '';
  const [rspoResult, clearbitResult] = await Promise.all([
    lookupRspoByDomain(domain),
    lookupClearbitDomain(domain, clearbitKey),
  ]);

  rspoData = rspoResult || clearbitResult;

  if (rspoData) {
    isSchoolDomain = true;
  }

  if (!isSchoolDomain) {
    try {
      const dns = await fetch(`https://dns.google/resolve?name=${domain}&type=MX`);
      if (dns.ok) {
        const dnsData = await dns.json();
        if (dnsData?.Answer?.length > 0) {
          isSchoolDomain = true;
        }
      }
    } catch {}
  }

  if (!isSchoolDomain) {
    return {
      valid: false,
      domain,
      isSchoolDomain: false,
      rspoData: null,
      message: 'Nie rozpoznano domeny szkolnej. Użyj adresu e-mail przypisanego do szkoły.',
    };
  }

  return {
    valid: true,
    domain,
    isSchoolDomain: true,
    rspoData,
    message: 'Domena szkolna zweryfikowana pomyślnie.',
  };
}
