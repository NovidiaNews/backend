/**
 * Age helpers for Novidia's privacy-first birthday model.
 *
 * The platform stores a user's full date of birth privately. Only a coarse
 * age group is ever exposed publicly (and to advertisers). Age groups match
 * the product spec, normalized so ranges do not overlap at their edges.
 */

export const MIN_AGE_WITHOUT_GUARDIAN = 13;

/** Age in whole years at `now`. */
export function computeAge(birthDate: Date, now: Date = new Date()): number {
  let age = now.getUTCFullYear() - birthDate.getUTCFullYear();
  const m = now.getUTCMonth() - birthDate.getUTCMonth();
  if (m < 0 || (m === 0 && now.getUTCDate() < birthDate.getUTCDate())) {
    age--;
  }
  return age;
}

/** Bucket an age into the advertiser-facing age group. */
export function ageGroupFor(age: number): string {
  if (age < 13) return "under13";
  if (age <= 15) return "13-15";
  if (age <= 18) return "16-18";
  if (age <= 25) return "19-25";
  if (age <= 30) return "26-30";
  if (age <= 39) return "31-39";
  if (age <= 55) return "40-55";
  if (age <= 64) return "56-64";
  if (age <= 74) return "65-74";
  return "75+";
}

/** True when the given birth date makes the user younger than 13. */
export function isUnderAge(birthDate: Date, now: Date = new Date()): boolean {
  return computeAge(birthDate, now) < MIN_AGE_WITHOUT_GUARDIAN;
}
