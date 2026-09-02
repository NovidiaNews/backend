import * as argon2 from 'argon2';
import bcrypt from 'bcryptjs';

export async function hashPassword(password: string): Promise<string> {
  return argon2.hash(password);
}

export async function verifyPassword(hash: string, plain: string): Promise<boolean> {
  if (hash.startsWith('$argon2')) {
    try {
      return await argon2.verify(hash, plain);
    } catch (err) {
      return false;
    }
  }

  // Fallback to bcrypt for older records
  try {
    return await bcrypt.compare(plain, hash);
  } catch (err) {
    return false;
  }
}
