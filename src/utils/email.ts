import 'dotenv/config';
import nodemailer from 'nodemailer';

const smtpHost = process.env.SMTP_HOST || '';
const smtpPort = Number(process.env.SMTP_PORT) || 587;
const smtpUser = process.env.SMTP_USER || '';
const smtpPass = process.env.SMTP_PASS || '';
const smtpFrom = process.env.SMTP_FROM || 'noreply@novidia.eu';

// Create a transporter if credentials are provided
let transporter: nodemailer.Transporter | null = null;
if (smtpHost && smtpUser && smtpPass) {
  console.log(`[SMTP] Configuring transporter for host: ${smtpHost}, user: ${smtpUser}`);
  transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpPort === 465, // true for 465, false for other ports
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
  });
} else {
  console.warn(`[SMTP WARNING] SMTP is NOT configured. Missing settings: host="${smtpHost}", user="${smtpUser}", pass="${smtpPass ? '***' : ''}"`);
}

const EMAIL_TEMPLATE = `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="pl">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Novidia</title>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,900&family=Montserrat:wght@400;600&display=swap" rel="stylesheet">

    <style type="text/css">
        /* Client-specific Styles & Reset */
        body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
        table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
        img { -ms-interpolation-mode: bicubic; }
        
        /* Reset */
        img { border: 0; height: auto; line-height: 100%; outline: none; text-decoration: none; }
        table { border-collapse: collapse !important; }
        body { height: 100% !important; margin: 0 !important; padding: 0 !important; width: 100% !important; }

        /* iOS Blue Links Fix */
        a[x-apple-data-detectors] {
            color: inherit !important;
            text-decoration: none !important;
            font-size: inherit !important;
            font-family: inherit !important;
            font-weight: inherit !important;
            line-height: inherit !important;
        }

        /* Webfont enforcement override for clients that support it */
        @media screen {
            .font-header { font-family: 'Fraunces', Georgia, serif !important; }
            .font-body { font-family: 'Montserrat', Helvetica, Arial, sans-serif !important; }
        }

        /* Responsive Styles */
        @media screen and (max-width: 600px) {
            .wrapper { width: 100% !important; max-width: 100% !important; }
            .fluid { width: 100% !important; max-width: 100% !important; display: block !important; }
            .padding-mobile { padding: 24px !important; }
            .footer-mobile { padding: 16px !important; }
            .footer-cell { display: block !important; width: 100% !important; text-align: center !important; padding: 8px 0 !important; }
        }
    </style>
</head>
<body style="background-color: #f4f4f5; margin: 0 !important; padding: 0 !important;">

    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td bgcolor="#f4f4f5" align="center" style="padding: 40px 16px 0px 16px;">
                
                <table border="0" cellpadding="0" cellspacing="0" width="100%" class="wrapper" style="max-width: 576px; background-color: #fafafa; border-radius: 16px; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);">
                    <tr>
                        <td class="padding-mobile" style="padding: 48px;">
                            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                
                                <tr>
                                    <td align="center" class="font-header" style="padding-bottom: 24px; font-family: Georgia, serif; font-size: 40px; font-weight: 900; line-height: 48px; color: #36316A;">
                                        Novidia
                                    </td>
                                </tr>
                                
                                <tr>
                                    <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 32px;">
                                        Aby potwierdzić, że to Ty, wysłaliśmy Ci tę wiadomość e-mail z kodem weryfikacyjnym, który powinieneś wpisać na stronie.
                                    </td>
                                </tr>
                                
                                <tr>
                                    <td align="center" style="padding-bottom: 32px;">
                                        <table border="0" cellpadding="0" cellspacing="0">
                                            <tr>
                                                <td align="center" bgcolor="#e4e4e7" style="border-radius: 8px; padding: 12px 24px; font-family: Courier, monospace; font-size: 28px; font-weight: bold; letter-spacing: 2px; color: #27272a;">
                                                    {{CODE}}
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                                
                                <tr>
                                    <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 32px;">
                                        Ten kod jest ważny przez 15 minut. Jeśli nie próbowałeś się zalogować, zignoruj tę wiadomość.
                                    </td>
                                </tr>
                                
                                <tr>
                                    <td style="border-top: 1px solid #e4e4e7; padding-top: 24px;">
                                        <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                            <tr>
                                                <td class="fluid font-body" align="left" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; color: #52525b; padding-bottom: 12px;">
                                                    Serdeczne pozdrowienia od zespołu Novidia
                                                </td>
                                                <td class="fluid font-body" align="right" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600; padding-bottom: 12px;">
                                                    <a href="https://www.novidia.eu/" target="_blank" style="color: #27272a; text-decoration: none;">Przejdź do Novidii &rarr;</a>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>

                            </table>
                        </td>
                    </tr>
                </table>
                </td>
        </tr>
        
        <tr>
            <td bgcolor="#f4f4f5" align="center" style="padding: 24px 16px 40px 16px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" class="wrapper" style="max-width: 576px; background-color: #36316A; border-radius: 16px; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);">
                    <tr>
                        <td class="footer-mobile" style="padding: 24px 48px;">
                            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                <tr>
                                    <td class="footer-cell font-body" align="center" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600;">
                                        <a href="https://www.novidia.eu/about" target="_blank" style="color: #f4f4f5; text-decoration: none;">O nas &rarr;</a>
                                    </td>
                                    <td class="footer-cell font-body" align="center" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600;">
                                        <a href="https://www.novidia.eu/privacy-policy" target="_blank" style="color: #f4f4f5; text-decoration: none;">Polityka prywatności &rarr;</a>
                                    </td>
                                    <td class="footer-cell font-body" align="center" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600;">
                                        <a href="https://www.novidia.eu/tos" target="_blank" style="color: #f4f4f5; text-decoration: none;">Warunki użytkowania &rarr;</a>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
                </td>
        </tr>
    </table>

</body>
</html>`;

export async function sendVerificationEmail(email: string, code: string): Promise<boolean> {
  const html = EMAIL_TEMPLATE.replace('{{CODE}}', code);
  
  if (!transporter) {
    console.log(`[SMTP SIMULATOR] Mail SMTP not configured. Verification code for ${email} is: ${code}`);
    console.log(`HTML Preview:\n${html.substring(0, 500)}...\n`);
    return true;
  }

  try {
    await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Kod weryfikacyjny - Novidia',
      html: html,
      text: `Twój kod weryfikacyjny to: ${code}. Jest on ważny przez 15 minut.`,
    });
    return true;
  } catch (error) {
    console.error('Error sending verification email via SMTP:', error);
    return false;
  }
}

// ── New-IP verification email ────────────────────────────────────────────────
export async function sendIpVerificationEmail(
  email: string,
  code: string,
  ip: string,
  location?: { city?: string | null; country?: string | null },
): Promise<boolean> {
  const locationStr = [location?.city, location?.country].filter(Boolean).join(', ') || 'Nieznana lokalizacja';
  const html = EMAIL_TEMPLATE.replace('{{CODE}}', code)
    .replace(
      'Ten kod jest ważny przez 15 minut. Jeśli nie próbowałeś się zalogować, zignoruj tę wiadomość.',
      `Wykryto logowanie z nowego adresu IP: <strong>${ip}</strong> (${locationStr}). Ten kod jest ważny przez 15 minut. Jeśli nie próbowałeś się zalogować, zignoruj tę wiadomość.`,
    );

  if (!transporter) {
    console.log(`[SMTP SIMULATOR] New-IP verification code for ${email} is: ${code} (IP: ${ip}, Location: ${locationStr})`);
    return true;
  }

  try {
    await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Nowe urządzenie wykryte - Novidia',
      html,
      text: `Wykryto logowanie z nowego adresu IP: ${ip} (${locationStr}). Twój kod weryfikacyjny to: ${code}. Jest on ważny przez 15 minut.`,
    });
    return true;
  } catch (error) {
    console.error('Error sending IP verification email:', error);
    return false;
  }
}

// ── Account deletion emails ──────────────────────────────────────────────────
const DELETION_EMAIL_TEMPLATE = (bodyHtml: string) => `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" lang="pl">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0"/>
    <title>Novidia</title>
    <link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,900&family=Montserrat:wght@400;600&display=swap" rel="stylesheet">
    <style type="text/css">
        body, table, td, a { -webkit-text-size-adjust: 100%; -ms-text-size-adjust: 100%; }
        table, td { mso-table-lspace: 0pt; mso-table-rspace: 0pt; }
        img { -ms-interpolation-mode: bicubic; }
        img { border: 0; height: auto; line-height: 100%; outline: none; text-decoration: none; }
        table { border-collapse: collapse !important; }
        body { height: 100% !important; margin: 0 !important; padding: 0 !important; width: 100% !important; }
        a[x-apple-data-detectors] { color: inherit !important; text-decoration: none !important; font-size: inherit !important; font-family: inherit !important; font-weight: inherit !important; line-height: inherit !important; }
        @media screen { .font-header { font-family: 'Fraunces', Georgia, serif !important; } .font-body { font-family: 'Montserrat', Helvetica, Arial, sans-serif !important; } }
        @media screen and (max-width: 600px) { .wrapper { width: 100% !important; max-width: 100% !important; } .fluid { width: 100% !important; max-width: 100% !important; display: block !important; } .padding-mobile { padding: 24px !important; } .footer-mobile { padding: 16px !important; } .footer-cell { display: block !important; width: 100% !important; text-align: center !important; padding: 8px 0 !important; } }
    </style>
</head>
<body style="background-color: #f4f4f5; margin: 0 !important; padding: 0 !important;">
    <table border="0" cellpadding="0" cellspacing="0" width="100%">
        <tr>
            <td bgcolor="#f4f4f5" align="center" style="padding: 40px 16px 0px 16px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" class="wrapper" style="max-width: 576px; background-color: #fafafa; border-radius: 16px; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);">
                    <tr>
                        <td class="padding-mobile" style="padding: 48px;">
                            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                <tr>
                                    <td align="center" class="font-header" style="padding-bottom: 24px; font-family: Georgia, serif; font-size: 40px; font-weight: 900; line-height: 48px; color: #36316A;">
                                        Novidia
                                    </td>
                                </tr>
                                ${bodyHtml}
                                <tr>
                                    <td style="border-top: 1px solid #e4e4e7; padding-top: 24px;">
                                        <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                            <tr>
                                                <td class="fluid font-body" align="left" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; color: #52525b; padding-bottom: 12px;">
                                                    Serdeczne pozdrowienia od zespołu Novidia
                                                </td>
                                                <td class="fluid font-body" align="right" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600; padding-bottom: 12px;">
                                                    <a href="https://www.novidia.eu/" target="_blank" style="color: #27272a; text-decoration: none;">Przejdź do Novidii &rarr;</a>
                                                </td>
                                            </tr>
                                        </table>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
        <tr>
            <td bgcolor="#f4f4f5" align="center" style="padding: 24px 16px 40px 16px;">
                <table border="0" cellpadding="0" cellspacing="0" width="100%" class="wrapper" style="max-width: 576px; background-color: #36316A; border-radius: 16px; box-shadow: 0 1px 2px 0 rgba(0, 0, 0, 0.05);">
                    <tr>
                        <td class="footer-mobile" style="padding: 24px 48px;">
                            <table border="0" cellpadding="0" cellspacing="0" width="100%">
                                <tr>
                                    <td class="footer-cell font-body" align="center" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600;">
                                        <a href="https://www.novidia.eu/about" target="_blank" style="color: #f4f4f5; text-decoration: none;">O nas &rarr;</a>
                                    </td>
                                    <td class="footer-cell font-body" align="center" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600;">
                                        <a href="https://www.novidia.eu/privacy-policy" target="_blank" style="color: #f4f4f5; text-decoration: none;">Polityka prywatności &rarr;</a>
                                    </td>
                                    <td class="footer-cell font-body" align="center" style="font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600;">
                                        <a href="https://www.novidia.eu/tos" target="_blank" style="color: #f4f4f5; text-decoration: none;">Warunki użytkowania &rarr;</a>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>`;

function restoreButtonHtml(restoreLink: string): string {
  return `
    <tr>
      <td align="center" style="padding-bottom: 32px;">
        <table border="0" cellpadding="0" cellspacing="0">
          <tr>
            <td align="center" bgcolor="#36316A" style="border-radius: 12px;">
              <a href="${restoreLink}" target="_blank" style="display: inline-block; padding: 14px 32px; font-family: Helvetica, Arial, sans-serif; font-size: 14px; font-weight: 600; color: #ffffff; text-decoration: none;">
                Przywróć konto
              </a>
            </td>
          </tr>
        </table>
      </td>
    </tr>`;
}

export async function sendDeletionRequestedEmail(email: string, restoreLink: string): Promise<boolean> {
  const bodyHtml = `
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 16px;">
        Zleciliśmy usunięcie Twojego konta Novidia. Konto zostanie trwale usunięte za <strong>7 dni</strong>.
      </td>
    </tr>
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 16px;">
        Jeśli zmienisz zdanie, możesz przywrócić konto logując się na nie w ciągu najbliższych 7 dni lub klikając poniższy przycisk.
      </td>
    </tr>
    ${restoreButtonHtml(restoreLink)}
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 32px;">
        Po tym czasie konto i wszystkie powiązane dane zostaną bezpowrotnie usunięte.
      </td>
    </tr>`;

  const html = DELETION_EMAIL_TEMPLATE(bodyHtml);

  if (!transporter) {
    console.log(`[SMTP SIMULATOR] Deletion requested for ${email}. Restore link: ${restoreLink}`);
    return true;
  }

  try {
    await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Usuwanie konta - Novidia',
      html,
      text: `Zleciliśmy usunięcie Twojego konta. Konto zostanie trwale usunięte za 7 dni. Przywróć logując się lub odwiedzając: ${restoreLink}`,
    });
    return true;
  } catch (error) {
    console.error('Error sending deletion email:', error);
    return false;
  }
}

export async function sendDeletionReminderEmail(email: string, restoreLink: string, daysLeft: number): Promise<boolean> {
  const bodyHtml = `
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 16px;">
        Przypominamy, że Twoje konto Novidia zostanie trwale usunięte za <strong>${daysLeft} ${daysLeft === 1 ? 'dzień' : 'dni'}</strong>.
      </td>
    </tr>
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 16px;">
        Jeśli chcesz zachować konto, zaloguj się na nie lub kliknij przycisk poniżej, aby przywrócić dostęp.
      </td>
    </tr>
    ${restoreButtonHtml(restoreLink)}
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 32px;">
        Po upływie tego terminu konto i wszystkie powiązane dane zostaną bezpowrotnie usunięte.
      </td>
    </tr>`;

  const html = DELETION_EMAIL_TEMPLATE(bodyHtml);

  if (!transporter) {
    console.log(`[SMTP SIMULATOR] Deletion reminder for ${email}: ${daysLeft} days left. Restore: ${restoreLink}`);
    return true;
  }

  try {
    await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: `Przypomnienie: konto zostanie usunięte za ${daysLeft} ${daysLeft === 1 ? 'dzień' : 'dni'} - Novidia`,
      html,
      text: `Twoje konto Novidia zostanie trwale usunięte za ${daysLeft} ${daysLeft === 1 ? 'dzień' : 'dni'}. Przywróć logując się lub odwiedzając: ${restoreLink}`,
    });
    return true;
  } catch (error) {
    console.error('Error sending deletion reminder email:', error);
    return false;
  }
}

export async function sendAccountDeletedFinalEmail(email: string): Promise<boolean> {
  const bodyHtml = `
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 16px;">
        Twoje konto Novidia zostało trwale usunięte zgodnie z Twoją prośbą.
      </td>
    </tr>
    <tr>
      <td align="left" class="font-body" style="font-family: Helvetica, Arial, sans-serif; font-size: 16px; font-weight: 400; line-height: 24px; color: #52525b; padding-bottom: 32px;">
        Wszystkie powiązane dane zostały bezpowrotnie usunięte. Jeśli w przyszłości zdecydujesz się wrócić, możesz utworzyć nowe konto na novidia.eu.
      </td>
    </tr>`;

  const html = DELETION_EMAIL_TEMPLATE(bodyHtml);

  if (!transporter) {
    console.log(`[SMTP SIMULATOR] Account permanently deleted: ${email}`);
    return true;
  }

  try {
    await transporter.sendMail({
      from: smtpFrom,
      to: email,
      subject: 'Konto usunięte - Novidia',
      html,
      text: `Twoje konto Novidia zostało trwale usunięte. Wszystkie powiązane dane zostały usunięte.`,
    });
    return true;
  } catch (error) {
    console.error('Error sending final deletion email:', error);
    return false;
  }
}
