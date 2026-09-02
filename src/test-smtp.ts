import 'dotenv/config';
import nodemailer from 'nodemailer';

async function test() {
  const smtpHost = process.env.SMTP_HOST || '';
  const smtpPort = Number(process.env.SMTP_PORT) || 587;
  const smtpUser = process.env.SMTP_USER || '';
  const smtpPass = process.env.SMTP_PASS || '';
  const smtpFrom = process.env.SMTP_FROM || 'noreply@novidia.eu';

  console.log('Testing SMTP connection with settings:');
  console.log(`Host: ${smtpHost}`);
  console.log(`Port: ${smtpPort}`);
  console.log(`User: ${smtpUser}`);
  console.log(`From: ${smtpFrom}`);
  console.log(`Password length: ${smtpPass.length}`);

  const transporter = nodemailer.createTransport({
    host: smtpHost,
    port: smtpPort,
    secure: smtpPort === 465,
    auth: {
      user: smtpUser,
      pass: smtpPass,
    },
    // Adding timeout and TLS options to debug
    connectionTimeout: 10000,
    greetingTimeout: 10000,
  });

  try {
    console.log('Verifying connection...');
    await transporter.verify();
    console.log('SMTP connection verified successfully!');

    console.log('Sending test email...');
    const info = await transporter.sendMail({
      from: smtpFrom,
      to: smtpUser, // Send to self
      subject: 'Test SMTP Novidia',
      text: 'SMTP is working correctly!',
    });
    console.log('Test email sent successfully! Message ID:', info.messageId);
  } catch (error) {
    console.error('SMTP test failed with error:');
    console.error(error);
  }
}

test();
