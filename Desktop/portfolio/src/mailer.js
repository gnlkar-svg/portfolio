/**
 * Sends the reset link by e-mail when SMTP is configured in .env;
 * otherwise prints it to the server terminal (development mode).
 */
export function createMailer(env = process.env) {
  if (!env.SMTP_HOST) {
    return {
      mode: "console",
      async sendResetLink(to, link) {
        console.log(`\n[şifre sıfırlama] ${to} için bağlantı (30 dk geçerli):\n${link}\n`);
      },
    };
  }
  let transport;
  return {
    mode: "smtp",
    async sendResetLink(to, link) {
      if (!transport) {
        const nodemailer = (await import("nodemailer")).default;
        transport = nodemailer.createTransport({
          host: env.SMTP_HOST,
          port: Number(env.SMTP_PORT || 587),
          secure: Number(env.SMTP_PORT) === 465,
          auth: env.SMTP_USER ? { user: env.SMTP_USER, pass: env.SMTP_PASS } : undefined,
        });
      }
      await transport.sendMail({
        from: env.SMTP_FROM || env.SMTP_USER,
        to,
        subject: "Şifre sıfırlama",
        text:
          "Şifreni sıfırlamak için bu bağlantıyı aç (30 dakika geçerli):\n\n" +
          `${link}\n\nBu isteği sen yapmadıysan bu e-postayı yok sayabilirsin.`,
      });
    },
  };
}
