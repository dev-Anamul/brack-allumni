/* eslint-disable class-methods-use-this */
const nodemailer = require('nodemailer');
const pug = require('pug');
const htmlToText = require('html-to-text');

module.exports = class Email {
    constructor(user, url) {
        this.user = user;
        this.to = user.email;
        this.firstName = user.firstName;
        this.url = url;
        this.from = `Anamul Haque <${process.env.EMAIL_FROM}>`;
    }

    newTransport() {
        return nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL_USER,
                pass: process.env.EMAIL_PASSWORD,
            },
        });
    }

    // send the actual email
    async send(template, subject) {
        // 1) render html based on a pug template
        const html = pug.renderFile(`${__dirname}/../view/${template}.pug`, {
            firstName: this.firstName,
            url: this.url,
            user: this.user,
            subject,
        });

        // 2) define email options
        const mailOptions = {
            from: this.from,
            to: this.to,
            subject,
            html,
            text: htmlToText.convert(html),
        };

        // 3) create a transport and send email
        await this.newTransport().sendMail(mailOptions);
    }

    async sendWelcome() {
        await this.send('welcome', 'Welcome to BRAC Allumni Association');
    }

    async sendPasswordReset() {
        await this.send('passwordReset', 'Your password reset token (valid for only 10 minutes)');
    }

    async sendApproval() {
        await this.send('approval', 'ACCOUNT APPROVAL');
    }
};

// https://github.com/leemunroe/responsive-html-email-template
// https://html2pug.now.sh/
