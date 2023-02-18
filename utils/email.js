const nodemailer = require('nodemailer');

const sendEmailToUser = async (options) => {
    // create transporter
    const transporter = nodemailer.createTransport({
        // host: process.env.EMAIL_HOST,
        // port: process.env.EMAIL_PORT,
        // secure: false,
        service: 'gmail',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASSWORD,
        },
    });
    // define option

    const mailOption = {
        from: 'Anamul Haque <anam@gmail.com>',
        to: options.email,
        subject: options.subject,
        text: options.text,
    };
    // finallly send email

    await transporter.sendMail(mailOption);
};

module.exports = sendEmailToUser;
