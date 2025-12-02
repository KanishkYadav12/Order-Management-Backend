import transporter from "../config/emailConfig.js";
const sendEmail = async (recepientEmail, subject, description) => {
  try {
    console.log("email : ", recepientEmail);
    let info = await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to: recepientEmail,
      subject: subject,
      html: description,
    });
  } catch (err) {
    throw err;
  }
};

export default sendEmail;
