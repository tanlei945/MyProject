package org.benben.modules.business.commen.service.impl;

import org.benben.common.util.RedisUtil;
import org.benben.modules.business.commen.service.IEmailServe;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.util.Properties;
import java.util.Random;

@Service
public class EmailServeImpl implements IEmailServe {

    @Value("${mail.username}")
    private String username;
    @Value("${mail.password}")
    private String password;

    @Autowired
    private RedisUtil redisUtil;

    @Override
    public Boolean offerCaptcha(String email, String event) {
        String captcha = this.getRandomNum();
        try {
            this.send_email(email, captcha);
            redisUtil.set(email + ":" + event,captcha,120);
            return true;
        } catch (Exception e) {
            e.printStackTrace();
            return false;
        }
    }

    public void send_email(String email, String code) throws Exception {
        //创建连接对象 连接到邮件服务器
        Properties properties = new Properties();
        //设置发送邮件的基本参数
        //发送邮件服务器
        String hostname = "";
        if (email.contains("@qq")) {
            hostname = "smtp.qq.com";
        } else if (email.contains("@163")) {
            hostname = "smtp.163.com";
        }
        properties.put("mail.smtp.host", hostname);
        //发送端口
        properties.put("mail.smtp.port", "25");
        properties.put("mail.smtp.auth", "true");
        //设置发送邮件的账号和密码
        Session session = Session.getInstance(properties, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                //两个参数分别是发送邮件的账户和密码
                return new PasswordAuthentication(username, password);
            }
        });
        //创建邮件对象
        Message message = new MimeMessage(session);
        //设置发件人
        message.setFrom(new InternetAddress(username));
        //设置收件人
        message.setRecipient(Message.RecipientType.TO, new InternetAddress(email));
        // 设置抄送人(抄送自己)
        message.setRecipients(Message.RecipientType.CC, InternetAddress.parse(password));
        //设置主题
        message.setSubject("来自程序员的愤怒");
        //设置邮件正文  第二个参数是邮件发送的类型
        message.setContent("本次验证码为" + code + "，有效时间2分钟，请及时处理", "text/html;charset=UTF-8");
        //发送一封邮件
        Transport.send(message);
    }

    public static String getRandomNum() {
        String str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        StringBuilder sb = new StringBuilder(4);
        for (int i = 0; i < 6; i++) {
            char ch = str.charAt(new Random().nextInt(str.length()));
            sb.append(ch);
        }
        return sb.toString();
    }


}
