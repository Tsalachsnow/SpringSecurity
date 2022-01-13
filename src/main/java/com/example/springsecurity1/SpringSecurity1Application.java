package com.example.springsecurity1;

import com.example.springsecurity1.JWT.JwtConfig;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.ApplicationContext;

@SpringBootApplication
public class SpringSecurity1Application {

    public static void main(String[] args) {
        ApplicationContext ctx =
        SpringApplication.run(SpringSecurity1Application.class, args);
        ctx.getBean("jwtConfig", JwtConfig.class);
    }
}
