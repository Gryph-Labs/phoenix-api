package com.gryphlabs.phoenix.api;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationPropertiesScan;

@ConfigurationPropertiesScan
@SpringBootApplication
public class PhoenixApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(PhoenixApiApplication.class, args);
    }
}
