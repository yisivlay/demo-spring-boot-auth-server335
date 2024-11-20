package com.dev4sep.base;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@SpringBootApplication
public class DemoAuthServer140Application {

	public static void main(String[] args) {
		SpringApplication.run(DemoAuthServer140Application.class, args);
	}

	@GetMapping("/")
	public String home() {
		return "Hello World";
	}

}
