package com.example.authmanager;

import java.util.ArrayList;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class AuthManagerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthManagerApplication.class, args);
	}

}

@EnableWebSecurity
@Configuration
class SecurityConfiguration {

	@Bean
	SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		return http
				.antMatcher("/**")
				.authorizeRequests(authorize -> authorize.anyRequest()
				.authenticated())
				.formLogin()
				.and()
				.build();
	}

	@Bean
	AuthenticationManager authenticationManager(AuthenticationManagerBuilder auth) throws Exception {
		return auth.build();
	}

	@Bean
	UserDetailsService userDetailsService() {
		InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
		manager.createUser(User.withDefaultPasswordEncoder().username("admin").password("admin").authorities(new ArrayList<>()).build());
		return manager;
	}


}

@RestController
class Controller {

	@GetMapping
	public String hello() {
		return "hello!";
	}

}