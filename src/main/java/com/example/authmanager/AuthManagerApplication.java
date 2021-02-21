package com.example.authmanager;

import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.actuate.autoconfigure.security.servlet.EndpointRequest;
import org.springframework.boot.actuate.health.HealthEndpoint;
import org.springframework.boot.actuate.metrics.MetricsEndpoint;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.CsrfConfigurer;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import lombok.extern.slf4j.Slf4j;

@SpringBootApplication
public class AuthManagerApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthManagerApplication.class, args);
    }

}

@EnableWebSecurity
@Configuration
class SecurityConfiguration {

    protected void configureDefaultSecurity(HttpSecurity http, AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver = request -> authenticationManagerBuilder.getObject();
        http.cors(cors -> {})
                .csrf(CsrfConfigurer::disable)
                .authorizeRequests(authorize -> authorize.requestMatchers(EndpointRequest.to(HealthEndpoint.class))
                        .permitAll().requestMatchers(EndpointRequest.to(MetricsEndpoint.class)).hasRole("ADMIN")
                        .anyRequest().authenticated())
                .addFilterBefore(getAuthenticationFilter(authenticationManagerResolver), UsernamePasswordAuthenticationFilter.class);
    }

    @Bean
    InMemoryUserDetailsManager userDetailsManager() {
        InMemoryUserDetailsManager manager = new InMemoryUserDetailsManager();
        manager.createUser(User.withUsername("user").password("{noop}user").roles("USER").build());
        manager.createUser(User.withUsername("admin").password("{noop}admin").roles("ADMIN").build());
        return manager;
    }

    public AuthenticationFilter getAuthenticationFilter(AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) {
        AuthenticationConverter converter = request -> new UsernamePasswordAuthenticationToken(request.getHeader("username"), request.getHeader("password"));
        AuthenticationFilter filter = new AuthenticationFilter(authenticationManagerResolver, converter);
        filter.setRequestMatcher(new AntPathRequestMatcher("/admin-login", "POST"));
        filter.setSuccessHandler((request, response, authentication) -> {});
        return filter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        final CorsConfiguration configuration = new CorsConfiguration();
        configuration.applyPermitDefaultValues();
        configuration.setAllowedOriginPatterns(List.of("*"));
        configuration.setAllowCredentials(true);
        configuration.setAllowedMethods(List.of("GET", "PATCH", "POST", "DELETE", "HEAD"));
        configuration.setExposedHeaders(List.of("X-Auth-Token"));
        final UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    @Bean
    SecurityFilterChain basicFilterChain(HttpSecurity http, AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        configureDefaultSecurity(http, authenticationManagerBuilder);
        return http.httpBasic().and().build();
    }

}

@Slf4j
@RestController
class Controller {

    @GetMapping
    public String hello(@AuthenticationPrincipal User user) {
        return "hello " + user.getUsername() + "!";
    }

    @ResponseStatus(code = HttpStatus.NO_CONTENT)
    @PostMapping("/admin-login")
    public void helloAdmin(@AuthenticationPrincipal User user) {
        log.info("Admin login: {} {}", user.getUsername(), user.getAuthorities());
    }

}