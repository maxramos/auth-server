package com.maxaramos.authserver.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.User.UserBuilder;

@EnableWebSecurity(debug = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	@Value("${spring.security.user.name}")
	private String username;

	@Value("${spring.security.user.password}")
	private String password;

	@Value("${spring.security.user.roles}")
	private String[] roles;

	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		@SuppressWarnings("deprecation")
		UserBuilder userBuilder = User.withDefaultPasswordEncoder();
		auth.inMemoryAuthentication()
			.withUser(userBuilder.username(username).password(password).roles(roles).build());
	}

	@Bean
	@Override
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
//		AuthorizationEndpoint
//		TokenEndpoint
//		OAuth2AuthenticationProcessingFilter
//		AuthorizationCodeTokenGranter
		http
			.requestMatchers()
				.antMatchers("/", "/login", "/oauth/authorize", "/oauth/confirm_access", "/oauth/error")
				.and()
			.authorizeRequests()
				.antMatchers("/oauth/error").permitAll()
				.antMatchers("/", "/oauth/authorize", "/oauth/confirm_access").authenticated()
				.and()
			.formLogin()
				.loginPage("/login").permitAll()
				.and()
			.csrf().disable();
	}

}
