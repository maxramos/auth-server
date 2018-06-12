package com.maxaramos.authserver.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableResourceServer;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;

@Configuration
public class OAuth2ServerConfig {

	@Configuration
	@EnableAuthorizationServer
	public static class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

		@Value("${as.security.oauth2.client.registration.examsimulator.client-id}")
		private String clientId;

		@Value("${as.security.oauth2.client.registration.examsimulator.client-secret}")
		private String clientSecret;

		@Value("${as.security.oauth2.client.registration.examsimulator.scope}")
		private String[] scopes;

		@Value("${as.security.oauth2.client.registration.examsimulator.redirect-uri-template}")
		private String redirectUri;

		@Value("${as.security.oauth2.client.registration.examsimulator.authorization-grant-type}")
		private String authorizedGrantType;

		@Autowired
		@Qualifier("authenticationManagerBean")
		private AuthenticationManager authenticationManager;

		@Override
		public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
			clients
				.inMemory()
					.withClient(clientId)
						.secret("{noop}" + clientSecret)
						.scopes(scopes)
						.redirectUris(redirectUri)
						.authorizedGrantTypes(authorizedGrantType)
						.authorities("ROLE_CLIENT")
						.autoApprove(true);
		}

		@Override
		public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
			endpoints.authenticationManager(authenticationManager);
		}

	}

	@Configuration
	@EnableResourceServer
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public static class ResourceServerConfig extends ResourceServerConfigurerAdapter {

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
					.and()
				.requestMatchers()
					.antMatchers("/oauth/token", "/api/**")
					.and()
				.authorizeRequests()
					.antMatchers("/oauth/token", "/api/**").access("#oauth2.hasScope('read')")
					.and()
				.csrf().disable();
		}

	}

}
