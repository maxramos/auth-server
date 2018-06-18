package com.maxaramos.authserver.security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
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
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.ResourceServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;

@Configuration
public class OAuth2ServerConfig {

	@Value("${as.token.signing-key.path}")
	private String signingKeyPath;

	@Value("${as.token.verifier-key.path}")
	private String verifierKeyPath;

	@Bean
	public DefaultTokenServices defaultTokenServices() {
		DefaultTokenServices tokenServices = new DefaultTokenServices();
		tokenServices.setTokenStore(jwtTokenStore());
		tokenServices.setSupportRefreshToken(true);
		return tokenServices;
	}

	@Bean
	public JwtTokenStore jwtTokenStore() {
		return new JwtTokenStore(jwtAccessTokenConverter());
	}

	@Bean
	public JwtAccessTokenConverter jwtAccessTokenConverter() {
		String privateKey = loadKey(signingKeyPath);
		String publicKey = loadKey(verifierKeyPath);

		JwtAccessTokenConverter accessTokenConverter = new JwtAccessTokenConverter();
		accessTokenConverter.setSigningKey(privateKey);
		accessTokenConverter.setVerifierKey(publicKey);
		return accessTokenConverter;
	}

	private String loadKey(String path) {
		InputStream in = getClass().getResourceAsStream(path);

		try (BufferedReader reader = new BufferedReader(new InputStreamReader(in, "utf-8"))) {
			return reader.lines().collect(Collectors.joining());
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}

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

		@Autowired
		private JwtAccessTokenConverter jwtAccessTokenConverter;

		@Autowired
		public JwtTokenStore jwtTokenStore;

		@Autowired
		private DefaultTokenServices defaultTokenServices;

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
			TokenEnhancerChain tokenEnhancerChain = new TokenEnhancerChain();
			tokenEnhancerChain.setTokenEnhancers(Arrays.asList(jwtAccessTokenConverter));

			endpoints
				.authenticationManager(authenticationManager)
				.accessTokenConverter(jwtAccessTokenConverter)
				.tokenEnhancer(tokenEnhancerChain)
				.tokenStore(jwtTokenStore)
				.tokenServices(defaultTokenServices);
		}

		@Override
		public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
			security
				.tokenKeyAccess("permitAll()")
				.checkTokenAccess("hasAuthority('ROLE_CLIENT')");
		}

	}

	@Configuration
	@EnableResourceServer
	@Order(Ordered.HIGHEST_PRECEDENCE)
	public static class ResourceServerConfig extends ResourceServerConfigurerAdapter {

		@Autowired
		private DefaultTokenServices defaultTokenServices;

		@Override
		public void configure(HttpSecurity http) throws Exception {
			http
				.requestMatchers()
					.antMatchers("/api/**")
					.and()
				.authorizeRequests()
					.antMatchers("/api/**").access("#oauth2.hasScope('openid')") // OAuth2SecurityExpressionMethods
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
					.and()
				.csrf().disable();
		}

		@Override
		public void configure(ResourceServerSecurityConfigurer resources) throws Exception {
			resources.tokenServices(defaultTokenServices);
		}

	}

}
