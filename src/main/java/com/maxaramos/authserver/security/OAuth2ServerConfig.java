package com.maxaramos.authserver.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;

@Configuration
@EnableAuthorizationServer
public class OAuth2ServerConfig extends AuthorizationServerConfigurerAdapter {

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

	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient(clientId)
					.secret(clientSecret)
					.scopes(scopes)
					.redirectUris(redirectUri)
					.authorizedGrantTypes(authorizedGrantType)
					.authorities("ROLE_CLIENT");

	}

}
