package com.algaworks.algafood.auth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

	@Autowired
	private PasswordEncoder passwordEncoder;
	
	@Autowired
	private AuthenticationManager authenticationManager;
	
	@Autowired
	private UserDetailsService userDetailsService;
	
	@Override
	public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
		clients
			.inMemory()
				.withClient("algafood-web")
				.secret(passwordEncoder.encode("web123"))
				.authorizedGrantTypes("password","refresh_token")
				.scopes("write", "read")
				.accessTokenValiditySeconds(6 * 60 * 60) // 6 horas (padrão é 12 horas)
				.refreshTokenValiditySeconds(10 * 24 * 60 * 60)//10 dias, padrao é 30 dias
				
				.and()
					.withClient("foodanalytics")
					.secret(passwordEncoder.encode("food123"))
					.authorizedGrantTypes("authorization_code")
					.scopes("write", "read")
					.redirectUris("http://localhost:5501","http://exemplo2-aplicacao-cliente")
				
				.and()
					.withClient("faturamento")
					.secret(passwordEncoder.encode("faturamento123"))
					.authorizedGrantTypes("client_credentials")
					.scopes("read")
					.accessTokenValiditySeconds(6 * 60 * 60) // 6 horas (padrão é 12 horas)
				 
				.and()
				.withClient("webadmin")
				.authorizedGrantTypes("implicit")
				.scopes("write", "read")
				.redirectUris("http://exemplo-aplicacao-cliente")
					
				.and()	
					.withClient("checktoken")//apenas pro resource server fazer a chamada da uri com introspecção
					.secret(passwordEncoder.encode("check123"));
	}
	
	@Override
	public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
		endpoints
		.authenticationManager(authenticationManager)
		.userDetailsService(userDetailsService);
		//.reuseRefreshTokens(false);
	}
	
	@Override
	public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
		//security.checkTokenAccess("isAuthenticated");
		security.checkTokenAccess("permitAll()");
	}
	
}