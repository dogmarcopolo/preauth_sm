package com.jfwang.preauth_sm;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationProvider;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.preauth.RequestHeaderAuthenticationFilter;

@Configuration
@EnableWebSecurity
// @EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

	/*
	 * @Autowired private OAuth2UserService<OidcUserRequest, OidcUser>
	 * oidcUserService;
	 */
	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http.addFilterAfter(siteminderFilter(), RequestHeaderAuthenticationFilter.class)
			.authorizeRequests()
			.antMatchers("/", "/Token").permitAll()
			.antMatchers("/admin/**").hasRole("ADMIN")
			.antMatchers("/user/**").hasRole("USER")
			.antMatchers("/both/**").hasAnyRole("USER", "ADMIN")
			.anyRequest().authenticated()
			.and()
				.oauth2Login().userInfoEndpoint();
		// .oidcUserService(oidcUserService);
	}

	
/*
 * Setup pre-authenticated header authorization
 * change with caution
 */
	@Bean(name = "siteminderFilter")
	public RequestHeaderAuthenticationFilter siteminderFilter() throws Exception {
		RequestHeaderAuthenticationFilter requestHeaderAuthenticationFilter = new RequestHeaderAuthenticationFilter();
		requestHeaderAuthenticationFilter.setPrincipalRequestHeader("SM_USER");
		requestHeaderAuthenticationFilter.setExceptionIfHeaderMissing(false);
		requestHeaderAuthenticationFilter.setAuthenticationManager(authenticationManager());
		return requestHeaderAuthenticationFilter;
	}

	@Bean
	@Override
	protected AuthenticationManager authenticationManager() throws Exception {
		final List<AuthenticationProvider> providers = new ArrayList<>(1);
		providers.add(preauthAuthProvider());
		return new ProviderManager(providers);
	}

	@Bean(name = "preAuthProvider")
	PreAuthenticatedAuthenticationProvider preauthAuthProvider() throws Exception {
		PreAuthenticatedAuthenticationProvider provider = new PreAuthenticatedAuthenticationProvider();
		provider.setPreAuthenticatedUserDetailsService(userDetailsServiceWrapper());
		return provider;
	}

	// for user/password, need to creat a wrapper, autowired will break the authentication chain!
	@Autowired
	private CustomUserDetailsService customUserDetailsService;

	@Bean
	UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> userDetailsServiceWrapper() throws Exception {
		UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken> wrapper = new UserDetailsByNameServiceWrapper<>();
		wrapper.setUserDetailsService(customUserDetailsService);
		return wrapper;
	}

/*
 * for testing purpose user/password authentication
 */

	/*
	  @Override 
	  protected void configure(HttpSecurity http) throws Exception { 
	  	http
	  		.addFilterAfter(siteminderFilter(), RequestHeaderAuthenticationFilter.class)
	  		.authorizeRequests()
	  		.antMatchers("/", "/Token").permitAll()
	  		.antMatchers("/admin/**").hasAuthority("ADMIN")
	  		.antMatchers("/user/**").hasAuthority("USER")
	  		.antMatchers("/both/**").hasAuthority("USER") 
	  		.anyRequest().authenticated()
	  	.and()
	  		.formLogin().permitAll() 
	  		//.loginPage("/login") 
	  	.and() 
	  		.logout().permitAll();
	   }

	 	@Bean
	  	@Override 
	  	public UserDetailsService userDetailsService() { 
	  		UserDetails user = User.withDefaultPasswordEncoder() 
	  			.username("user") .password("password")
				.authorities("USER") .build();
			return new InMemoryUserDetailsManager(user); 
		}
	 */
}