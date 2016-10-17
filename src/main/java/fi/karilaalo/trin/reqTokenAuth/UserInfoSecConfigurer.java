package fi.karilaalo.trin.reqTokenAuth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

/**
 * 
 * <p>Basic Spring-Security 
 * <code>WebSecurityConfigurerAdapter</code> adds the
 * <code>ReqAuthFilter</code> to the filter chain. Order
 * of the filters in the chain is important.</p>
 * 
 */
@EnableWebSecurity
public class UserInfoSecConfigurer extends WebSecurityConfigurerAdapter {

	@Autowired
	private AuthenticationProvider authProv;
	
	@Autowired
	private ReqAuthConfiguration authConf;
	
	/**
	 * 
	 * <p>The actual overridden 
	 * <a href="http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#jc-httpsecurity">
	 * configure</a> method.</p>
	 * 
	 * <p>Proper authenticationFilter object might have been
	 * more elegant and if implemented as component it would
	 * have been recognised and added to filter chain
	 * automatically at the time of context initialisation.
	 * Now that it is a once per request filter, it
	 * need to be added in the security configurer.</p> 
	 * 
	 */
	@Override
	public void configure(HttpSecurity http) throws Exception {
		http
		.authorizeRequests()
			.antMatchers("/info.html").permitAll()
		.and().antMatcher("/oma/**").addFilterBefore(authConf.getReqAuthFilter(), BasicAuthenticationFilter.class)
			.authenticationProvider(authProv)
			.authorizeRequests().antMatchers("/oma/**").authenticated()
		.and().authorizeRequests()
			.anyRequest().denyAll();
	}
}
