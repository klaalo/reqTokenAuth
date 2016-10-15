package fi.karilaalo.trin.reqTokenAuth;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

@EnableWebSecurity
public class UserInfoSecConfigurer extends WebSecurityConfigurerAdapter {

	@Autowired
	private AuthenticationProvider authProv;
	
	@Autowired
	ReqAuthConfiguration authConf;
	
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
