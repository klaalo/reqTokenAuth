package fi.karilaalo.trin.reqTokenAuth;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Logger;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.github.vbauer.herald.annotation.Log;

/**
 * 
 * <p>Simple filter to fetch the authentication information
 * from the HTTP-headers of each request (this is where 
 * the magic happens). The filter is implemented as 
 * OncePerRequesyFilter by trial-error
 * method. E.g. 
 * <code>AbstractAuthenticationProcessingFilter</code>
 * would probably be more coherent way of achieving the goal
 * but it didn't seem to be achieved easy. This is a simple
 * solution that seemed to be working as hoped.</p>
 * 
 * <h2>Deployment scenario</h2>
 * <p>The scenario is that the users of the application
 * are authenticated on the proxy server on front. The actual
 * deployment could be e.g. Shibboleth SP software, but this
 * particular implementation has been tested with
 * <a href="https://github.com/pingidentity/mod_auth_openidc">
 * mod_auth_openidc</a>.
 * </p>
 * 
 * <ul>
 * <li><a href="https://github.com/pingidentity/mod_auth_openidc">
 * https://github.com/pingidentity/mod_auth_openidc</a></li>
 * <li><a href="https://shibboleth.net/products/service-provider.html">
 * https://shibboleth.net/products/service-provider.html</a></li>
 * </ul>
 */
public class ReqAuthFilter extends OncePerRequestFilter {
	
	private ReqAuthConfiguration conf;
	
	/**
	 * 
	 * @param configuration
	 * Configuration object is provided by bean factory method
	 * on <code>ReqAuthConfiguration</code>.
	 */
	public ReqAuthFilter(ReqAuthConfiguration configuration) {
		this.conf = configuration;
	}
	
	@Log
	private Logger log;
	
	/**
	 * <p>The actual filter functionality to find authentication information
	 * from request headers. Filter trusts that the proxy server in front
	 * of the application secures the application and does the actual
	 * authentication. Filter only cathes the authentication information
	 * that is provided to the filter in HTTP Request Headers.</p>
	 * 
	 * <p>The user principal object that can later be fetched by
	 * <code>Authentication.getPrincipal()</code> method is the user
	 * id String released by the authenticative proxy.</p>
	 * 
	 * <p>The user information details that the proxy releases in request
	 * headers are saved as HashMap to the details object of the
	 * authentication token. They can be later found from
	 * <code>Authentication.getDetails()</code>.</p>
	 * 
	 * <p>Because of the nature of the deployment scenario, the filter
	 * must be run on every single <code>HttpServletRequest</code>.
	 * The user session is handled by the proxy, which makes
	 * the application unaware of the authentication status of
	 * the user.</p>
	 * 
	 * <p><strong>Note</strong> the Spring Reference Documentation observation,
	 * which applies also here:</p>
	 * <p><cite>the framework performs no authentication checks at all and 
	 * it is extremely important that the external system is configured
	 * properly and protects all access to the application</cite></p>
	 * 
	 *  <a href="http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#request-header-authentication-siteminder">
	 *  http://docs.spring.io/spring-security/site/docs/current/reference/htmlsingle/#request-header-authentication-siteminder</a>
	 */
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		String user = request.getHeader(conf.getAuthHdr());
		if (user == null || user.isEmpty()) {
			SecurityContextHolder.getContext().setAuthentication(null);
			filterChain.doFilter(request, response);
			return;
		}
		
		List<GrantedAuthority> auths = new ArrayList<GrantedAuthority>();
		auths.add(conf.getUserRole());
		
		if (conf.isSuperAdmin(user)) {
			log.info("----- is superAdmin: " + user);
			auths.add(conf.getSuperRole());
		}
		
		// Iterate through headers to find authentication detail
		// headers from the request. Add only those details to authentication
		// detail map that are listed in configuration.
		Map<String, String> details = new HashMap<String, String>();
		for (String hdr: Collections.list(request.getHeaderNames())) {
			String cleaned = hdr.replace(conf.getDetHdrPrefix(), "");
			if (hdr.startsWith(conf.getDetHdrPrefix()) &&
					conf.getDetInclList().contains(cleaned)) {
				details.put(cleaned, request.getHeader(hdr));
			}
		}
		ReqAuthToken auth = new ReqAuthToken(auths, user);
		auth.setDetails(details);
		SecurityContextHolder.getContext().setAuthentication(auth);
		filterChain.doFilter(request, response);
	}

}
