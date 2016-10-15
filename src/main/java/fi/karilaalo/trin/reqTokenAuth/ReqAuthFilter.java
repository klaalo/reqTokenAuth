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

public class ReqAuthFilter extends OncePerRequestFilter {
	
	private ReqAuthConfiguration conf;
	
	public ReqAuthFilter(ReqAuthConfiguration configuration) {
		this.conf = configuration;
	}
	
	@Log
	Logger log;
	
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
