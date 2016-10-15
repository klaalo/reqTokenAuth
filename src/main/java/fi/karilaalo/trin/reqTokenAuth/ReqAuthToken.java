package fi.karilaalo.trin.reqTokenAuth;

import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

public class ReqAuthToken extends AbstractAuthenticationToken {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -3760297788901457685L;
	String principal;

	public ReqAuthToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
	}

	public ReqAuthToken(List<GrantedAuthority> auths, String princ) {
		this(auths);
		this.principal = princ;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}
	
}
