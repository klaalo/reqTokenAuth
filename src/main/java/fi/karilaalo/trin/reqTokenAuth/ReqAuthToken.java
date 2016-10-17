package fi.karilaalo.trin.reqTokenAuth;

import java.util.Collection;
import java.util.List;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

/**
 * 
 * Authentication token implementation to
 * hold user information.
 *
 */
public class ReqAuthToken extends AbstractAuthenticationToken {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -3760297788901457685L;
	String principal;

	/**
	 * Mandatory constructor.
	 * 
	 * @param authorities
	 * List of granted authorities is provided
	 * in the authentication filter which sets the
	 * authentication object to the <code>SecurityCOntext</code>.
	 */
	public ReqAuthToken(Collection<? extends GrantedAuthority> authorities) {
		super(authorities);
	}

	/**
	 * 
	 * Additional constructor to convey user principal
	 * for the authentication token to make things more
	 * simple.
	 * 
	 * @param auths
	 * List of granted authorities is provided
	 * in the authentication filter which sets the
	 * authentication object to the <code>SecurityCOntext</code>.

	 * @param princ
	 * The principal object of the user i.e. the user id.
	 */
	public ReqAuthToken(List<GrantedAuthority> auths, String princ) {
		this(auths);
		this.principal = princ;
	}

	/**
	 * Since the authentication information is provided by
	 * the proxy server, we don't need  to save, fetch
	 * or check the credentials for the user. Hence, they
	 * are always null.
	 * 
	 * @return
	 * Always null since credentials are not needed on this scenario
	 * where the proxy handles the authentication for us.
	 */
	@Override
	public Object getCredentials() {
		return null;
	}

	/**
	 * User principal is the user id for the user
	 * returned by the authenticative proxy on front
	 * of the application
	 * 
	 * @return
	 * String holding the user principal i.e. user id.
	 */
	@Override
	public Object getPrincipal() {
		return principal;
	}
	
}
