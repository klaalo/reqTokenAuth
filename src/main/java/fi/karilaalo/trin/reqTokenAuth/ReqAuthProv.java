package fi.karilaalo.trin.reqTokenAuth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

/**
 * 
 * Simple authenticationprovider to convey authentication
 * object. Since the userr details are provided by the
 * proxy on front of the application no user profile
 * is needed to be handled or fetched by the authentication
 * provider.
 *
 */
@Component
public class ReqAuthProv implements AuthenticationProvider {
	
	/**
	 * The overridden <code>authenticate</code> method simply checks
	 * whether authentication element carries authentication information
	 * and if it does, marks the user authenticated by returning
	 * the same authentication object.
	 * 
	 * @return
	 * The authentication object if it carries user inormation.
	 * Null if no user information were found.
	 * 
	 */
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (supports(authentication.getClass()) &&
				! ((String) authentication.getPrincipal()).isEmpty()) {
			return authentication;
		}
		return null;
	}

	/**
	 * Usual method to check whether the provider supports
	 * given authentication object.
	 * 
	 * @return
	 * True if <code>ReqAuthProv</code> is assignable from
	 * given authentication object.
	 */
	@Override
	public boolean supports(Class<?> authentication) {
		return ReqAuthToken.class.isAssignableFrom(authentication);
	}

}
