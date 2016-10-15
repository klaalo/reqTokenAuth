package fi.karilaalo.trin.reqTokenAuth;

import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.stereotype.Component;

@Component
public class ReqAuthProv implements AuthenticationProvider {
	
	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (supports(authentication.getClass()) &&
				! ((String) authentication.getPrincipal()).isEmpty()) {
			return authentication;
		}
		return null;
	}

	@Override
	public boolean supports(Class<?> authentication) {
		return ReqAuthToken.class.isAssignableFrom(authentication);
	}

}
