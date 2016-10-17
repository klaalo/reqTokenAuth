package fi.karilaalo.trin.reqTokenAuth;

import java.util.Enumeration;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.owasp.html.PolicyFactory;
import org.owasp.html.Sanitizers;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

/**
 * 
 * The controller class for the application to
 * display user information conveyed by the
 * authenticative proxy on front of the application. 
 *
 */
@Controller
public class UserInfoController {

	private static final String SESS_USER_STR = "userStr";
	private static final String INFO_TMPL = "info";
	public static final String USR_STR_PAR_NAME = "userStr";

	@Autowired
	private ReqAuthConfiguration authConf;

	/**
	 * 
	 * <a href="info.html">User info handler</a>
	 * shows the basic user information
	 * for unauthenticated users.
	 * 
	 */
	@GetMapping("info")
	public void getInfo(Model model, HttpServletRequest req) {
		model.addAttribute("addr", getAddr(req));
	}
	
	/**
	 * 
	 * <p><a href="oma/info.html">User info handler</a>
	 * for authenticated users shows user information
	 * that is provided by the authenticative proxy
	 * in front of the application.</p>
	 * 
	 * <p>Details are fetched from user's authentication
	 * object by the view.</p>
	 * 
	 * <p>Application assumes that the application path
	 * 'oma' is protected by the authenticative proxy
	 * and user details are released on this path.
	 * It is up to the proxy to protect the application
	 * </p>
	 *
	 * @param model
	 * Model object for the view. Only authentication
	 * status (which is assumed to be tru on this
	 * path of the application) and the ip address
	 * of the user are passed in the model.
	 * 
	 * @param req
	 * HttpServletRequest object is used to pass
	 * the user ip address to the Model.
	 * 
	 * @param auth
	 * Authentication object is used to figure out
	 * if the user has the superAdmin role. If
	 * (s)he has, more details are showed on the
	 * view.
	 * 
	 * @return
	 * All handlers return a handle to the same view.
	 * 
	 * @see ReqAuthFilter
	 * 
	 */
	@GetMapping("/oma/info")
	public String getOmaInfo(Model model, HttpServletRequest req,
			Authentication auth) {
		model.addAttribute("isAuth", true);
		model.addAttribute("addr", getAddr(req));
		if (auth.getAuthorities().contains(
				authConf.getSuperRole())
				) {
			model.addAttribute("superAdmin", true);
		}
		return INFO_TMPL;
	}
	
	/**
	 * PostMapping to save userStr to the Session object.
	 * Implemented only for curiosity. This functionality
	 * is not actually needed to demonstrate request token
	 * authentication.
	 *  
	 * @param userStr
	 * User provided string to be saved.
	 * @param session
	 * The user provided string is saved in the
	 * Session object.
	 * 
	 */
	@PostMapping("/info")
	public String postInfo(Model model, HttpServletRequest req,
			@RequestParam(USR_STR_PAR_NAME) String userStr,
			HttpSession session) {
		PolicyFactory policy = Sanitizers.FORMATTING;
		session.setAttribute(SESS_USER_STR, policy.sanitize(userStr));
		model.addAttribute("addr", getAddr(req));
		return INFO_TMPL;
	}
	
	/**
	 *
	 * Another PostMapping to save the userStr
	 * from authenticated user.
	 * 
	 */
	@PostMapping("/oma/info")
	public String postOmaInfo(Model model, HttpServletRequest req,
			@RequestParam(USR_STR_PAR_NAME) String userStr,
			HttpSession session,
			Authentication auth) {
		PolicyFactory policy = Sanitizers.FORMATTING;
		session.setAttribute(SESS_USER_STR, policy.sanitize(userStr));
		model.addAttribute("isAuth", true);
		model.addAttribute("addr", getAddr(req));
		if (auth.getAuthorities().contains(
				authConf.getSuperRole())
				) {
			model.addAttribute("superAdmin", true);
		}
		return INFO_TMPL;
	}
	
    private String getAddr(HttpServletRequest req) {
    	Enumeration<?> e = req.getHeaderNames();
    	while (e.hasMoreElements()) {
    		String key = (String) e.nextElement();
    		if (key.equalsIgnoreCase("X-Forwarded-For")) {
    			return req.getHeader(key);
    		}
    	}
    	return req.getRemoteAddr();
    }	
	
	
}
