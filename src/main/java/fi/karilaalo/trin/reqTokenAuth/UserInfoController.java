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

@Controller
public class UserInfoController {

	private static final String SESS_USER_STR = "userStr";
	private static final String INFO_TMPL = "info";

	@Autowired
	ReqAuthConfiguration authConf;

	@GetMapping("info")
	public void getInfo(Model model, HttpServletRequest req) {
		model.addAttribute("addr", getAddr(req));
	}
	
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
	
	@PostMapping("/info")
	public String postInfo(Model model, HttpServletRequest req,
			@RequestParam("userStr") String userStr,
			HttpSession session) {
		PolicyFactory policy = Sanitizers.FORMATTING;
		session.setAttribute(SESS_USER_STR, policy.sanitize(userStr));
		model.addAttribute("addr", getAddr(req));
		return INFO_TMPL;
	}
	
	@PostMapping("/oma/info")
	public String postOmaInfo(Model model, HttpServletRequest req,
			@RequestParam("userStr") String userStr,
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
