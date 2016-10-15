package fi.karilaalo.trin.reqTokenAuth;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

@Configuration
public class ReqAuthConfiguration {
	
	public static final String ROLE_SUPER = "ROLE_SUPERADMIN";
	public static final String ROLE_USER = "ROLE_USER";
	public static final String LIST_SEPARATOR = ",";
	
	@Value("${my.reqAuth.authHdr}")
	private String authHdr;

	@Value("${my.reqAuth.detHdrPrefix}")
	private String detHdrPrefix;
	
	private List<String> detInclList;
	
	private List<String> superAdmins;
	
	private List<String> hideList;
	
	Logger log = Logger.getLogger(this.getClass().getName());
	
	public ReqAuthConfiguration(
			@Value("${my.reqAuth.detInclList}") String detInclList,
			@Value("${my.reqAuth.superList}") String superList,
			@Value("${my.reqAuth.hideList}") String hideList
			) {
		this.detInclList = Arrays.asList(detInclList.split(LIST_SEPARATOR));
		this.superAdmins = Arrays.asList(superList.split(LIST_SEPARATOR));
		this.hideList = Arrays.asList(hideList.split(LIST_SEPARATOR));
	}
	
	@Bean
	public ReqAuthFilter getReqAuthFilter () {
		return new ReqAuthFilter(this);
	}
	
	public String getAuthHdr() {
		return authHdr;
	}
	
	public String getDetHdrPrefix() {
		return detHdrPrefix;
	}
	
	public List<String> getDetInclList() {
		return detInclList;
	}
	
	public boolean isSuperAdmin (String id) {
		return superAdmins.contains(id);
	}
	
	public GrantedAuthority getSuperRole() {
		return getRole(ROLE_SUPER);
	}
	
	public GrantedAuthority getUserRole() {
		return getRole(ROLE_USER);
	}
	
	private GrantedAuthority getRole(String roleStr) {
		return new SimpleGrantedAuthority(roleStr);
	}
	
	public boolean matchesToHideList(String str) {
		for (String matcherStr: hideList) {
			if (str.matches(".*" + matcherStr)) {
				return true;
			}
		}
		return false;
	}
	
}
