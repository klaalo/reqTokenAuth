package fi.karilaalo.trin.reqTokenAuth;

import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Configuration class to make application.properties available for the application.
 */
@Configuration
public class ReqAuthConfiguration {
	
	/**
	 * Final field for superAdmin role. SuperAdmin is able to
	 * see all information provided by the application.
	 */
	public static final String ROLE_SUPER = "ROLE_SUPERADMIN";

	/**
	 * Basic user role.
	 */
	public static final String ROLE_USER = "ROLE_USER";

	/**
	 * List separator is used in application.properties to separate
	 * values to generate lists. 
	 */
	public static final String LIST_SEPARATOR = ",";
	
	@Value("${my.reqAuth.authHdr}")
	private String authHdr;

	@Value("${my.reqAuth.detHdrPrefix}")
	private String detHdrPrefix;
	
	private List<String> detInclList;
	
	private List<String> superAdmins;
	
	private List<String> hideList;
	
	Logger log = Logger.getLogger(this.getClass().getName());
	
	/**
	 * 
	 * @param detInclList 
	 * A list of details that will be used in
	 * user's authentication object. See
	 * <code>my.reqAuth.detInclList</code> in
	 * application.properties.

	 * @param superList
	 * List of user ids that will be granted
	 * the superAdmin role. Will be generated
	 * from <code>my.reqAuth.superList</code>
	 * in application properties by the constructor.
	 * 
	 * @param hideList
	 * List of authentication headers that will
	 * be hidden from the user. However, the current
	 * info.html template shows headers only for
	 * superAdmins.
	 */
	public ReqAuthConfiguration(
			@Value("${my.reqAuth.detInclList}") String detInclList,
			@Value("${my.reqAuth.superList}") String superList,
			@Value("${my.reqAuth.hideList}") String hideList
			) {
		this.detInclList = Arrays.asList(detInclList.split(LIST_SEPARATOR));
		this.superAdmins = Arrays.asList(superList.split(LIST_SEPARATOR));
		this.hideList = Arrays.asList(hideList.split(LIST_SEPARATOR));
	}
	
	/**
	 * Factory method to initialize the authentication
	 * processing filter.
	 * 
	 * @return ReqAuthFilter
	 * that is configured to 
	 * use in <code>UserInfoSecConfigurer</code>.
	 */
	@Bean
	public ReqAuthFilter getReqAuthFilter () {
		return new ReqAuthFilter(this);
	}
	
	/**
	 * @return
	 * Authentication header name from which value the
	 * user identity is created. Will be saved as
	 * authentication principal.
	 */
	public String getAuthHdr() {
		return authHdr;
	}
	
	/**
	 * @return
	 * Header prefix that is used to fetch authentication
	 * details for a user.
	 */
	public String getDetHdrPrefix() {
		return detHdrPrefix;
	}
	
	/**
	 * 
	 * @return
	 * A list of details that will be used in
	 * user's authentication object. See
	 * <code>my.reqAuth.detInclList</code> in
	 * application.properties.
	 */
	public List<String> getDetInclList() {
		return detInclList;
	}
	
	/**
	 * 
	 * @param id
	 * Query by user id if user is in the
	 * list of superAdmins.
	 * 
	 * @return
	 * Whether the queried user has a superAdmin
	 * role.
	 */
	public boolean isSuperAdmin (String id) {
		return superAdmins.contains(id);
	}
	
	/**
	 * 
	 * @return
	 * The role for superAdmin.
	 */
	public GrantedAuthority getSuperRole() {
		return getRole(ROLE_SUPER);
	}
	
	/**
	 * 
	 * @return
	 * The role for basic user.
	 */
	public GrantedAuthority getUserRole() {
		return getRole(ROLE_USER);
	}
	
	private GrantedAuthority getRole(String roleStr) {
		return new SimpleGrantedAuthority(roleStr);
	}
	
	/**
	 * 
	 * @param str
	 * String to test whether header should be hidden
	 * from view.
	 * 
	 * @return
	 * Boolean value indicating whether the header
	 * should be hidden from the view.
	 */
	public boolean matchesToHideList(String str) {
		for (String matcherStr: hideList) {
			if (str.matches(".*" + matcherStr)) {
				return true;
			}
		}
		return false;
	}
	
}
