package fi.karilaalo.trin.reqTokenAuth;

import static org.assertj.core.api.Assertions.assertThat;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
@SpringBootTest
public class ReqAuthConfigurationTest {

	@Autowired
	private ReqAuthConfiguration conf;
	
	@Test
	public void getReqAuthFilterTest() {
		Assert.assertNotNull(conf.getReqAuthFilter());
	}
	
	@Test
	public void getAuthHdeTest() {
		assertThat(conf.getAuthHdr()).isNotEmpty();
	}
	
	@Test
	public void getDetHdrPrefixTest() {
		assertThat(conf.getDetHdrPrefix()).isNotEmpty();
	}
	
	@Test
	public void getDetInclListTest() {
		assertThat(conf.getDetInclList())
		.hasAtLeastOneElementOfType(String.class);
	}
	
	@Test
	public void isSuperAdminTest() {
		/* Test that method returns false for
		 * random String.
		 */
		assertThat(
			conf.isSuperAdmin(
					RandomStringUtils.randomAlphanumeric(12))
				).isFalse();
		
		/*
		 * We eill rely on that the default
		 * application.properties has
		 * testSuper user on superList.
		 */
		assertThat(
			conf.isSuperAdmin("testSuper"))
			.isTrue();
	}
	
	@Test
	public void getSuperRoleTest() {
		assertThat(conf.getSuperRole())
			.isInstanceOf(SimpleGrantedAuthority.class);
	}

	@Test
	public void getUserRoleTest() {
		assertThat(conf.getUserRole())
			.isInstanceOf(SimpleGrantedAuthority.class);
	}
	
	@Test
	public void matchesToHideListTest() {
		/* Test that method returns false for
		 * random String.
		 */
		assertThat(
				conf.matchesToHideList(
						RandomStringUtils.randomAlphanumeric(6))
				).isFalse();
		
		/* We will rely on that the default 
		 * application.properties has "token"
		 * on hideList.
		 */
		assertThat(
				conf.matchesToHideList("token"))
			.isTrue();

	}
}
