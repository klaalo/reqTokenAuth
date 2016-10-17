package fi.karilaalo.trin.reqTokenAuth;

import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.*;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
//import static org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder.*;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*;

import java.util.stream.Collectors;

import org.apache.commons.lang3.RandomStringUtils;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
public class AppTest {
	
	@Autowired
	UserInfoController ctrl;
	
	@Autowired
    private TestRestTemplate restTemplate;
	
	private MockMvc mvc;
	
	@Autowired
	private WebApplicationContext ctx;
	
	@LocalServerPort
    private int port;
	
	private String hostUrl;
	private String infoUrl;
	private String omaUrl;
	private final String user = "testSuper";
	private final String userHdr = "x-proxy-remote-user";

	
	@Before
	public void init() {
		this.hostUrl =
				"http://localhost:" + port;
		this.infoUrl = hostUrl +
				"/info.html";
		this.omaUrl = hostUrl +
				"/oma/info.html";
		mvc = MockMvcBuilders
				.webAppContextSetup(ctx)
				.apply(springSecurity())
				.build();
	}
	
	@Test
	public void contextLoadsTest() {
		Assert.assertNotNull(ctrl);
	}
	
	@Test
	public void infoHandlerLoadsTest() {
		assertThat(
				this.restTemplate.getForObject(
					infoUrl,
					String.class).contains("tietosi")
				);
	}
	
	@Test
	public void userStrTest() {
		
		String url = infoUrl;
		
		/**
		 * Post userStr form and check that it
		 * returns successfully. Store response
		 * so that we can get back to the session.
		 */
		HttpHeaders hdrs = new HttpHeaders();
		hdrs.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		hdrs.set(userHdr, user);
		MultiValueMap<String, String> map = new LinkedMultiValueMap<>();
		final String userStr = RandomStringUtils.randomAlphanumeric(12);
		map.add(
				UserInfoController.USR_STR_PAR_NAME, 
				userStr);
		HttpEntity<MultiValueMap<String, String>> request =
				new HttpEntity<MultiValueMap<String,String>>(
						map, hdrs);
		ResponseEntity<String> resp =
				this.restTemplate.postForEntity(
						url, request, String.class);
		assertThat(resp.getBody())
			.contains("tietosi");

		/**
		 * Build new request object based on the
		 * session obtained at previous step and
		 * check that the same userStr string
		 * is displayed.
		 */
		hdrs = new HttpHeaders();
		hdrs.set("Cookie", 
				resp.getHeaders().get("Set-Cookie").stream()
				.collect(Collectors.joining(";")));
		request = new HttpEntity<>(hdrs); 
		assertThat(
				this.restTemplate.exchange(
						url,
						HttpMethod.GET,
						request,
						String.class)
				.getBody())
			.contains(userStr);
	}
	
	@Test
	public void userStrOma() throws Exception {
		final String userStr =
				RandomStringUtils.randomAlphabetic(8);
		mvc.perform(
			post(omaUrl)
				.header(userHdr, user)
				.header("oidc_claim_name", "Testi Super")
				.header("oidc_claim_access_token", 
						RandomStringUtils.randomAlphabetic(12))
				.param(UserInfoController.USR_STR_PAR_NAME,
						userStr)
				.with(csrf())
			)
		.andExpect(status().isOk());
	}
	
	@Test
	public void xForwardedTest() {
		HttpHeaders hdrs = new HttpHeaders();
		final String addr = "127.0.0.2";
		hdrs.set("X-Forwarded-For", addr);
		testWithHeaders(hdrs, infoUrl, addr);
	}
	
	@Test
	public void authenticatedUserTest() {
		HttpHeaders hdrs = new HttpHeaders();
		hdrs.set(userHdr, user);
		testWithHeaders(hdrs, omaUrl, user);
		
	}
	
	private void testWithHeaders(HttpHeaders hdrs,
			String url,
			String testStr) {
		HttpEntity<String> request = new HttpEntity<String>(hdrs);
		assertThat(
				this.restTemplate.exchange(
						url,
						HttpMethod.GET,
						request,
						String.class)
				.getBody())
			.contains(testStr);
	}
	
}
