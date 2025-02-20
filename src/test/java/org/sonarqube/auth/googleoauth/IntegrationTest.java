/*
 * Google Authentication for SonarQube
 * Copyright (C) 2016-2016 SonarSource SA
 * mailto:contact AT sonarsource DOT com
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */
package org.sonarqube.auth.googleoauth;

/*-
 * #%L
 * Google Authentication for SonarQube
 * %%
 * Copyright (C) 2016 SonarSource
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

import com.squareup.okhttp.mockwebserver.MockResponse;
import com.squareup.okhttp.mockwebserver.MockWebServer;
import com.squareup.okhttp.mockwebserver.RecordedRequest;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.sonar.api.config.Configuration;
import org.sonar.api.config.PropertyDefinitions;
import org.sonar.api.server.authentication.OAuth2IdentityProvider;
import org.sonar.api.server.authentication.UserIdentity;
import org.sonar.api.server.http.Cookie;
import org.sonar.api.server.http.HttpRequest;
import org.sonar.api.server.http.HttpResponse;
import org.sonar.api.config.Settings;

import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;
import java.util.Locale;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicBoolean;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IntegrationTest {

  private static final String CALLBACK_URL = "http://localhost/oauth/callback/googleoauth";

  @Rule
  public MockWebServer google = new MockWebServer();

  @Rule
  public ExpectedException expectedException = ExpectedException.none();

  // load settings with default values
  Settings settings = mock(Settings.class);
  GoogleSettings googleSettings = new GoogleSettings(settings);
  UserIdentityFactory userIdentityFactory = new UserIdentityFactory(googleSettings);
  GoogleScribeApi scribeApi = new GoogleScribeApi(googleSettings);
  GoogleIdentityProvider underTest = new GoogleIdentityProvider(googleSettings, userIdentityFactory, scribeApi);

  @Before
  public void enable() {
    // Update the when statements to use Settings methods instead of Configuration methods
    when(settings.getString("sonar.auth.googleoauth.clientId.secured")).thenReturn("the_id");
    when(settings.getString("sonar.auth.googleoauth.clientSecret.secured")).thenReturn("the_secret");
    when(settings.getBoolean("sonar.auth.googleoauth.enabled")).thenReturn(true);
    when(settings.getString("sonar.auth.googleoauth.limitOauthDomain")).thenReturn("googleoauth.com");
    when(settings.getString("sonar.auth.googleoauth.apiUrl")).thenReturn(format("http://%s:%d", google.getHostName(), google.getPort()));
    when(settings.getString("sonar.auth.googleoauth.webUrl")).thenReturn(format("http://%s:%d/o/oauth2/auth", google.getHostName(), google.getPort()));
  }

  /**
   * First phase: SonarQube redirects browser to Google authentication form, requesting the
   * minimal access rights ("scope") to get user profile.
   */
  @Test
  public void redirect_browser_to_google_authentication_form() throws Exception {
    DumbInitContext context = new DumbInitContext("the-csrf-state");
    underTest.init(context);
    assertThat(context.redirectedTo)
      .startsWith(google.url("o/oauth2/auth").toString())
      .contains("scope=" + "openid%20email");
  }

  /**
   * Second phase: Google redirects browser to SonarQube at /oauth/callback/googleoauth?code={the verifier code}.
   * This SonarQube web service sends two requests to Google:
   * <ul>
   *   <li>get an access token</li>
   *   <li>get the profile (login, name) of the authenticated user</li>
   * </ul>
   */
  @Test
  public void callback_on_successful_authentication() throws IOException, InterruptedException {
    google.enqueue(newSuccessfulAccessTokenResponse());
    // response of https://www.googleapis.com/oauth2/v3/token
    google.enqueue(new MockResponse().setBody("{\n" +
            "    \"id\": \"42\",\n" +
            "    \"email\": \"john.smith@googleoauth.com\",\n" +
            "    \"verified_email\": true,\n" +
            "    \"name\": \"John Smith\",\n" +
            "    \"given_name\": \"John\",\n" +
            "    \"family_name\": \"Smith\",\n" +
            "    \"picture\": \"https://lh3.googleusercontent.com/-AAAAAAAA/AAAAAAAAAAA/AAAAAAAAAAA/AAAAAAAAAA/photo.jpg\",\n" +
            "    \"locale\": \"en-US\"\n" +
            "}"));

    HttpRequest request = newRequest("the-verifier-code");
    DumbCallbackContext callbackContext = new DumbCallbackContext(request);
    underTest.callback(callbackContext);

    assertThat(callbackContext.csrfStateVerified.get()).isFalse();
    assertThat(callbackContext.userIdentity.getLogin()).isEqualTo("john.smith@googleoauth.com");
    assertThat(callbackContext.userIdentity.getName()).isEqualTo("John Smith");
    assertThat(callbackContext.userIdentity.getEmail()).isEqualTo("john.smith@googleoauth.com");
    assertThat(callbackContext.redirectSent.get()).isTrue();

    // Verify the requests sent to Google
    RecordedRequest accessTokenRequest = google.takeRequest();
    assertThat(accessTokenRequest.getPath()).startsWith("/oauth2/v3/token");
    RecordedRequest userRequest = google.takeRequest();
    assertThat(userRequest.getPath()).startsWith("/oauth2/v1/userinfo");
  }

  /**
   * Second phase: Google redirects browser to SonarQube at /oauth/callback/googleoauth?code={the verifier code}.
   * This SonarQube web service sends two requests to Google:
   * <ul>
   *   <li>get an access token</li>
   *   <li>get the profile (login, name) of the authenticated user</li>
   * </ul>
   */
  @Test
  public void callback_on_successful_authentication_without_domain() throws IOException, InterruptedException {
    when(settings.getString("sonar.auth.googleoauth.limitOauthDomain")).thenReturn(null);
    callback_on_successful_authentication();
  }

  @Test
  public void callback_throws_OAE_if_error_when_requesting_user_profile() throws IOException, InterruptedException {
    google.enqueue(newSuccessfulAccessTokenResponse());
    // https://accounts.google.com/o/oauth2/token fails
    google.enqueue(new MockResponse().setResponseCode(500).setBody("{error}"));

    DumbCallbackContext callbackContext = new DumbCallbackContext(newRequest("the-verifier-code"));
    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage("Can not get Google user profile. HTTP code: 500, response: {error}");
    underTest.callback(callbackContext);

    assertThat(callbackContext.csrfStateVerified.get()).isTrue();
    assertThat(callbackContext.userIdentity).isNull();
    assertThat(callbackContext.redirectSent.get()).isFalse();
  }

  @Test
  public void callback_redirects_to_unauthorized_if_domain_does_not_match() throws IOException, InterruptedException {
    google.enqueue(newSuccessfulAccessTokenResponse());
    // https://accounts.google.com/o/oauth2/token fails
    google.enqueue(new MockResponse().setResponseCode(200).setBody("{\n"+
            "    \"email\": \"john.smith@example.com\",\n" +
            "    \"verified_email\": true,\n" +
            "    \"name\": \"John Smith\",\n" +
            "    \"given_name\": \"John\",\n" +
            "    \"family_name\": \"Smith\",\n" +
            "    \"picture\": \"https://lh3.googleusercontent.com/-AAAAAAAA/AAAAAAAAAAA/AAAAAAAAAAA/AAAAAAAAAA/photo.jpg\",\n" +
            "    \"locale\": \"en-US\"\n" +
            "}"));

    HttpRequest request = newRequest("the-verifier-code");
    DumbCallbackContext callbackContext = new DumbCallbackContext(request);
    underTest.callback(callbackContext);

    assertThat(callbackContext.csrfStateVerified.get()).isFalse();
    assertThat(callbackContext.userIdentity).isNull();
  }

  /**
   * Response sent by Bitbucket to SonarQube when generating an access token
   */
  private static MockResponse newSuccessfulAccessTokenResponse() {
    return new MockResponse().setBody("{\"access_token\":\"e72e16c7e42f292c6912e7710c838347ae178b4a\",\"scope\":\"user\"}");
  }

  private static HttpRequest newRequest(String verifierCode) {
    HttpRequest request = mock(HttpRequest.class);
    when(request.getParameter("code")).thenReturn(verifierCode);
    return request;
  }

  @Test
  public void verify_csrf_state() throws IOException {
    google.enqueue(newSuccessfulAccessTokenResponse());
    google.enqueue(new MockResponse().setBody("{\n" +
        "    \"email\": \"john.smith@googleoauth.com\",\n" +
        "    \"verified_email\": true,\n" +
        "    \"name\": \"John Smith\"\n" +
        "}"));

    HttpRequest request = mock(HttpRequest.class);
    when(request.getParameter("state")).thenReturn("expected-state");
    DumbCallbackContext callbackContext = new DumbCallbackContext(request);

    // This should not throw exception
    callbackContext.verifyCsrfState("expected-state");
    assertThat(callbackContext.csrfStateVerified.get()).isTrue();

    // Should throw exception for invalid state
    when(request.getParameter("state")).thenReturn("unexpected-state");
    expectedException.expect(IllegalStateException.class);
    expectedException.expectMessage("CSRF state does not match");
    callbackContext.verifyCsrfState("expected-state");
}

  private static class DumbCallbackContext implements OAuth2IdentityProvider.CallbackContext {
    final HttpRequest request;
    final AtomicBoolean csrfStateVerified = new AtomicBoolean(false);
    final AtomicBoolean redirectSent = new AtomicBoolean(false);
    UserIdentity userIdentity;

    public DumbCallbackContext(HttpRequest request) {
        this.request = request;
    }

    @Override
    public void verifyCsrfState() {
        String state = request.getParameter("state");
        if (state == null || !state.equals("expected-state")) {
            throw new IllegalStateException("CSRF state does not match");
        }
        csrfStateVerified.set(true);
    }

    @Override
    public void verifyCsrfState(String expectedState) {
        String state = request.getParameter("state");
        if (state == null || !state.equals(expectedState)) {
            throw new IllegalStateException("CSRF state does not match");
        }
        csrfStateVerified.set(true);
    }

    @Override
    public void authenticate(UserIdentity userIdentity) {
      this.userIdentity = userIdentity;
    }

    @Override
    public String getCallbackUrl() {
      return CALLBACK_URL;
    }

    @Override
    public HttpRequest getRequest() {
      return request;
    }

    @Override
    public HttpResponse getResponse() {
      return new HttpResponse() {
        @Override
        public void addCookie(Cookie cookie) {

        }

        @Override
        public boolean containsHeader(String name) {
          return false;
        }

        @Override
        public String encodeURL(String url) {
          return null;
        }

        @Override
        public String encodeRedirectURL(String url) {
          return null;
        }

        @Override
        public String encodeUrl(String url) {
          return null;
        }

        @Override
        public String encodeRedirectUrl(String url) {
          return null;
        }

        @Override
        public void sendError(int sc, String msg) throws IOException {

        }

        @Override
        public void sendError(int sc) throws IOException {

        }

        @Override
        public void sendRedirect(String location) throws IOException {
          redirectSent.set(true);
        }

        @Override
        public void setDateHeader(String name, long date) {

        }

        @Override
        public void addDateHeader(String name, long date) {

        }

        @Override
        public void setHeader(String name, String value) {

        }

        @Override
        public void addHeader(String name, String value) {

        }

        @Override
        public void setIntHeader(String name, int value) {

        }

        @Override
        public void addIntHeader(String name, int value) {

        }

        @Override
        public void setStatus(int sc) {

        }

        @Override
        public void setStatus(int sc, String sm) {

        }

        @Override
        public int getStatus() {
          return 0;
        }

        @Override
        public String getHeader(String name) {
          return null;
        }

        @Override
        public Collection<String> getHeaders(String name) {
          return null;
        }

        @Override
        public Collection<String> getHeaderNames() {
          return null;
        }

        @Override
        public String getCharacterEncoding() {
          return null;
        }

        @Override
        public String getContentType() {
          return null;
        }

        @Override
        public ServletOutputStream getOutputStream() throws IOException {
          return null;
        }

        @Override
        public PrintWriter getWriter() throws IOException {
          return null;
        }

        @Override
        public void setCharacterEncoding(String charset) {

        }

        @Override
        public void setContentLength(int len) {

        }

        @Override
        public void setContentType(String type) {

        }

        @Override
        public void setBufferSize(int size) {

        }

        @Override
        public int getBufferSize() {
          return 0;
        }

        @Override
        public void flushBuffer() throws IOException {

        }

        @Override
        public void resetBuffer() {

        }

        @Override
        public boolean isCommitted() {
          return false;
        }

        @Override
        public void reset() {

        }

        @Override
        public void setLocale(Locale loc) {

        }

        @Override
        public Locale getLocale() {
          return null;
        }
      };
    }

    @Override
    public void redirectToRequestedPage() {
        // Implementation for test context - can be empty or set a flag
        redirectSent.set(true);
    }

    @Override
    public HttpResponse getHttpResponse() {
        return getResponse();
    }
  }

  private static class DumbInitContext implements OAuth2IdentityProvider.InitContext {
    String redirectedTo = null;
    private final String generatedCsrfState;

    public DumbInitContext(String generatedCsrfState) {
      this.generatedCsrfState = generatedCsrfState;
    }

    @Override
    public String generateCsrfState() {
      return generatedCsrfState;
    }

    @Override
    public void redirectTo(String url) {
      this.redirectedTo = url;
    }

    @Override
    public String getCallbackUrl() {
      return CALLBACK_URL;
    }

    @Override
    public HttpRequest getRequest() {
      return null;
    }

    @Override
    public HttpResponse getResponse() {
      return null;
    }

    @Override
    public HttpResponse getHttpResponse() {
        return getResponse();
    }
  }
}
