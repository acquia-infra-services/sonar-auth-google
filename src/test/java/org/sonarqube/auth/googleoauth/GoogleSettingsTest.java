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

 import org.junit.Before;
 import org.junit.Test;
 import org.sonar.api.config.Settings;
 import org.sonar.api.config.PropertyDefinitions;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
 import static org.assertj.core.api.Assertions.assertThat;
 import static org.sonarqube.auth.googleoauth.GoogleSettings.LOGIN_STRATEGY_DEFAULT_VALUE;
 import static org.sonarqube.auth.googleoauth.GoogleSettings.LOGIN_STRATEGY_PROVIDER_LOGIN;
 
 public class GoogleSettingsTest {
 
  private Settings settings;
  private GoogleSettings underTest;
 
  @Before
  public void setUp() {
      settings = mock(Settings.class);
      underTest = new GoogleSettings(settings);
  }
 
  @Test
  public void is_enabled() {
      when(settings.getString("sonar.auth.googleoauth.clientId.secured")).thenReturn("id");
      when(settings.getString("sonar.auth.googleoauth.clientSecret.secured")).thenReturn("secret");
      when(settings.getString("sonar.auth.googleoauth.loginStrategy")).thenReturn(LOGIN_STRATEGY_DEFAULT_VALUE);
      
      when(settings.getBoolean("sonar.auth.googleoauth.enabled")).thenReturn(true);
      assertThat(underTest.isEnabled()).isTrue();

      when(settings.getBoolean("sonar.auth.googleoauth.enabled")).thenReturn(false);
      assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_client_id_is_null() {
    when(settings.getBoolean("sonar.auth.googleoauth.enabled")).thenReturn(true);
    when(settings.getString("sonar.auth.googleoauth.clientId.secured")).thenReturn(null);
    when(settings.getString("sonar.auth.googleoauth.clientSecret.secured")).thenReturn("secret");
    when(settings.getString("sonar.auth.googleoauth.loginStrategy")).thenReturn(LOGIN_STRATEGY_DEFAULT_VALUE);

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void is_enabled_always_return_false_when_client_secret_is_null() {
    when(settings.getBoolean("sonar.auth.googleoauth.enabled")).thenReturn(true);
    when(settings.getString("sonar.auth.googleoauth.clientId.secured")).thenReturn("id");
    when(settings.getString("sonar.auth.googleoauth.clientSecret.secured")).thenReturn(null);
    when(settings.getString("sonar.auth.googleoauth.loginStrategy")).thenReturn(LOGIN_STRATEGY_DEFAULT_VALUE);

    assertThat(underTest.isEnabled()).isFalse();
  }

  @Test
  public void default_login_strategy_is_unique_login() {
    assertThat(underTest.loginStrategy()).isEqualTo(GoogleSettings.LOGIN_STRATEGY_UNIQUE);
  }

  @Test
  public void return_client_id() {
    when(settings.getString("sonar.auth.googleoauth.clientId.secured")).thenReturn("id");   
    assertThat(underTest.clientId()).isEqualTo("id");
  }

  @Test
  public void return_client_secret() {
    when(settings.getString("sonar.auth.googleoauth.clientSecret.secured")).thenReturn("secret");   
    assertThat(underTest.clientSecret()).isEqualTo("secret");
  }

  @Test
  public void return_login_strategy() {
    when(settings.getString("sonar.auth.googleoauth.loginStrategy")).thenReturn(LOGIN_STRATEGY_PROVIDER_LOGIN); 
    assertThat(underTest.loginStrategy()).isEqualTo(LOGIN_STRATEGY_PROVIDER_LOGIN);
  }

  @Test
  public void allow_users_to_sign_up() {
    when(settings.getBoolean("sonar.auth.googleoauth.allowUsersToSignUp")).thenReturn(true);
    assertThat(underTest.allowUsersToSignUp()).isTrue();

    when(settings.getBoolean("sonar.auth.googleoauth.allowUsersToSignUp")).thenReturn(false);
    assertThat(underTest.allowUsersToSignUp()).isFalse();
  }

  @Test
  public void default_apiUrl() {
    assertThat(underTest.apiURL()).isEqualTo("https://www.googleapis.com/");
  }

  @Test
  public void default_webUrl() {
    assertThat(underTest.webURL()).isEqualTo("https://accounts.google.com/o/oauth2/v2/auth");
  }

  @Test
  public void definitions() {
    assertThat(GoogleSettings.definitions()).hasSize(7);
  }

}
