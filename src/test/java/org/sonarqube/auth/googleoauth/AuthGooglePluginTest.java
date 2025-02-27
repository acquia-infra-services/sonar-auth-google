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

import org.junit.Test;
import org.sonar.api.Plugin;
import static org.mockito.Mockito.*;
import static org.assertj.core.api.Assertions.assertThat;
import java.util.List;
import java.util.ArrayList;

public class AuthGooglePluginTest {

    @Test
    public void test_extensions() {
        AuthGooglePlugin underTest = new AuthGooglePlugin();
        Plugin.Context context = mock(Plugin.Context.class);

        // Create a list to capture the extensions
        List<Object> capturedExtensions = new ArrayList<>();

        // Configure mock to capture extensions
        doAnswer(invocation -> {
            capturedExtensions.addAll((List<?>) invocation.getArgument(0));
            return null;
        }).when(context).addExtensions(anyList());

        // Call the plugin's define method
        underTest.define(context);

        // Verify extensions were added
        verify(context, times(2)).addExtensions(anyList());

        // Verify core extensions
        assertThat(capturedExtensions)
            .contains(GoogleSettings.class)
            .contains(UserIdentityFactory.class)
            .contains(GoogleIdentityProvider.class)
            .contains(GoogleScribeApi.class);
    }
}