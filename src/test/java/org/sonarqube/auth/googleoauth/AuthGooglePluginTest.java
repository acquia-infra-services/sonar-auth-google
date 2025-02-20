package org.sonarqube.auth.googleoauth;

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