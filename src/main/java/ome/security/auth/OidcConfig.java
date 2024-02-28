package ome.security.auth;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientProperties;
import org.springframework.boot.autoconfigure.security.oauth2.client.OAuth2ClientPropertiesRegistrationAdapter;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.PasswordOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.ReactiveOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
/* 
 * Stores information and static objects for OIDC
 */
public class OidcConfig  {
    // default constants
    public static class DefaultOmeOidcMap{
        public static final String OME_NAME="omeName";
        public static final String OME_SCOPE="omero";
        public static final String OME_ADMIN_ROLE="omero-root";
    }
    // wrapper for relevant reusables
    public class OmeClientRegistration {
        public final ClientRegistration registration;

        public final JwtDecoder decoder;

        public final OAuth2AuthorizedClientProvider clientProvider;

        public final OpaqueTokenIntrospector introspector;

        public OmeClientRegistration(ClientRegistration registration, JwtDecoder decoder,
                OAuth2AuthorizedClientProvider clientProvider, OpaqueTokenIntrospector introspector) {
            this.registration = registration;
            this.decoder = decoder;
            this.clientProvider = clientProvider;
            this.introspector = introspector;
        }
    }

    private final boolean enabled;
    
    private final boolean enablePasswordGrant;

    private final Map<String, OmeClientRegistration> registrationRepo;
    
    public OidcConfig(boolean enabled, boolean enablePasswordGrant, OAuth2ClientProperties props) { 
            // get client registration map and wrap goodies
            this(enabled, enablePasswordGrant, OAuth2ClientPropertiesRegistrationAdapter.getClientRegistrations(props).values());
    }
    
    public OidcConfig(boolean enabled, boolean enablePasswordGrant, Collection<ClientRegistration> registrations){
        this.enabled = enabled;
        this.enablePasswordGrant = enablePasswordGrant; 
        this.registrationRepo = new HashMap<String,OmeClientRegistration>();
        if (enabled){
            registrations.forEach( reg->{
                String issuer = reg.getProviderDetails().getConfigurationMetadata().get("issuer").toString();
                JwtDecoder decoder = JwtDecoders.fromIssuerLocation(issuer);
                OAuth2AuthorizedClientProvider provider = OAuth2AuthorizedClientProviderBuilder.builder().authorizationCode().clientCredentials().build();
                // does not automatically register introspection url, get it manually
                OpaqueTokenIntrospector introspector = new  SpringOpaqueTokenIntrospector(getIntrospectionUri(reg),
                        reg.getClientId(), reg.getClientSecret());
                        
                
                // if (enablePasswordGrant) provider = new PasswordOAuth2AuthorizedClientProvider();

                // System.out.println(provider.authorize(OAuth2AuthorizationContext.withClientRegistration(reg).principal(null).build()));
                
                OmeClientRegistration registration = new OmeClientRegistration(reg, decoder, provider, introspector);
                registrationRepo.put(issuer, registration);
            });
        }
    }

	public boolean isEnabled(){
        return this.enabled;
    }

    public OmeClientRegistration lookupIssuer(String issuer){
        return registrationRepo.get(issuer);
    }

    public Jwt decodeJwt(String issuer, String token){
        // get proper decoder and decode
        return this.registrationRepo.get(issuer)
                    .decoder.decode(token);
    }

    public Set<String> getAllIssuers(){
        return registrationRepo.keySet();
    }

    public boolean isPasswordGrantEnabled(){
        return this.enablePasswordGrant;
    }
    public String getIntrospectionUri(ClientRegistration reg){
        Object introspectionUri = reg.getProviderDetails()
            .getConfigurationMetadata().get("introspection_endpoint");
        if (introspectionUri == null) return null;
        return introspectionUri.toString();
    }
}
