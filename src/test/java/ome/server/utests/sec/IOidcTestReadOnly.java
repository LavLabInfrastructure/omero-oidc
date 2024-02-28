package ome.server.utests.sec;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import org.junit.AfterClass;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientCredentialsOAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.endpoint.OAuth2PasswordGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.util.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import com.beust.jcommander.converters.InetAddressConverter;

import no.nav.security.mock.oauth2.MockOAuth2Server;
import no.nav.security.mock.oauth2.OAuth2Config;
import no.nav.security.mock.oauth2.StandaloneMockOAuth2ServerKt;
import no.nav.security.mock.oauth2.http.MockWebServerWrapper;
import no.nav.security.mock.oauth2.http.OAuth2HttpServer;
import no.nav.security.mock.oauth2.http.Ssl;
import no.nav.security.mock.oauth2.http.SslKeystore;
import no.nav.security.mock.oauth2.token.DefaultOAuth2TokenCallback;
import no.nav.security.mock.oauth2.token.KeyProvider;
import no.nav.security.mock.oauth2.token.OAuth2TokenProvider;
import ome.api.IOidc;
import ome.logic.OidcImpl;
import ome.security.auth.OidcConfig;

@Test
public class IOidcTestReadOnly { 
    String issuer;
    String issuerId = "master";
    String clientId = "default";
    String clientSecret = "BDEt0z2ZjGuxyofywSixdxhCdyINYwO4";
    String user = "admin";
    String sub = "sub"; 
    String pass = "admin";
    String scope = "scope";


    Path json;

    Set<ClientRegistration> registrations = new HashSet<ClientRegistration>();

    MockOAuth2Server testServer;
    
    IOidc iOidc;
  
    private static class DefaultTrustManager implements X509TrustManager {

        @Override
        public void checkClientTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}

        @Override
        public void checkServerTrusted(X509Certificate[] arg0, String arg1) throws CertificateException {}

        @Override
        public X509Certificate [] getAcceptedIssuers() {
            return null;
        }
    }

    @BeforeClass
    public void init() {
        issuer="http://localhost:8080/realms/master";
        // System.out.println(new ClientCredentialsOAuth2AuthorizedClientProvider().authorize(OAuth2AuthorizationContext.withClientRegistration(
        //     ClientRegistrations
        //     .fromOidcIssuerLocation(issuer)
        //     .clientId(clientId)
        //     .clientSecret(clientSecret)
        //     .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
        //     .build())
        //     .principal(new TestingAuthenticationToken("sub","f"))
        //     .build()));

            
        //System.out.println(new DefaultSignatureNameFinder().getAlgorithmName(org.bouncycastle.internal.asn1.cms.CMSObjectIdentifiers.id_RSASSA_PSS_SHAKE128));
        // get test server config from classpath
        String jsonUri = null;
        try{
            jsonUri = this.getClass().getResource(
                "/services/oidc/auth-test-server.json"
                ).toURI().getPath();
        } catch (URISyntaxException e){
            Assert.isNull(e, "Failed finding JSON file path while launching oidc readonly test");
        }

        // read json
        json = FileSystems.getDefault().getPath(jsonUri);
        String jsonData=null;
        try{
            jsonData=Files.readString(json);
        } catch (IOException e){
            System.out.println(e);
            Assert.isNull(e, "Failed to read JSON file while launching oidc readonly test");
        }

        // disable ssl verification
        

        // // create and start server
        // Ssl ssl = new Ssl( new SslKeystore(
        //     "", new File("src/test/resources/localhost.p12"),
        //     SslKeystore.KeyStoreType.PKCS12, ""));

        // String loginPagePath = "";
        // testServer = new MockOAuth2Server(new OAuth2Config(true,loginPagePath,new OAuth2TokenProvider(new KeyProvider()),null,(OAuth2HttpServer) new MockWebServerWrapper(ssl) ));
        OAuth2Config config = OAuth2Config.Companion.fromJson(jsonData);
        testServer = new MockOAuth2Server(config);

        try{
            testServer.start();
            // System.setProperty("proxyHost", "localhost");
            // System.setProperty("proxyPort", "8080");
        } catch (Exception e){}

        issuer = testServer.issuerUrl(issuerId).toString();
        // try{
            // OAuth2AuthorizationContext oac = OAuth2AuthorizationContext.withClientRegistration(ClientRegistrations
            //     .fromOidcIssuerLocation(issuer)
            //     .clientId(clientId)
            //     .clientSecret(clientSecret)
            //     .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            //     .build())
            //     .principal(new UsernamePasswordAuthenticationToken(user, pass))
            //     .attribute(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, user)
            //     .attribute(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, pass)
            //     .build();
            // OAuth2AuthorizedClient authorizedClient = OAuth2AuthorizedClientProviderBuilder.builder().clientCredentials().password().build().authorize(oac);
            // System.out.println(authorizedClient);
        registrations.add(ClientRegistrations
            .fromOidcIssuerLocation(issuer)
            .clientId(clientId)
            .clientSecret(clientSecret)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .scope(scope)
            .build());
        
        iOidc =  new OidcImpl(null, new OidcConfig(
            true, true, registrations), null);
        // } catch (IllegalArgumentException e){
            // try{
            // TimeUnit.MINUTES.sleep(100);
            // }catch(Exception ee){}
        // }
    }

    @AfterClass
    public void deinit(){
        try{
        testServer.shutdown();
        } catch(Exception e) {}
    }

    /*
     *  Get an Access token the old fashioned way
     *  curl -X POST -d user=msmith -d password=msmith -H 'Accept: application/json' 'https://oidctest.wsweet.org/oauth2/'
     *  ( Converted using https://curlconverter.com/java/ )
     */
    public  String getSafeToken(String user, String pass) {
        try{
		    URL url = new URL("http://localhost:8080/read-only/oauth2/token");
		    HttpURLConnection httpConn = (HttpURLConnection) url.openConnection();
		    httpConn.setRequestMethod("POST");

		    httpConn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");

		    httpConn.setDoOutput(true);
		    OutputStreamWriter writer = new OutputStreamWriter(httpConn.getOutputStream());
		    writer.write("grant_type=client_credentials&client_id=anything&client_secret=anything");
		    writer.flush();
		    writer.close();
		    httpConn.getOutputStream().close();

		    InputStream responseStream = httpConn.getResponseCode() / 100 == 2
		    		? httpConn.getInputStream()
		    		: httpConn.getErrorStream();
		    Scanner s = new Scanner(responseStream).useDelimiter("\\A");
		    String response = s.hasNext() ? s.next() : "";
		    return response;
        } catch (IOException e){
            return null;
        }
	}

    @Test
    public String getTestingToken(){
        Map<String, Object> map = new HashMap<>(); 
        map.put("scp", scope);
        return testServer.issueToken(issuerId, sub, clientId, map).serialize();
    }

    @Test
    public void testLookupIssuer(){
        if (iOidc.getSetting()){
            Assert.notNull(iOidc.lookupIssuer(issuer),
                "Lookup failed!");
        }
    }

    // public void testCreateUser(){
    //     if(iOidc.getSetting()){
    //         Map<String, Object> attributes = new HashMap<String, Object>();
    //         attributes.put(OidcConfig.DefaultOmeOidcMap.OME_NAME,  "msmith");
    //         Experimenter user = iOidc.createUser(new DefaultOAuth2AuthenticatedPrincipal(
    //             attributes, null));
    //         Assert.notNull(user, "User failed to be created");
    //     }
    // }
    
    @Test
    public void testValidateToken(){
        if(iOidc.getSetting()){
            // String token = getSafeToken(user,pass);
            String token = getTestingToken();
            System.out.print("Validating token: "+token);
            Assert.notNull(iOidc.validateToken(issuer, token),
                "Validate Token Failed!");
        }
    }

    @Test
    public void testAttemptPasswordGrant(){
        if(iOidc.getSetting()){
            Object rv = iOidc.attemptPasswordGrant(user, pass);
            System.out.println(rv);
            if (rv == null) 
                new Exception("Test failed");
        }
    }


}