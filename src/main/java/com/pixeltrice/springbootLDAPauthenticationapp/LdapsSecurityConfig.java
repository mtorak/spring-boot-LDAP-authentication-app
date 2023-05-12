package com.pixeltrice.springbootLDAPauthenticationapp;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.authentication.BindAuthenticator;
import org.springframework.security.ldap.authentication.LdapAuthenticationProvider;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapUserDetailsService;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;

// @Configuration
@Deprecated
@Slf4j
public class LdapsSecurityConfig extends WebSecurityConfigurerAdapter {

  @Value("${ldap.key_store_path}")
  private String keyStorePath;

  @Value("${ldap.key_store_password}")
  private String keyStorePassword;

  @Value("${ldap.key_store_alias}")
  private String keyStoreAlias;

  @Value("${ldap.trusted_store_path}")
  private String trustedStorePath;

  private static String accessDenied = "/accessDenied.html";

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http.csrf().disable();
    http.anonymous().disable();
    http.logout().disable();
    http.x509().subjectPrincipalRegex("cN=(.*?),");//.userDetailsService(new       NoopUserDetailsService( filterBasedLdapUsersearch() ));
    http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
    http.exceptionHandling().accessDeniedHandler(new HandleAccessDenied());
    http.authorizeRequests().antMatchers("/timeout.html", "/resources/**",
            LdapsSecurityConfig.accessDenied).permitAll()
        .antMatchers("/**").hasAnyRole("SOME_ROLE")
        .anyRequest().authenticated()
        .and().requiresChannel()
        .anyRequest().requiresSecure();
  }

  @Autowired
  public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
    auth.authenticationProvider(ldapAuthenticationProvider());
    auth.userDetailsService(new NoopUserDetailsService(filterBasedLdapUserSearch()));
  }

  @Bean
  public LdapAuthenticationProvider ldapAuthenticationProvider() throws Exception {
    return new LdapAuthenticationProvider(bindAuthenticator(), authoritiesPopulator());
  }

  @Bean
  public BindAuthenticator bindAuthenticator() throws Exception {
    BindAuthenticator bindAuthenticator = new BindAuthenticator(contextSource());
    String[] pattern = {"cn={0},ou=people"};
    bindAuthenticator.setUserDnPatterns(pattern);
    return bindAuthenticator;
  }

  @Bean
  public DefaultLdapAuthoritiesPopulator authoritiesPopulator() throws Exception {
    DefaultLdapAuthoritiesPopulator authoritiesPopulator = new DefaultLdapAuthoritiesPopulator(contextSource(), "ou=groups");
    authoritiesPopulator.setGroupRoleAttribute("ou");
    authoritiesPopulator.setSearchSubtree(true);
    return authoritiesPopulator;
  }

  @Bean
  public FilterBasedLdapUserSearch filterBasedLdapUserSearch() throws Exception {
    FilterBasedLdapUserSearch search = new FilterBasedLdapUserSearch("ou=People", "(cn=101)", contextSource());
    search.setSearchSubtree(true);
    return search;
  }

  @Bean
  public DefaultSpringSecurityContextSource contextSource() throws Exception {
    String ldapUrl = "ldaps://remote-server:636";
    //    String keystorePath = ConfigurationManager.getProperty(Constants.KEY_STORE_PATH);
    //    String keyStorePassword = ConfigurationManager.getProperty(Constants.KEY_STORE_PASSWORD);
    //    String keyStoreAlias = ConfigurationManager.getProperty(Constants.KEY_STORE_ALIAS);
    //    String trustStorePath = ConfigurationManager.getProperty(Constants.TRUSTED_STORE_PATH);
    System.setProperty("javax.net.ssl.trustStore", trustedStorePath);
    System.setProperty("javax.net.ssl.trustStorePassword", "");
    System.setProperty("javax.net.ssl.keyStore", keyStorePath);
    System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

    /* SSLContext _sslContext = SSLutils.getSSLContext("TLSv1", keystorePath, "JKS", keystorePassword, keyStoreAlias, trustStorePath, "JKS");*/

    DefaultSpringSecurityContextSource source = new DefaultSpringSecurityContextSource(ldapUrl);
    //    ExternalTlsDirContextAuthenticationStrategy strategy = new ExternalTlsDirContextAuthenticationStrategy();
    //    strategy.setSslSocketFactory(createSSLContext(keyStorePath, keyStorePassword, trustedStorePath).getSocketFactory());
    //    strategy.setShutdownTlsGracefully(true);

    DefaultTlsDirContextAuthenticationStrategy strategy = new DefaultTlsDirContextAuthenticationStrategy();
    strategy.setSslSocketFactory(createSSLContext(keyStorePath, keyStorePassword, trustedStorePath).getSocketFactory());

    source.setPooled(false);
    //  source.setAuthenticationStrategy(strategy);
    source.afterPropertiesSet();
    source.setAnonymousReadOnly(false);
    return source;
  }

  public static final class HandleAccessDenied extends AccessDeniedHandlerImpl {
    public HandleAccessDenied() {
      super.setErrorPage(LdapsSecurityConfig.accessDenied);
    }
  }

  public class NoopUserDetailsService extends LdapUserDetailsService {

    private FilterBasedLdapUserSearch ldapDao;

    public NoopUserDetailsService(FilterBasedLdapUserSearch ldapDao) {
      super(ldapDao);
      this.ldapDao = ldapDao;
    }

    @Override
    public UserDetails loadUserByUsername(String certSubjectName) throws UsernameNotFoundException {
      try {
        this.ldapDao.searchForUser(certSubjectName);
                /*
                    log.info("user " + principal.getDisplayName() + " has the following roles");
                    iterator it = principal.getAuthorities().iterator();
                    while(it.hasNext()){
                        SimpleGrantedAuthority authority = (SimpleGrantedAuthority)it.next();
                        log.info("Role : " + authority.getAuthority());
                        //log.info(principal.toString()); return null;

                    // } */
      } catch (Exception e) {
        throw new UsernameNotFoundException("Cannot find " + certSubjectName, e);
      }
      return null;
    }
  }

  private SSLContext createSSLContext(String keystoreUrl, String keystorePassword, String truststoreUrl)
      throws KeyStoreException, KeyManagementException, CertificateException, CertificateException, IOException {

    SSLContext sslcontext = null;
    try {
      KeyManager[] keymanagers = null;
      TrustManager[] trustmanagers = null;
      if (keystoreUrl != null) {
        KeyStore keystore = createKeyStore(keystoreUrl, keystorePassword);
        //if (log.isDebugEnabled()) {
        Enumeration aliases = keystore.aliases();
        while (aliases.hasMoreElements()) {
          String alias = (String) aliases.nextElement();
          Certificate[] certs = keystore.getCertificateChain(alias);
          if (certs != null) {
            log.debug("Certificate chain '" + alias + "':");
          }
        }
        keymanagers = createKeyManagers(keystore, keystorePassword);
      }

      if (truststoreUrl != null) {
        KeyStore keystore = createKeyStore(truststoreUrl, null);
        if (log.isDebugEnabled()) {
          Enumeration aliases = keystore.aliases();
          while (aliases.hasMoreElements()) {
            String alias = (String) aliases.nextElement();
            log.debug("Trusted certificate '" + alias + "':");
          }
          trustmanagers = createTrustManagers(keystore);
        }

      }

      sslcontext = SSLContext.getInstance("SSL");
      //SSLContext.getinstance("TLS");
      sslcontext.init(keymanagers, trustmanagers, new SecureRandom());
      SSLContext.setDefault(sslcontext);
    } catch (NoSuchAlgorithmException e) {
      log.error(e.getMessage(), e);
      //throw new AuthSSLInitializationError("unsupported algorithm exception: " + e.getMessage());
    } catch (KeyStoreException e) {
      log.error(e.getMessage(), e);
      //throw new AuthSSLInitializationError("Keystore exception: " + e.getMessage());
    } catch (GeneralSecurityException e) {
      log.error(e.getMessage(), e);
      //throw new AuthSSLlnitializationError("Key management exception: e.getMessage());
    }
    return sslcontext;
  }

  private static KeyStore createKeyStore(final String url, final String password)
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException, java.security.cert.CertificateException, IOException {
    if (url == null) {
      throw new IllegalArgumentException("Keystore url may not be null");
    }
    InputStream is = LdapsSecurityConfig.class.getClassLoader().getResourceAsStream(url);
    log.debug("Initializing key store");
    KeyStore keystore = KeyStore.getInstance("jks");
    try { //is = url.openStream();
      keystore.load(is, password != null ? password.toCharArray() : null);
    } finally {
      if (is != null) {
        is.close();
      }
    }
    return keystore;
  }

  private static KeyManager[] createKeyManagers(final KeyStore keystore, final String password)
      throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException {
    if (keystore == null) {
      throw new IllegalArgumentException("Keystore may not be null");
    }
    log.debug("Initializing key manager");
    KeyManagerFactory kmfactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
    kmfactory.init(keystore, password != null ? password.toCharArray() : null);
    return kmfactory.getKeyManagers();
  }

  private static TrustManager[] createTrustManagers(final KeyStore keystore) throws KeyStoreException, NoSuchAlgorithmException {
    log.debug("Initializing trust manager");
    TrustManagerFactory tmfactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
    tmfactory.init(keystore);
    TrustManager[] trustmanagers = tmfactory.getTrustManagers();
    return trustmanagers;
  }

}

