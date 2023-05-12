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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.ldap.core.support.DefaultTlsDirContextAuthenticationStrategy;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;

@Slf4j
//@Configuration
public class SecurityConfigSsl extends WebSecurityConfigurerAdapter {

  @Value("${ldap.key_store_path}")
  private String keyStorePath;

  @Value("${ldap.key_store_password}")
  private String keyStorePassword;

  @Value("${ldap.key_store_alias}")
  private String keyStoreAlias;

  @Value("${ldap.trusted_store_path}")
  private String trustedStorePath;

  //  private static final String ldapUrl = "ldap://localhost:8389/dc=springframework,dc=org";
  //  private static final String ldapUrlSecure = "ldaps://remote-server:636";

  @Value("${ldap.urls}")
  private String ldapUrls;

  @Value("${ldap.managerdn}")
  private String managerDn;

  @Value("${ldap.managerpwd}")
  private String managerPwd;

  @Override
  protected void configure(HttpSecurity http) throws Exception {
    http
        .authorizeRequests()
        .anyRequest().fullyAuthenticated()
        .and()
        .formLogin();
  }

  @Override
  public void configure(AuthenticationManagerBuilder auth) throws Exception {
    auth
        .ldapAuthentication()
        .userDnPatterns("uid={0},ou=people")
        .groupSearchBase("ou=groups")
        .contextSource(contextSource())
        //.url(ldapUrl)
        //.and()
        .passwordCompare()
        .passwordEncoder(new BCryptPasswordEncoder())
        .passwordAttribute("userPassword");
  }

  @Bean
  public DefaultSpringSecurityContextSource contextSource() throws Exception {
    // String ldapUrl = "ldaps://remote-server:636";
    //    String keystorePath = ConfigurationManager.getProperty(Constants.KEY_STORE_PATH);
    //    String keyStorePassword = ConfigurationManager.getProperty(Constants.KEY_STORE_PASSWORD);
    //    String keyStoreAlias = ConfigurationManager.getProperty(Constants.KEY_STORE_ALIAS);
    //    String trustStorePath = ConfigurationManager.getProperty(Constants.TRUSTED_STORE_PATH);
    System.setProperty("javax.net.ssl.trustStore", trustedStorePath);
    System.setProperty("javax.net.ssl.trustStorePassword", "");
    System.setProperty("javax.net.ssl.keyStore", keyStorePath);
    System.setProperty("javax.net.ssl.keyStorePassword", keyStorePassword);

    /* SSLContext _sslContext = SSLutils.getSSLContext("TLSv1", keystorePath, "JKS", keystorePassword, keyStoreAlias, trustStorePath, "JKS");*/

    DefaultSpringSecurityContextSource source = new DefaultSpringSecurityContextSource(ldapUrls);
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
      throws KeyStoreException, NoSuchAlgorithmException, CertificateException, CertificateException, IOException {
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
